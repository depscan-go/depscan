package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/depscan-go/depscan/internal/api"
	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
	"github.com/depscan-go/depscan/internal/store"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "address to listen on (local only by default)")
	scanRoot := flag.String("scan-root", "", "only folders inside this directory can be scanned (default: your home folder)")
	policyFile := flag.String("policy", "policy.yaml", "path to policy.yaml")
	flag.Parse()

	p, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy: %v\n", err)
		os.Exit(1)
	}

	if *scanRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot find home folder, pass -scan-root: %v\n", err)
			os.Exit(1)
		}
		*scanRoot = home
	}
	log.Printf("scan root: %s", *scanRoot)

	engine := scan.New(p)
	handler, err := api.New(engine, *scanRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -scan-root: %v\n", err)
		os.Exit(1)
	}
	handler.AllowList = localOnly(*addr)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handler.Dashboard)
	mux.HandleFunc("GET /assets/{name}", handler.Asset)
	mux.HandleFunc("GET /healthz", handler.Healthz)
	mux.HandleFunc("POST /scans", handler.CreateScan)
	mux.HandleFunc("POST /scans/upload", handler.ScanUpload)
	mux.HandleFunc("GET /policy", handler.PolicyView)
	mux.HandleFunc("GET /scans", handler.ListScans)
	mux.HandleFunc("GET /scans/{id}", handler.GetScan)
	mux.HandleFunc("GET /scans/{id}/report", handler.GetReport)

	// GitHub webhooks are on only when a secret is set. The secret comes from
	// the environment, not a flag, so it never shows up in the process list.
	workers, cancelWorkers := context.WithCancel(context.Background())
	var queue *github.Queue
	if secret := os.Getenv("DEPSCAN_WEBHOOK_SECRET"); secret != "" {
		token := os.Getenv("GITHUB_TOKEN")
		fetcher := github.NewFetcher(token)
		publisher := newPublisher(token)
		anchorer, err := newServerAnchorer()
		if err != nil {
			log.Printf("anchoring: off: %v", err)
		} else if anchorer != nil {
			go logBalance(anchorer, log.Printf)
		}
		queue = github.NewQueue(50, fetcher, engine, func(o github.Outcome) {
			label := fmt.Sprintf("github.com/%s#%d@%.7s", o.Job.Repo, o.Job.PR, o.Job.HeadSHA)
			scanID := ""
			if o.Err != nil {
				log.Printf("webhook: %s failed after %s: %v", label, o.Duration.Round(time.Millisecond), o.Err)
			} else {
				rec, _ := handler.Record(context.Background(), store.PR, label, o.Result)
				scanID = rec.ID
				log.Printf("webhook: %s scanned in %s: %d lockfiles, %d deps, %d violations",
					label, o.Duration.Round(time.Millisecond), o.Files, len(o.Result.Deps), len(o.Result.Violations))
				if anchorer != nil {
					// Anchor before reporting, so the comment can carry the transaction.
					// A devnet anchor takes a few seconds, well inside the time the app
					// stays up after the webhook request.
					ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					data, info, err := anchorScan(ctx, anchorer, p, o)
					cancel()
					if data != nil {
						_ = handler.AttachReport(context.Background(), rec, data, info)
						o.Anchor = anchorNote(info)
					}
					if err != nil {
						log.Printf("webhook: %s: anchoring %s: %v", label, info.Digest, err)
					} else {
						log.Printf("webhook: %s: anchored %s in %s", label, info.Digest, info.Anchor.TxID)
					}
				}
			}
			if publisher != nil {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := publisher.Finished(ctx, o, scanID); err != nil {
					log.Printf("webhook: %s: reporting to GitHub: %v", label, err)
				}
			}
		})
		if publisher != nil {
			queue.OnStart(func(ctx context.Context, j github.Job) {
				if err := publisher.Started(ctx, j); err != nil {
					log.Printf("webhook: github.com/%s#%d@%.7s: pending status: %v", j.Repo, j.PR, j.HeadSHA, err)
				}
			})
		}
		queue.Start(workers, 2)

		wh, err := github.NewWebhookHandler(secret, queue.Enqueue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "webhook setup: %v\n", err)
			os.Exit(1)
		}
		mux.Handle("POST /webhooks/github", wh)
		log.Printf("webhooks: POST /webhooks/github (GitHub token: %t, results on pull requests: %s, anchoring: %t)", token != "", feedbackMode(publisher), anchorer != nil)
	} else {
		log.Printf("webhooks: off (set DEPSCAN_WEBHOOK_SECRET to enable)")
	}

	root := api.Logger(api.Recovery(api.MaxBytes(mux)))

	server := &http.Server{
		Addr:         *addr,
		Handler:      root,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("dashboard: http://%s", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	// Stop webhook workers after the server stops accepting new deliveries.
	cancelWorkers()
	if queue != nil {
		queue.Wait()
	}
	log.Println("done")
}

// newPublisher reports webhook scans back to the pull request: a commit
// status always, and a comment unless DEPSCAN_PR_FEEDBACK=status. It needs
// GITHUB_TOKEN; DEPSCAN_PR_FEEDBACK=off turns both off.
func newPublisher(token string) *github.Publisher {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("DEPSCAN_PR_FEEDBACK")))
	if token == "" || mode == "off" {
		return nil
	}
	p := github.NewPublisher(token)
	p.Comments = mode != "status"
	p.DashboardURL = os.Getenv("DEPSCAN_PUBLIC_URL")
	return p
}

func feedbackMode(p *github.Publisher) string {
	switch {
	case p == nil:
		return "off"
	case p.Comments:
		return "status and comment"
	}
	return "status only"
}
