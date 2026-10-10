package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/depscan-go/depscan/internal/api"
	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
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

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handler.Dashboard)
	mux.HandleFunc("GET /healthz", handler.Healthz)
	mux.HandleFunc("POST /scans", handler.CreateScan)
	mux.HandleFunc("GET /scans", handler.ListScans)
	mux.HandleFunc("GET /scans/{id}", handler.GetScan)

	// GitHub webhooks are on only when a secret is set. The secret comes from
	// the environment, not a flag, so it never shows up in the process list.
	workers, cancelWorkers := context.WithCancel(context.Background())
	var queue *github.Queue
	if secret := os.Getenv("DEPSCAN_WEBHOOK_SECRET"); secret != "" {
		fetcher := github.NewFetcher(os.Getenv("GITHUB_TOKEN"))
		queue = github.NewQueue(50, fetcher, engine, func(o github.Outcome) {
			label := fmt.Sprintf("github.com/%s#%d@%.7s", o.Job.Repo, o.Job.PR, o.Job.HeadSHA)
			if o.Err != nil {
				log.Printf("webhook: %s failed after %s: %v", label, o.Duration.Round(time.Millisecond), o.Err)
				return
			}
			handler.Record(label, o.Result)
			log.Printf("webhook: %s scanned in %s: %d lockfiles, %d deps, %d violations",
				label, o.Duration.Round(time.Millisecond), o.Files, len(o.Result.Deps), len(o.Result.Violations))
		})
		queue.Start(workers, 2)

		wh, err := github.NewWebhookHandler(secret, queue.Enqueue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "webhook setup: %v\n", err)
			os.Exit(1)
		}
		mux.Handle("POST /webhooks/github", wh)
		log.Printf("webhooks: POST /webhooks/github (GitHub token: %t)", os.Getenv("GITHUB_TOKEN") != "")
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
