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

	// No -scan-root given: allow anything under the user's home folder,
	// so local repos can be scanned without extra flags.
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
	log.Println("done")
}
