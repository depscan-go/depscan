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
	addr := flag.String("addr", ":8080", "address to listen on")
	// CHANGED (1): the only folder the API is allowed to scan
	scanRoot := flag.String("scan-root", ".", "only folders inside this directory can be scanned via the API")
	policyFile := flag.String("policy", "policy.yaml", "path to policy.yaml")
	flag.Parse()

	p, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy: %v\n", err)
		os.Exit(1)
	}

	engine := scan.New(p)
	// CHANGED (2): api.New now takes the scan root and can fail (e.g. folder doesn't exist)
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
		log.Printf("server listening on %s", *addr)
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
	// CHANGED (3): don't ignore the error (golangci-lint errcheck flags this)
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("done")
}
