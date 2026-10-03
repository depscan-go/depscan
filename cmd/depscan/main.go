package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
)

func main() {
	path := flag.String("path", ".", "path to the repository to scan")
	policyFile := flag.String("policy", "policy.yaml", "path to policy.yaml")
	flag.Parse()

	fmt.Printf("Scanning: %s\n", *path)
	fmt.Printf("Policy:   %s\n\n", *policyFile)

	p, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy: %v\n", err)
		os.Exit(1)
	}

	engine := scan.New(p)
	result, err := engine.Run(context.Background(), *path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Dependencies: %d\n", len(result.Deps))
	fmt.Printf("Findings:     %d\n", len(result.Findings))
	fmt.Printf("Violations:   %d\n", len(result.Violations))
	fmt.Printf("Warnings:     %d\n\n", len(result.Warnings))

	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  %d warning(s) — will not fail the scan:\n\n", len(result.Warnings))
		for _, w := range result.Warnings {
			fmt.Printf("  [WARN] [%s] %s@%s\n", w.Kind, w.Dep.Name, w.Dep.Version)
			fmt.Printf("         %s\n\n", w.Reason)
		}
	}

	if len(result.Violations) == 0 {
		fmt.Println("✅ No policy violations. Scan passed.")
		return
	}

	fmt.Printf("❌ %d policy violation(s) — scan failed:\n\n", len(result.Violations))
	for _, v := range result.Violations {
		fmt.Printf("  [BLOCK] [%s] %s@%s\n", v.Kind, v.Dep.Name, v.Dep.Version)
		fmt.Printf("          %s\n\n", v.Reason)
	}

	fmt.Printf("Result: %d violation(s)\n", len(result.Violations))
	os.Exit(1)
}
