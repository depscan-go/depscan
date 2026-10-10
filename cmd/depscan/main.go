package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/report"
	"github.com/depscan-go/depscan/internal/scan"
)

var version = "dev"

const (
	exitClean     = 0
	exitViolation = 1
	exitToolError = 2
)

func main() {
	path := flag.String("path", ".", "path to the repository to scan")
	policyFile := flag.String("policy", "policy.yaml", "path to policy.yaml")
	reportFile := flag.String("report", "", "write a CycloneDX SBOM report to this file")
	commit := flag.String("commit", "", "VCS revision being scanned, recorded in the report (e.g. $GITHUB_SHA)")
	flag.Parse()

	fmt.Printf("Scanning: %s\n", *path)
	fmt.Printf("Policy:   %s\n\n", *policyFile)

	p, err := policy.Load(*policyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading policy: %v\n", err)
		os.Exit(exitToolError)
	}

	engine := scan.New(p)
	scannedAt := time.Now()
	result, err := engine.Run(context.Background(), *path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(exitToolError)
	}

	if *reportFile != "" {
		if err := writeReport(*reportFile, report.Input{
			Result:      result,
			Policy:      p,
			Subject:     subjectName(*path),
			Commit:      *commit,
			ScannedAt:   scannedAt,
			ToolVersion: version,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "report error: %v\n", err)
			os.Exit(exitToolError)
		}
		fmt.Printf("Report:       %s\n", *reportFile)
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
		os.Exit(exitClean)
	}

	fmt.Printf("❌ %d policy violation(s) — scan failed:\n\n", len(result.Violations))
	for _, v := range result.Violations {
		fmt.Printf("  [BLOCK] [%s] %s@%s\n", v.Kind, v.Dep.Name, v.Dep.Version)
		fmt.Printf("          %s\n\n", v.Reason)
	}

	fmt.Printf("Result: %d violation(s)\n", len(result.Violations))
	os.Exit(exitViolation)
}

func writeReport(file string, in report.Input) error {
	bom, err := report.Build(in)
	if err != nil {
		return err
	}
	data, err := bom.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0o644)
}

// subjectName is the scanned folder's name, never its absolute path, so the
// report is the same on every machine and leaks nothing about the host.
func subjectName(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.Base(abs)
}
