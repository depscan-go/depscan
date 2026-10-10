package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
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
	reportFile := flag.String("report", "", "write a CycloneDX SBOM report to this file (plus <file>.sha256)")
	commit := flag.String("commit", "", "VCS revision being scanned, recorded in the report (e.g. $GITHUB_SHA)")
	anchorName := flag.String("anchor", "", "anchor the report digest with this backend (noop); needs -report")
	flag.Parse()

	var anchorer anchor.Anchorer
	if *anchorName != "" {
		if *reportFile == "" {
			fmt.Fprintln(os.Stderr, "-anchor needs -report: only a written report can be anchored")
			os.Exit(exitToolError)
		}
		a, err := anchor.New(*anchorName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "anchor error: %v\n", err)
			os.Exit(exitToolError)
		}
		anchorer = a
	}

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
		digest, err := writeReport(*reportFile, report.Input{
			Result:      result,
			Policy:      p,
			Subject:     subjectName(*path),
			Commit:      *commit,
			ScannedAt:   scannedAt,
			ToolVersion: version,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "report error: %v\n", err)
			os.Exit(exitToolError)
		}
		fmt.Printf("Report:       %s\n", *reportFile)
		fmt.Printf("Digest:       %s\n", digest)

		if anchorer != nil {
			receipt, err := anchorReport(anchorer, digest, *reportFile+".anchor.json")
			if err != nil {
				fmt.Fprintf(os.Stderr, "anchor error: %v\n", err)
				os.Exit(exitToolError)
			}
			fmt.Printf("Anchored:     %s via %s\n", receipt.Digest, receipt.Backend)
		}
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

// writeReport writes the report and, next to it, "<file>.sha256" in
// sha256sum format, then returns the report's digest. Anchoring and
// verification use that digest; `sha256sum -c <file>.sha256` checks it.
func writeReport(file string, in report.Input) (string, error) {
	bom, err := report.Build(in)
	if err != nil {
		return "", err
	}
	data, err := bom.Encode()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(file+".sha256", []byte(report.ChecksumLine(data, file)), 0o644); err != nil {
		return "", err
	}
	return report.Digest(data), nil
}

func subjectName(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.Base(abs)
}

func anchorReport(a anchor.Anchorer, digest, receiptPath string) (anchor.Receipt, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	r, err := a.Anchor(ctx, digest)
	if err != nil {
		return anchor.Receipt{}, err
	}
	return r, anchor.WriteReceipt(receiptPath, r)
}
