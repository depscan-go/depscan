package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/depscan-go/depscan/internal/license"
	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/osv"
	"github.com/depscan-go/depscan/internal/parser"
	"github.com/depscan-go/depscan/internal/policy"
)

// VulnSource finds known vulnerabilities for a set of dependencies.
// *osv.Client is the real implementation; tests use a fake.
type VulnSource interface {
	QueryBatch(ctx context.Context, deps []model.Dependency) ([]model.Finding, error)
}

// LicenseSource fills in Dependency.License in place. It fails soft: a lookup
// that errors leaves that license empty (unknown) and is returned so the
// caller can warn, but it never fails the whole scan.
// *license.Client is the real implementation.
type LicenseSource interface {
	Enrich(ctx context.Context, deps []model.Dependency) []error
}

// Engine runs one scan: parse lockfiles, look up licenses, query
// vulnerabilities, then apply the policy.
type Engine struct {
	Vulns    VulnSource
	Licenses LicenseSource // nil disables license lookups
	Policy   *policy.Policy
}

// New wires the engine to the real OSV.dev and deps.dev clients.
func New(p *policy.Policy) *Engine {
	e := &Engine{
		Vulns:  osv.New(),
		Policy: p,
	}
	if !p.SkipLicenseCheck {
		e.Licenses = license.New()
	}
	return e
}

func (e *Engine) Run(ctx context.Context, path string) (*model.ScanResult, error) {
	deps, err := collect(path)
	if err != nil {
		return nil, err
	}

	// License lookups fail soft: a package we can't look up keeps an empty
	// license, which the policy turns into a warning (or a violation with
	// block_unknown_license). One summary line instead of one per package,
	// so an offline run doesn't print hundreds of identical errors.
	if e.Licenses != nil && !e.Policy.SkipLicenseCheck {
		if errs := e.Licenses.Enrich(ctx, deps); len(errs) > 0 {
			fmt.Printf("[warn] license lookup failed for %d package(s), first error: %v\n", len(errs), errs[0])
		}
	}

	findings, err := e.Vulns.QueryBatch(ctx, deps)
	if err != nil {
		return nil, fmt.Errorf("querying OSV: %w", err)
	}

	violations, warnings := policy.Evaluate(e.Policy, findings, deps)

	return &model.ScanResult{
		Deps:       deps,
		Findings:   findings,
		Violations: violations,
		Warnings:   warnings,
	}, nil
}

// collect walks path and parses every lockfile it recognises.
func collect(path string) ([]model.Dependency, error) {
	var deps []model.Dependency

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }() // opened read-only

		parsed, err := parser.ParseFile(info.Name(), f)
		if err != nil {
			fmt.Printf("[warn] %s: %v\n", filePath, err)
			return nil
		}
		deps = append(deps, parsed...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking path: %w", err)
	}
	return deps, nil
}
