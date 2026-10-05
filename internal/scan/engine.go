package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/osv"
	"github.com/depscan-go/depscan/internal/parser"
	"github.com/depscan-go/depscan/internal/policy"
)

type Engine struct {
	OSV    *osv.Client
	Policy *policy.Policy
}

func New(p *policy.Policy) *Engine {
	return &Engine{
		OSV:    osv.New(),
		Policy: p,
	}
}

func (e *Engine) Run(ctx context.Context, path string) (*model.ScanResult, error) {

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
		if parsed == nil {
			return nil
		}

		deps = append(deps, parsed...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking path: %w", err)
	}

	findings, err := e.OSV.QueryBatch(ctx, deps)
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
