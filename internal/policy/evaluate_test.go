package policy_test

import (
	"testing"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/policy"
)

func finding(name, severity string, direct bool) model.Finding {
	return model.Finding{
		Dep:          model.Dependency{Name: name, Version: "1.0.0", Direct: direct},
		VulnID:       "GHSA-test-" + name,
		Severity:     severity,
		Summary:      "test vulnerability",
		FixedVersion: "2.0.0",
	}
}

func TestEvaluate_BlocksCriticalAndHigh(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL", "HIGH"},
		WarnSeverities:  []string{"MODERATE"},
		CheckTransitive: true,
	}

	findings := []model.Finding{
		finding("pkg-critical", "CRITICAL", true),
		finding("pkg-high", "HIGH", true),
		finding("pkg-moderate", "MODERATE", true),
		finding("pkg-unknown", "UNKNOWN", true),
	}

	violations, warnings := policy.Evaluate(p, findings, nil)

	if len(violations) != 2 {
		t.Errorf("expected 2 violations (CRITICAL+HIGH), got %d", len(violations))
	}
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning (MODERATE), got %d", len(warnings))
	}
}

func TestEvaluate_BlockUnknown_False(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		BlockUnknown:    false,
		CheckTransitive: true,
	}

	findings := []model.Finding{
		finding("pkg-unknown", "UNKNOWN", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations when block_unknown=false, got %d", len(violations))
	}
}

func TestEvaluate_BlockUnknown_True(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		BlockUnknown:    true,
		CheckTransitive: true,
	}

	findings := []model.Finding{
		finding("pkg-unknown", "UNKNOWN", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)
	if len(violations) != 1 {
		t.Errorf("expected 1 violation when block_unknown=true, got %d", len(violations))
	}
}

func TestEvaluate_SkipsTransitiveWhenDisabled(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		CheckTransitive: false,
	}

	findings := []model.Finding{
		finding("transitive-pkg", "CRITICAL", false),
		finding("direct-pkg", "CRITICAL", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)

	if len(violations) != 1 {
		t.Errorf("expected 1 violation (direct only), got %d", len(violations))
	}
	if violations[0].Dep.Name != "direct-pkg" {
		t.Errorf("wrong dep blocked: %s", violations[0].Dep.Name)
	}
}

func TestEvaluate_ExceptionSkipsVuln(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		CheckTransitive: true,
		Exceptions: []policy.Exception{
			{
				ID:     "GHSA-test-pkg-critical",
				Reason: "does not affect our usage",
			},
		},
	}

	findings := []model.Finding{
		finding("pkg-critical", "CRITICAL", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)
	if len(violations) != 0 {
		t.Errorf("expected 0 violations (excepted), got %d", len(violations))
	}
}

func TestEvaluate_ExpiredExceptionStillBlocks(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		CheckTransitive: true,
		Exceptions: []policy.Exception{
			{
				ID:      "GHSA-test-pkg-critical",
				Reason:  "expired exception",
				Expires: "2000-01-01", // already expired
			},
		},
	}

	findings := []model.Finding{
		finding("pkg-critical", "CRITICAL", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)
	if len(violations) != 1 {
		t.Errorf("expected 1 violation (exception expired), got %d", len(violations))
	}
}

func TestEvaluate_FailFastStopsAfterFirst(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		CheckTransitive: true,
		FailFast:        true,
	}

	findings := []model.Finding{
		finding("pkg-a", "CRITICAL", true),
		finding("pkg-b", "CRITICAL", true),
		finding("pkg-c", "CRITICAL", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)
	if len(violations) != 1 {
		t.Errorf("expected 1 violation (fail_fast), got %d", len(violations))
	}
}

func TestEvaluate_MaxViolationsCap(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL"},
		CheckTransitive: true,
		MaxViolations:   2,
	}

	findings := []model.Finding{
		finding("pkg-a", "CRITICAL", true),
		finding("pkg-b", "CRITICAL", true),
		finding("pkg-c", "CRITICAL", true),
	}

	violations, _ := policy.Evaluate(p, findings, nil)
	if len(violations) != 2 {
		t.Errorf("expected 2 violations (max_violations cap), got %d", len(violations))
	}
}

func TestEvaluate_DeniedLicense(t *testing.T) {
	p := &policy.Policy{
		CheckTransitive: true,
		DeniedLicenses:  []string{"GPL-3.0"},
	}

	deps := []model.Dependency{
		{Name: "gpl-pkg", Version: "1.0.0", License: "GPL-3.0", Direct: true},
		{Name: "mit-pkg", Version: "1.0.0", License: "MIT", Direct: true},
	}

	violations, _ := policy.Evaluate(p, nil, deps)
	if len(violations) != 1 {
		t.Errorf("expected 1 license violation, got %d", len(violations))
	}
	if violations[0].Dep.Name != "gpl-pkg" {
		t.Errorf("wrong dep in license violation: %s", violations[0].Dep.Name)
	}
}

func TestEvaluate_NoFindings(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities: []string{"CRITICAL", "HIGH"},
		CheckTransitive: true,
	}

	violations, warnings := policy.Evaluate(p, nil, nil)
	if len(violations) != 0 || len(warnings) != 0 {
		t.Errorf("expected clean scan, got %d violations %d warnings", len(violations), len(warnings))
	}
}
