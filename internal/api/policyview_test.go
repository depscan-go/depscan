package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
)

func TestPolicyView(t *testing.T) {
	p := &policy.Policy{
		BlockSeverities:     []string{"CRITICAL", "HIGH"},
		CheckTransitive:     true,
		DeniedLicenses:      []string{"GPL-3.0-only"},
		BlockUnknownLicense: true,
		Exceptions:          []policy.Exception{{ID: "GHSA-2c4m-59x9-fr2g", Reason: "not used", Expires: "2026-12-31"}},
	}
	h, err := New(&scan.Engine{Policy: p}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.PolicyView(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	// Empty lists are [] rather than null, so the page never special-cases them.
	if string(raw["warn_severities"]) != "[]" {
		t.Errorf("warn_severities = %s, want []", raw["warn_severities"])
	}

	var v policyView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	want, _ := p.Digest()
	if v.Digest != want {
		t.Errorf("digest = %q, want %q", v.Digest, want)
	}
	if !v.CheckTransitive || !v.BlockUnknownLicense || len(v.BlockSeverities) != 2 || v.DeniedLicenses[0] != "GPL-3.0-only" {
		t.Errorf("unexpected view: %+v", v)
	}
	if len(v.Exceptions) != 1 || v.Exceptions[0].Expires != "2026-12-31" {
		t.Errorf("exceptions = %+v", v.Exceptions)
	}
}

func TestPolicyView_NoPolicy(t *testing.T) {
	h, err := New(&scan.Engine{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.PolicyView(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
