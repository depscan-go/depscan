package osv_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/osv"
)

func TestQueryBatch_FindsVulnerability(t *testing.T) {

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"results": []map[string]interface{}{
				{
					"vulns": []map[string]string{
						{"id": "GHSA-42xw-2xvc-qx8m"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/vulns/GHSA-42xw-2xvc-qx8m", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"id":      "GHSA-42xw-2xvc-qx8m",
			"summary": "Axios vulnerable to SSRF",
			"aliases": []string{"CVE-2020-28168"},
			"database_specific": map[string]string{
				"severity": "MEDIUM",
			},
			"affected": []map[string]interface{}{
				{
					"ranges": []map[string]interface{}{
						{
							"events": []map[string]string{
								{"fixed": "0.21.2"},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := osv.NewWithBaseURL(server.URL)

	deps := []model.Dependency{
		{
			Ecosystem: "npm",
			Name:      "axios",
			Version:   "0.21.1",
			Direct:    true,
		},
	}

	findings, err := client.QueryBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.VulnID != "GHSA-42xw-2xvc-qx8m" {
		t.Errorf("wrong vuln ID: got %q", f.VulnID)
	}
	if f.Severity != "MEDIUM" {
		t.Errorf("wrong severity: got %q", f.Severity)
	}
	if f.FixedVersion != "0.21.2" {
		t.Errorf("wrong fixed version: got %q", f.FixedVersion)
	}
	if f.Dep.Name != "axios" {
		t.Errorf("wrong dep name: got %q", f.Dep.Name)
	}
}

func TestQueryBatch_NoDeps(t *testing.T) {
	client := osv.NewWithBaseURL("http://should-not-be-called")
	findings, err := client.QueryBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
