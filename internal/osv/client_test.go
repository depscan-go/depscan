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
		writeJSON(t, w, resp)
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
					"package": map[string]string{"name": "axios", "ecosystem": "npm"},
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
		writeJSON(t, w, resp)
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

func TestQueryBatch_FixedVersionMatchesPackage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]interface{}{
			"results": []map[string]interface{}{
				{"vulns": []map[string]string{{"id": "GHSA-cjjc-xp8v-855w"}}},
			},
		})
	})
	mux.HandleFunc("/v1/vulns/GHSA-cjjc-xp8v-855w", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]interface{}{
			"id": "GHSA-cjjc-xp8v-855w",
			"affected": []map[string]interface{}{
				{ // listed first: the old code returned this one
					"package": map[string]string{"name": "github.com/helm/helm", "ecosystem": "Go"},
					"ranges":  []map[string]interface{}{{"events": []map[string]string{{"introduced": "2.0.0"}, {"fixed": "2.16.8"}}}},
				},
				{
					"package": map[string]string{"name": "helm.sh/helm/v3", "ecosystem": "Go"},
					"ranges":  []map[string]interface{}{{"events": []map[string]string{{"introduced": "3.0.0"}, {"fixed": "3.1.0"}}}},
				},
				{
					"package": map[string]string{"name": "golang.org/x/crypto", "ecosystem": "Go"},
					"ranges":  []map[string]interface{}{{"events": []map[string]string{{"introduced": "0"}, {"fixed": "0.0.0-20200124225646-8b5121be2f68"}}}},
				},
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	deps := []model.Dependency{{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "0.0.0-20190308221718-c2843e01d9a2"}}
	findings, err := osv.NewWithBaseURL(server.URL).QueryBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if got, want := findings[0].FixedVersion, "0.0.0-20200124225646-8b5121be2f68"; got != want {
		t.Errorf("FixedVersion = %q, want %q (must not pick another package's fix)", got, want)
	}
}

func TestQueryBatch_ResultCountMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]interface{}{"results": []interface{}{}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	deps := []model.Dependency{{Ecosystem: "npm", Name: "axios", Version: "0.21.1"}}
	if _, err := osv.NewWithBaseURL(server.URL).QueryBatch(context.Background(), deps); err == nil {
		t.Fatal("expected an error when result count does not match query count")
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding fake OSV response: %v", err)
	}
}
