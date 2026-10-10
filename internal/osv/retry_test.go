package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/osv"
)

func dropOnce(calls *int32, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(calls, 1) == 1 {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return
		}
		next(w, r)
	}
}

func oneVulnServer(t *testing.T, batch, detail http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", batch)
	mux.HandleFunc("/v1/vulns/GHSA-test", detail)
	return httptest.NewServer(mux)
}

func batchOK(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"results": []map[string]any{{"vulns": []map[string]string{{"id": "GHSA-test"}}}}})
	}
}

func detailOK(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"id": "GHSA-test", "database_specific": map[string]string{"severity": "HIGH"}})
	}
}

var axios = []model.Dependency{{Ecosystem: "npm", Name: "axios", Version: "0.21.1"}}

func TestQueryBatch_RetriesDroppedConnections(t *testing.T) {
	var batchCalls, detailCalls int32
	srv := oneVulnServer(t, dropOnce(&batchCalls, batchOK(t)), dropOnce(&detailCalls, detailOK(t)))
	defer srv.Close()

	findings, err := osv.NewWithBaseURL(srv.URL).QueryBatch(context.Background(), axios)
	if err != nil {
		t.Fatalf("one dropped connection per endpoint should be retried, got %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("findings = %+v, want the HIGH advisory", findings)
	}
}

func TestQueryBatch_FailedAdvisoryFailsTheScan(t *testing.T) {
	srv := oneVulnServer(t, batchOK(t), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	defer srv.Close()

	findings, err := osv.NewWithBaseURL(srv.URL).QueryBatch(context.Background(), axios)
	if err == nil {
		t.Fatalf("want an error when an advisory cannot be fetched, got %d findings and no error", len(findings))
	}
}

func TestQueryBatch_WithdrawnAdvisoryIsSkipped(t *testing.T) {
	srv := oneVulnServer(t, batchOK(t), http.NotFound)
	defer srv.Close()

	findings, err := osv.NewWithBaseURL(srv.URL).QueryBatch(context.Background(), axios)
	if err != nil || len(findings) != 0 {
		t.Fatalf("got %d findings, %v; want a 404 advisory skipped without failing", len(findings), err)
	}
}
