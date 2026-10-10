package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
)

func fakeDepsDev(t *testing.T, licenses map[string][]string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		ls, ok := licenses[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"licenses": ls}); err != nil {
			t.Errorf("encoding fake response: %v", err)
		}
	}))
}

func TestLookup_GoAddsVPrefixAndEscapesSlashes(t *testing.T) {
	srv := fakeDepsDev(t, map[string][]string{
		"/v3/systems/GO/packages/github.com%2Fgin-gonic%2Fgin/versions/v1.9.0": {"MIT"},
	}, nil)
	defer srv.Close()

	dep := model.Dependency{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "1.9.0"}
	got, err := NewWithBaseURL(srv.URL).Lookup(context.Background(), dep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "MIT" {
		t.Errorf("license = %q, want MIT", got)
	}
}

func TestLookup_GoFallsBackToBareVersion(t *testing.T) {
	srv := fakeDepsDev(t, map[string][]string{
		"/v3/systems/GO/packages/example.com%2Fmod/versions/1.0.0": {"Apache-2.0"},
	}, nil)
	defer srv.Close()

	dep := model.Dependency{Ecosystem: "Go", Name: "example.com/mod", Version: "1.0.0"}
	got, err := NewWithBaseURL(srv.URL).Lookup(context.Background(), dep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "Apache-2.0" {
		t.Errorf("license = %q, want Apache-2.0", got)
	}
}

func TestLookup_ScopedNpmPackage(t *testing.T) {
	srv := fakeDepsDev(t, map[string][]string{
		"/v3/systems/NPM/packages/%40types%2Fnode/versions/20.0.0": {"MIT"},
	}, nil)
	defer srv.Close()

	dep := model.Dependency{Ecosystem: "npm", Name: "@types/node", Version: "20.0.0"}
	got, err := NewWithBaseURL(srv.URL).Lookup(context.Background(), dep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "MIT" {
		t.Errorf("license = %q, want MIT", got)
	}
}

func TestLookup_NotFoundIsUnknownNotError(t *testing.T) {
	srv := fakeDepsDev(t, map[string][]string{}, nil)
	defer srv.Close()

	dep := model.Dependency{Ecosystem: "npm", Name: "ghost-pkg", Version: "1.0.0"}
	got, err := NewWithBaseURL(srv.URL).Lookup(context.Background(), dep)
	if err != nil {
		t.Fatalf("404 should not be an error, got %v", err)
	}
	if got != "" {
		t.Errorf("license = %q, want empty (unknown)", got)
	}
}

func TestLookup_MultipleLicensesJoinedWithAnd(t *testing.T) {
	srv := fakeDepsDev(t, map[string][]string{
		"/v3/systems/NPM/packages/dual/versions/1.0.0": {"MIT", "Apache-2.0 OR GPL-3.0-only"},
	}, nil)
	defer srv.Close()

	dep := model.Dependency{Ecosystem: "npm", Name: "dual", Version: "1.0.0"}
	got, err := NewWithBaseURL(srv.URL).Lookup(context.Background(), dep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "MIT AND (Apache-2.0 OR GPL-3.0-only)"; got != want {
		t.Errorf("license = %q, want %q", got, want)
	}
}

func TestLookup_CachesResults(t *testing.T) {
	var hits int32
	srv := fakeDepsDev(t, map[string][]string{
		"/v3/systems/NPM/packages/axios/versions/0.21.1": {"MIT"},
	}, &hits)
	defer srv.Close()

	c := NewWithBaseURL(srv.URL)
	dep := model.Dependency{Ecosystem: "npm", Name: "axios", Version: "0.21.1"}
	for i := 0; i < 3; i++ {
		if _, err := c.Lookup(context.Background(), dep); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (cached)", hits)
	}
}

func TestLookup_RetriesServerErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"licenses":["ISC"]}`))
	}))
	defer srv.Close()

	dep := model.Dependency{Ecosystem: "npm", Name: "x", Version: "1.0.0"}
	got, err := NewWithBaseURL(srv.URL).Lookup(context.Background(), dep)
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if got != "ISC" || calls != 2 {
		t.Errorf("got %q after %d calls, want ISC after 2", got, calls)
	}
}

func TestEnrich_FillsLicensesConcurrently(t *testing.T) {
	srv := fakeDepsDev(t, map[string][]string{
		"/v3/systems/NPM/packages/a/versions/1.0.0": {"MIT"},
		"/v3/systems/NPM/packages/b/versions/1.0.0": {"GPL-3.0-only"},
	}, nil)
	defer srv.Close()

	deps := []model.Dependency{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "missing", Version: "1.0.0"},
		{Ecosystem: "PyPI", Name: "requests", Version: "2.0.0"}, // unsupported: skipped
	}
	if errs := NewWithBaseURL(srv.URL).Enrich(context.Background(), deps); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	want := []string{"MIT", "GPL-3.0-only", "", ""}
	for i, w := range want {
		if deps[i].License != w {
			t.Errorf("deps[%d].License = %q, want %q", i, deps[i].License, w)
		}
	}
}
