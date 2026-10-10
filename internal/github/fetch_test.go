package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/github"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func fakeGitHub(t *testing.T, tree []map[string]any, blobs map[string]string, truncated bool, auth *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{name}/git/trees/{sha}", func(w http.ResponseWriter, r *http.Request) {
		if auth != nil {
			*auth = r.Header.Get("Authorization")
		}
		if r.PathValue("owner") != "acme" || r.URL.Query().Get("recursive") != "1" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"truncated": truncated, "tree": tree}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("GET /repos/{owner}/{name}/git/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github.raw" {
			http.Error(w, "want raw", http.StatusBadRequest)
			return
		}
		body, ok := blobs[r.PathValue("sha")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	})
	return httptest.NewServer(mux)
}

func blob(path, sha string) map[string]any {
	return map[string]any{"path": path, "type": "blob", "sha": sha, "size": 10}
}

func TestFetchLockfiles_OnlyLockfilesOutsideVendor(t *testing.T) {
	var auth string
	srv := fakeGitHub(t, []map[string]any{
		blob("go.mod", "b1"),
		blob("web/package-lock.json", "b2"),
		blob("vendor/x/go.mod", "b3"),                      // skipped like the local scanner
		blob("web/node_modules/a/package-lock.json", "b4"), // skipped
		blob("README.md", "b5"),                            // not a lockfile
		{"path": "docs", "type": "tree", "sha": "t1"},
	}, map[string]string{"b1": "module x\n", "b2": `{"lockfileVersion":3}`}, false, &auth)
	defer srv.Close()

	dir := t.TempDir()
	n, err := github.NewFetcherWithBaseURL(srv.URL, "tok").FetchLockfiles(context.Background(), "acme/app", sha, dir)
	if err != nil {
		t.Fatalf("FetchLockfiles: %v", err)
	}
	if n != 2 {
		t.Errorf("wrote %d files, want 2", n)
	}
	for p, want := range map[string]string{"go.mod": "module x\n", "web/package-lock.json": `{"lockfileVersion":3}`} {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", p, got, err, want)
		}
	}
	if auth != "Bearer tok" {
		t.Errorf("Authorization = %q, want the token", auth)
	}
}

func TestFetchLockfiles_RefusesPathTraversal(t *testing.T) {
	srv := fakeGitHub(t, []map[string]any{blob("../../evil/go.mod", "b1")}, map[string]string{"b1": "x"}, false, nil)
	defer srv.Close()

	if _, err := github.NewFetcherWithBaseURL(srv.URL, "").FetchLockfiles(context.Background(), "acme/app", sha, t.TempDir()); err == nil {
		t.Fatal("a tree path escaping the folder must be refused")
	}
}

func TestFetchLockfiles_TruncatedTreeFailsLoudly(t *testing.T) {
	srv := fakeGitHub(t, nil, nil, true, nil)
	defer srv.Close()

	if _, err := github.NewFetcherWithBaseURL(srv.URL, "").FetchLockfiles(context.Background(), "acme/app", sha, t.TempDir()); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("got %v, want a truncated-tree error", err)
	}
}

func TestFetchLockfiles_NotFound(t *testing.T) {
	srv := fakeGitHub(t, nil, nil, false, nil)
	defer srv.Close()

	_, err := github.NewFetcherWithBaseURL(srv.URL, "").FetchLockfiles(context.Background(), "other/repo", sha, t.TempDir())
	if !errors.Is(err, github.ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestFetchLockfiles_ValidatesInputs(t *testing.T) {
	f := github.NewFetcherWithBaseURL("http://unused.invalid", "")
	for _, c := range []struct{ repo, sha string }{
		{"acme", sha},
		{"../..", sha},
		{"acme/app/extra", sha},
		{"acme/app", "main"},
		{"acme/app", strings.ToUpper(sha)},
	} {
		if _, err := f.FetchLockfiles(context.Background(), c.repo, c.sha, t.TempDir()); err == nil {
			t.Errorf("FetchLockfiles(%q, %q) should fail", c.repo, c.sha)
		}
	}
}
