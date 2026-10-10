package api

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	h, err := New(scan.New(&policy.Policy{}), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDashboard_InjectsScanRoot(t *testing.T) {
	h := newTestHandler(t)

	rec := httptest.NewRecorder()
	h.Dashboard(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "__SCAN_ROOT_JSON__") || !strings.Contains(body, `DEPSCAN_ROOT = "`) {
		t.Fatalf("scan root not injected (status %d)", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Dashboard(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: status = %d, want 404", rec.Code)
	}
}

// Every /assets/ file the page references must exist, so a renamed or
// forgotten file fails here instead of as a blank page in the browser.
func TestDashboard_ReferencedAssetsExist(t *testing.T) {
	refs := regexp.MustCompile(`/assets/([A-Za-z0-9._-]+)`).FindAllStringSubmatch(indexHTML, -1)
	if len(refs) == 0 {
		t.Fatal("index.html references no assets")
	}
	for _, m := range refs {
		if _, ok := assets[m[1]]; !ok {
			t.Errorf("index.html loads /assets/%s, which is not embedded", m[1])
		}
	}
}

func TestAsset(t *testing.T) {
	h := newTestHandler(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/{name}", h.Asset)

	get := func(path, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	rec := get("/assets/app.js", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("app.js: status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("app.js: Content-Type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("app.js: missing nosniff")
	}
	etag := rec.Header().Get("ETag")
	if len(etag) != 18 {
		t.Fatalf("app.js: ETag = %q, want a quoted 16-hex hash", etag)
	}

	if rec := get("/assets/app.js", etag); rec.Code != http.StatusNotModified {
		t.Errorf("matching If-None-Match: status = %d, want 304", rec.Code)
	}
	if rec := get("/assets/app.css", ""); rec.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Errorf("app.css: Content-Type = %q", rec.Header().Get("Content-Type"))
	}

	for _, p := range []string{"/assets/nope.js", "/assets/index.html", "/assets/..%2Fweb.go"} {
		if rec := get(p, ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", p, rec.Code)
		}
	}
}
