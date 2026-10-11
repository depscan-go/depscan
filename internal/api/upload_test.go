package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
)

// fakeVulns reports one HIGH advisory for golang.org/x/net and records the
// dependencies it was asked about, so tests can see what the engine parsed.
type fakeVulns struct {
	mu   sync.Mutex
	seen []model.Dependency
}

func (f *fakeVulns) QueryBatch(_ context.Context, deps []model.Dependency) ([]model.Finding, error) {
	f.mu.Lock()
	f.seen = append(f.seen, deps...)
	f.mu.Unlock()
	var out []model.Finding
	for _, d := range deps {
		if d.Name == "golang.org/x/net" {
			out = append(out, model.Finding{Dep: d, VulnID: "GHSA-test-0001", Severity: "HIGH", FixedVersion: "0.17.0"})
		}
	}
	return out, nil
}

const testGoMod = `module example.com/shop

go 1.22

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.10.0 // indirect
)
`

const testLock = `{
  "name": "web", "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"axios": "^0.21.1"}},
    "node_modules/axios": {"version": "0.21.1", "resolved": "https://registry.npmjs.org/axios/-/axios-0.21.1.tgz"},
    "node_modules/follow-redirects": {"version": "1.14.0"}
  }
}`

func newUploadHandler(t *testing.T) (*Handler, *fakeVulns) {
	t.Helper()
	uploadTempDir = t.TempDir()
	t.Cleanup(func() { uploadTempDir = "" })
	fv := &fakeVulns{}
	eng := &scan.Engine{Vulns: fv, Policy: &policy.Policy{BlockSeverities: []string{"CRITICAL", "HIGH"}, CheckTransitive: true}}
	h, err := New(eng, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return h, fv
}

func uploadBody(t *testing.T, req uploadRequest, gz bool) *bytes.Buffer {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if !gz {
		return bytes.NewBuffer(raw)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func postUpload(h http.Handler, body *bytes.Buffer, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/scans/upload", body)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestScanUpload_ScansLockfilesWithTheirLayout(t *testing.T) {
	h, fv := newUploadHandler(t)
	body := uploadBody(t, uploadRequest{
		Name: "shop-api",
		Files: []uploadFile{
			{Path: "go.mod", Content: testGoMod},
			{Path: "web/package-lock.json", Content: testLock},
		},
	}, true)

	rec := postUpload(http.HandlerFunc(h.ScanUpload), body, map[string]string{"Content-Encoding": "gzip"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (a HIGH advisory blocks); body: %s", rec.Code, rec.Body)
	}

	var got ScanRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Path != "shop-api" || got.ID == "" {
		t.Errorf("record label = %q, id = %q", got.Path, got.ID)
	}
	if n := len(got.Result.Violations); n != 1 {
		t.Errorf("violations = %d, want 1", n)
	}

	var names []string
	for _, d := range fv.seen {
		names = append(names, d.Ecosystem+":"+d.Name)
	}
	sort.Strings(names)
	want := "Go:github.com/gin-gonic/gin Go:golang.org/x/net npm:axios npm:follow-redirects"
	if strings.Join(names, " ") != want {
		t.Errorf("parsed deps = %v, want %s", names, want)
	}

	// The scan is recorded like any other, so GET /scans/{id} finds it.
	if _, ok := h.scans[got.ID]; !ok {
		t.Error("upload scan was not recorded")
	}

	// The staging folder is gone.
	left, err := os.ReadDir(uploadTempDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestScanUpload_PlainJSONAndCleanResult(t *testing.T) {
	h, _ := newUploadHandler(t)
	body := uploadBody(t, uploadRequest{Name: "web", Files: []uploadFile{{Path: "package-lock.json", Content: testLock}}}, false)
	rec := postUpload(http.HandlerFunc(h.ScanUpload), body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
}

func TestScanUpload_RejectsUnsafePaths(t *testing.T) {
	h, fv := newUploadHandler(t)
	bad := []string{
		"", "../go.mod", "web/../../go.mod", "/etc/go.mod", "C:/Users/go.mod", `web\go.mod`,
		"./go.mod", "web//go.mod", "web/./go.mod", "web/", "main.go", "go.sum", "web/\x00/go.mod", "a/ /go.mod",
	}
	for _, p := range bad {
		body := uploadBody(t, uploadRequest{Name: "x", Files: []uploadFile{{Path: p, Content: testGoMod}}}, false)
		rec := postUpload(http.HandlerFunc(h.ScanUpload), body, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("path %q: status = %d, want 400", p, rec.Code)
		}
	}
	if len(fv.seen) != 0 {
		t.Errorf("engine ran for a rejected upload: %v", fv.seen)
	}
}

func TestScanUpload_RejectsBadRequests(t *testing.T) {
	h, _ := newUploadHandler(t)
	ok := uploadRequest{Name: "x", Files: []uploadFile{{Path: "go.mod", Content: testGoMod}}}

	tests := []struct {
		name    string
		body    *bytes.Buffer
		headers map[string]string
		want    int
	}{
		{"cross-site request", uploadBody(t, ok, false), map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"form content type", uploadBody(t, ok, false), map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		{"unknown encoding", uploadBody(t, ok, false), map[string]string{"Content-Encoding": "br"}, http.StatusUnsupportedMediaType},
		{"not gzip", uploadBody(t, ok, false), map[string]string{"Content-Encoding": "gzip"}, http.StatusBadRequest},
		{"not JSON", bytes.NewBufferString("{"), nil, http.StatusBadRequest},
		{"no files", uploadBody(t, uploadRequest{Name: "x"}, false), nil, http.StatusBadRequest},
		{"same file twice", uploadBody(t, uploadRequest{Files: []uploadFile{{Path: "go.mod"}, {Path: "GO.MOD"}}}, false), nil, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postUpload(http.HandlerFunc(h.ScanUpload), tt.body, tt.headers)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d; body: %s", rec.Code, tt.want, rec.Body)
			}
		})
	}
}

func TestScanUpload_SizeLimits(t *testing.T) {
	h, _ := newUploadHandler(t)

	// Over 1 MB as sent: the MaxBytes middleware the server wraps every route in.
	big := uploadBody(t, uploadRequest{Name: "x", Files: []uploadFile{{Path: "go.mod", Content: strings.Repeat("x", 2<<20)}}}, false)
	rec := postUpload(MaxBytes(http.HandlerFunc(h.ScanUpload)), big, nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("raw body over 1 MB: status = %d, want 413", rec.Code)
	}

	// Small when compressed but over the unpacked limit (a gzip bomb).
	old := maxUploadUnpacked
	maxUploadUnpacked = 1 << 20
	t.Cleanup(func() { maxUploadUnpacked = old })
	bomb := uploadBody(t, uploadRequest{Name: "x", Files: []uploadFile{{Path: "go.mod", Content: strings.Repeat("0", 3<<20)}}}, true)
	rec = postUpload(MaxBytes(http.HandlerFunc(h.ScanUpload)), bomb, map[string]string{"Content-Encoding": "gzip"})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("gzip bomb: status = %d, want 413; body: %s", rec.Code, rec.Body)
	}
}

func TestUploadLabel(t *testing.T) {
	cases := map[string]string{
		"  kyverno  ":            "kyverno",
		"":                       "picked folder",
		"evil\nname\x1b[31m":     "evilname[31m",
		strings.Repeat("é", 200): strings.Repeat("é", maxUploadNameLen),
	}
	for in, want := range cases {
		if got := uploadLabel(in); got != want {
			t.Errorf("uploadLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
