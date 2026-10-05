package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/scan"
)

func TestResolveScanPath(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}

	h, err := New(scan.New(&policy.Policy{}), root)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"subfolder is allowed", "repo", false},
		{"root itself is allowed", ".", false},
		{"parent traversal is rejected", "../", true},
		{"nested traversal is rejected", "repo/../../", true},
		{"absolute path is rejected", "/etc", true},
		{"missing folder is rejected", "does-not-exist", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.resolveScanPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveScanPath(%q) err = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestCreateScan_RejectsTraversal(t *testing.T) {
	h, err := New(scan.New(&policy.Policy{}), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(`{"path":"../../"}`))
	rec := httptest.NewRecorder()
	h.CreateScan(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
}
