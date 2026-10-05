package parser_test

import (
	"os"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/parser"
)

func TestGoModParser(t *testing.T) {
	f, err := os.Open("../../testdata/go.mod")
	if err != nil {
		t.Fatalf("opening testdata: %v", err)
	}
	defer f.Close()

	deps, err := parser.ParseFile("go.mod", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}

	tests := []struct {
		name      string
		ecosystem string
		version   string
		direct    bool
	}{
		{"github.com/gin-gonic/gin", "Go", "1.9.0", true},
		{"golang.org/x/crypto", "Go", "0.0.0-20190308221718-c2843e01d9a2", false},
	}

	for i, tt := range tests {
		d := deps[i]
		if d.Name != tt.name {
			t.Errorf("dep[%d].Name: want %q got %q", i, tt.name, d.Name)
		}
		if d.Ecosystem != tt.ecosystem {
			t.Errorf("dep[%d].Ecosystem: want %q got %q", i, tt.ecosystem, d.Ecosystem)
		}
		if d.Version != tt.version {
			t.Errorf("dep[%d].Version: want %q got %q", i, tt.version, d.Version)
		}
		if d.Direct != tt.direct {
			t.Errorf("dep[%d].Direct: want %v got %v", i, tt.direct, d.Direct)
		}
	}
}

func TestNpmParser(t *testing.T) {
	f, err := os.Open("../../testdata/package-lock.json")
	if err != nil {
		t.Fatalf("opening testdata: %v", err)
	}
	defer f.Close()

	deps, err := parser.ParseFile("package-lock.json", f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []struct {
		name    string
		version string
		direct  bool
	}{
		{"@types/node", "20.0.0", true},       // devDependency of root
		{"axios", "0.21.1", true},             // dependency of root
		{"follow-redirects", "1.14.7", false}, // pulled in by axios
	}

	if len(deps) != len(want) {
		t.Fatalf("expected %d deps, got %d: %+v", len(want), len(deps), deps)
	}
	for i, w := range want {
		d := deps[i]
		if d.Name != w.name || d.Version != w.version || d.Direct != w.direct || d.Ecosystem != "npm" {
			t.Errorf("dep[%d] = %+v, want name=%s version=%s direct=%v ecosystem=npm",
				i, d, w.name, w.version, w.direct)
		}
	}
}

func TestNpmParser_RejectsLockfileV1(t *testing.T) {
	v1 := `{"lockfileVersion": 1, "dependencies": {"axios": {"version": "0.21.1"}}}`
	_, err := parser.ParseFile("package-lock.json", strings.NewReader(v1))
	if err == nil {
		t.Fatal("expected an error for lockfileVersion 1")
	}
}

func TestNpmParser_MalformedJSON(t *testing.T) {
	_, err := parser.ParseFile("package-lock.json", strings.NewReader("{not json"))
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}
