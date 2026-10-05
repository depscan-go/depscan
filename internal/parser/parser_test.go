package parser_test

import (
	"os"
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
