package parser_test

import (
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/parser"
)

func parseGoMod(t *testing.T, gomod string) []model.Dependency {
	t.Helper()
	deps, err := parser.ParseFile("go.mod", strings.NewReader(gomod))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return deps
}

func TestGoModReplace(t *testing.T) {
	const header = "module example.com/app\n\ngo 1.22\n\n"

	tests := []struct {
		name string
		body string
		want []model.Dependency
	}{
		{
			name: "no replace",
			body: "require github.com/a/lib v1.0.0\n",
			want: []model.Dependency{{Ecosystem: "Go", Name: "github.com/a/lib", Version: "1.0.0", Direct: true}},
		},
		{
			name: "replace all versions with a newer release",
			body: "require github.com/a/lib v1.0.0\n" +
				"replace github.com/a/lib => github.com/a/lib v1.0.5\n",
			want: []model.Dependency{{Ecosystem: "Go", Name: "github.com/a/lib", Version: "1.0.5", Direct: true}},
		},
		{
			name: "replace with a fork keeps indirect status",
			body: "require github.com/a/lib v1.0.0 // indirect\n" +
				"replace github.com/a/lib => github.com/me/lib-fork v1.0.1\n",
			want: []model.Dependency{{Ecosystem: "Go", Name: "github.com/me/lib-fork", Version: "1.0.1", Direct: false}},
		},
		{
			name: "version-specific replace wins over a wildcard",
			body: "require github.com/a/lib v1.0.0\n" +
				"replace github.com/a/lib => github.com/a/lib v1.9.9\n" +
				"replace github.com/a/lib v1.0.0 => github.com/a/lib v1.0.2\n",
			want: []model.Dependency{{Ecosystem: "Go", Name: "github.com/a/lib", Version: "1.0.2", Direct: true}},
		},
		{
			name: "replace for a different version does not apply",
			body: "require github.com/a/lib v1.0.0\n" +
				"replace github.com/a/lib v0.9.0 => github.com/a/lib v0.9.1\n",
			want: []model.Dependency{{Ecosystem: "Go", Name: "github.com/a/lib", Version: "1.0.0", Direct: true}},
		},
		{
			name: "local directory replace is skipped",
			body: "require (\n\tgithub.com/a/lib v1.0.0\n\tgithub.com/b/lib v2.0.0+incompatible\n)\n" +
				"replace github.com/a/lib => ../lib\n",
			want: []model.Dependency{{Ecosystem: "Go", Name: "github.com/b/lib", Version: "2.0.0+incompatible", Direct: true}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseGoMod(t, header+tt.body)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d deps %+v, want %d %+v", len(got), got, len(tt.want), tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("dep[%d] = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
