package parser

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/depscan-go/depscan/internal/model"
)

type GoModParser struct{}

func (p *GoModParser) Match(filename string) bool {
	return filename == "go.mod"
}

func (p *GoModParser) Parse(r io.Reader) ([]model.Dependency, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	var deps []model.Dependency

	for _, req := range f.Require {
		mod, ok := applyReplace(f.Replace, req.Mod.Path, req.Mod.Version)
		if !ok {

			continue
		}

		deps = append(deps, model.Dependency{
			Ecosystem: "Go",
			Name:      mod.path,

			Version: strings.TrimPrefix(mod.version, "v"),

			Direct: !req.Indirect,
		})
	}

	return deps, nil
}

type module struct{ path, version string }

func applyReplace(replaces []*modfile.Replace, path, version string) (m module, ok bool) {
	var match *modfile.Replace
	for _, r := range replaces {
		if r.Old.Path != path {
			continue
		}
		if r.Old.Version == version {
			match = r
			break
		}
		if r.Old.Version == "" && match == nil {
			match = r
		}
	}

	if match == nil {
		return module{path, version}, true
	}
	if match.New.Version == "" {
		return module{}, false
	}
	return module{match.New.Path, match.New.Version}, true
}
