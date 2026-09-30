
package parser

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/D-source1602/depscan/internal/model"
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
		// req.Mod.Path  = "github.com/gin-gonic/gin"
		// req.Mod.Version = "v1.9.0"
		// req.Indirect  = true if it's a transitive dependency

		// OSV.dev expects Go versions WITHOUT the "v" prefix.
		// "v1.9.0" → "1.9.0"
		version := strings.TrimPrefix(req.Mod.Version, "v")

		deps = append(deps, model.Dependency{
			Ecosystem: "Go", 
			Name:      req.Mod.Path,
			Version:   version,
			Direct:    !req.Indirect,
		})
	}

	return deps, nil
}