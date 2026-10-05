package parser

import (
	"io"
	"path/filepath"

	"github.com/depscan-go/depscan/internal/model"
)

type Parser interface {
	Match(filename string) bool
	Parse(r io.Reader) ([]model.Dependency, error)
}

var registry = []Parser{
	&GoModParser{},
	&NpmParser{},
}

func ParseFile(filename string, r io.Reader) ([]model.Dependency, error) {
	base := filepath.Base(filename)
	for _, p := range registry {
		if p.Match(base) {
			return p.Parse(r)
		}
	}
	return nil, nil
}
