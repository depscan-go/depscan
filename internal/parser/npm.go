package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/depscan-go/depscan/internal/model"
)

type NpmParser struct{}

func (p *NpmParser) Match(filename string) bool {
	return filename == "package-lock.json"
}

type npmLockfile struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]npmPackage `json:"packages"`
}

type npmPackage struct {
	Version         string            `json:"version"`
	Link            bool              `json:"link"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (p *NpmParser) Parse(r io.Reader) ([]model.Dependency, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading package-lock.json: %w", err)
	}

	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	if lock.LockfileVersion < 2 || lock.Packages == nil {
		return nil, fmt.Errorf("package-lock.json lockfileVersion %d is not supported (need 2 or 3, run npm >= 7)", lock.LockfileVersion)
	}

	root := lock.Packages[""]
	direct := make(map[string]bool)
	for name := range root.Dependencies {
		direct[name] = true
	}
	for name := range root.DevDependencies {
		direct[name] = true
	}

	seen := make(map[string]bool)
	var deps []model.Dependency

	for path, pkg := range lock.Packages {
		if path == "" || pkg.Link || pkg.Version == "" {
			continue
		}
		name := extractNpmName(path)
		if name == "" {
			continue
		}

		key := name + "@" + pkg.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		isTopLevel := path == "node_modules/"+name

		deps = append(deps, model.Dependency{
			Ecosystem: "npm",
			Name:      name,
			Version:   pkg.Version,
			Direct:    isTopLevel && direct[name],
		})
	}

	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})

	return deps, nil
}

func extractNpmName(path string) string {
	const prefix = "node_modules/"
	idx := strings.LastIndex(path, prefix)
	if idx == -1 {
		return ""
	}
	return path[idx+len(prefix):]
}
