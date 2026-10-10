package osv

import (
	"sort"
	"strings"

	"github.com/depscan-go/depscan/internal/model"
)

func dedupe(findings []model.Finding) []model.Finding {
	if len(findings) < 2 {
		return findings
	}

	// Union-find over finding indexes, keyed by package + identifier.
	parent := make([]int, len(findings))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}

	owner := map[string]int{}
	for i, f := range findings {
		pkg := f.Dep.Ecosystem + "|" + f.Dep.Name + "@" + f.Dep.Version
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			key := pkg + "|" + strings.ToUpper(id)
			if j, ok := owner[key]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[key] = i
			}
		}
	}

	groups := map[int][]int{}
	var roots []int
	for i := range findings {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], i)
	}

	out := make([]model.Finding, 0, len(roots))
	for _, r := range roots {
		members := groups[r]
		best := members[0]
		for _, m := range members[1:] {
			if better(findings[m], findings[best]) {
				best = m
			}
		}
		out = append(out, merge(findings[best], members, findings))
	}
	return out
}

func better(a, b model.Finding) bool {
	if ka, kb := knownSeverity(a), knownSeverity(b); ka != kb {
		return ka
	}
	if ga, gb := strings.HasPrefix(a.VulnID, "GHSA-"), strings.HasPrefix(b.VulnID, "GHSA-"); ga != gb {
		return ga
	}
	return a.VulnID < b.VulnID
}

func knownSeverity(f model.Finding) bool {
	return f.Severity != "" && f.Severity != "UNKNOWN"
}

func merge(keep model.Finding, members []int, all []model.Finding) model.Finding {
	ids := map[string]bool{}
	for _, m := range members {
		f := all[m]
		ids[f.VulnID] = true
		for _, a := range f.Aliases {
			ids[a] = true
		}
		if keep.Summary == "" {
			keep.Summary = f.Summary
		}
		if keep.FixedVersion == "" {
			keep.FixedVersion = f.FixedVersion
		}
	}
	delete(ids, keep.VulnID)

	aliases := make([]string, 0, len(ids))
	for id := range ids {
		aliases = append(aliases, id)
	}
	sort.Strings(aliases)
	keep.Aliases = aliases
	return keep
}
