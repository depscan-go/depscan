package policy

import (
	"fmt"

	"github.com/depscan-go/depscan/internal/model"
)

func Evaluate(p *Policy, findings []model.Finding, deps []model.Dependency) (violations []model.Violation, warnings []model.Violation) {
	for _, f := range findings {

		if !p.CheckTransitive && !f.Dep.Direct {
			continue
		}

		if excepted, reason := p.IsException(f); excepted {
			fmt.Printf("  [skip] %s — exception: %s\n", f.VulnID, reason)
			continue
		}

		fixNote := "no fix available"
		if f.FixedVersion != "" {
			fixNote = "upgrade to " + f.FixedVersion
		}

		reason := fmt.Sprintf("%s (%s) — %s — %s", f.VulnID, f.Severity, f.Summary, fixNote)

		v := model.Violation{
			Kind:   "vulnerability",
			Dep:    f.Dep,
			Reason: reason,
		}

		if p.IsBlocked(f.Severity) {
			violations = append(violations, v)
			if p.FailFast {
				return violations, warnings
			}
		} else if p.IsWarned(f.Severity) {
			warnings = append(warnings, v)
		}

		if p.MaxViolations > 0 && len(violations) >= p.MaxViolations {
			return violations, warnings
		}
	}

	for _, dep := range deps {
		if dep.License == "" {
			continue
		}
		if p.IsLicenseDenied(dep.License) {
			violations = append(violations, model.Violation{
				Kind:   "license",
				Dep:    dep,
				Reason: fmt.Sprintf("license %s is not allowed by policy", dep.License),
			})
		}
	}

	return violations, warnings
}
