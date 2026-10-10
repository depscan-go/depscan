package policy

import (
	"fmt"

	"github.com/depscan-go/depscan/internal/license"
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

	if p.SkipLicenseCheck {
		return violations, warnings
	}

	deny := license.DenySet(p.DeniedLicenses)
	for _, dep := range deps {
		if license.Unknown(dep.License) {
			v := model.Violation{
				Kind:   "license",
				Dep:    dep,
				Reason: "license could not be determined (not on deps.dev or no SPDX identifier)",
			}
			if p.BlockUnknownLicense {
				violations = append(violations, v)
			} else {
				warnings = append(warnings, v)
			}
			continue
		}

		if ok, reason := license.Check(dep.License, deny, true); !ok {
			violations = append(violations, model.Violation{
				Kind:   "license",
				Dep:    dep,
				Reason: fmt.Sprintf("%s (declared: %s)", reason, dep.License),
			})
		}
	}

	return violations, warnings
}
