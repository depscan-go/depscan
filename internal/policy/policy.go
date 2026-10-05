package policy

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/depscan-go/depscan/internal/model"
)

type Policy struct {
	BlockSeverities []string    `yaml:"block_severities"`
	WarnSeverities  []string    `yaml:"warn_severities"`
	BlockUnknown    bool        `yaml:"block_unknown_severity"`
	CheckTransitive bool        `yaml:"check_transitive"`
	DeniedLicenses  []string    `yaml:"denied_licenses"`
	Exceptions      []Exception `yaml:"exceptions"`
	FailFast        bool        `yaml:"fail_fast"`
	MaxViolations   int         `yaml:"max_violations"`
}

type Exception struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires"`
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy file: %w", err)
	}

	return &p, nil
}

func (p *Policy) Validate() error {
	for i, e := range p.Exceptions {
		if e.ID == "" {
			return fmt.Errorf("exceptions[%d]: id is required", i)
		}
		if e.Reason == "" {
			return fmt.Errorf("exceptions[%d] (%s): reason is required", i, e.ID)
		}
		if e.Expires != "" {
			if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
				return fmt.Errorf("exceptions[%d] (%s): expires must be YYYY-MM-DD: %w", i, e.ID, err)
			}
		}
	}
	return nil
}

func (p *Policy) IsBlocked(severity string) bool {
	if severity == "UNKNOWN" {
		return p.BlockUnknown
	}
	for _, s := range p.BlockSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

func (p *Policy) IsWarned(severity string) bool {
	for _, s := range p.WarnSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

func (p *Policy) IsLicenseDenied(license string) bool {
	for _, l := range p.DeniedLicenses {
		if l == license {
			return true
		}
	}
	return false
}

func (p *Policy) IsException(f model.Finding) (bool, string) {
	return p.isExceptionAt(f, time.Now())
}

func (p *Policy) isExceptionAt(f model.Finding, now time.Time) (bool, string) {
	ids := append([]string{f.VulnID}, f.Aliases...)

	for _, e := range p.Exceptions {
		if !containsString(ids, e.ID) {
			continue
		}
		if e.Expires != "" {
			expiry, err := time.Parse("2006-01-02", e.Expires)
			if err != nil || !now.Before(expiry.Add(24*time.Hour)) {
				continue
			}
		}
		return true, e.Reason
	}
	return false, ""
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
