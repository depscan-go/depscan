package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/policy"
)

type Input struct {
	Result *model.ScanResult
	Policy *policy.Policy

	Subject string

	Commit string

	ScannedAt time.Time

	ToolVersion string
}

type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	Version         int             `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      Tools      `json:"tools"`
	Component  Component  `json:"component"`
	Properties []Property `json:"properties"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type License struct {
	Expression string `json:"expression"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Vulnerability struct {
	BOMRef         string      `json:"bom-ref"`
	ID             string      `json:"id"`
	Source         Source      `json:"source"`
	References     []Reference `json:"references,omitempty"`
	Ratings        []Rating    `json:"ratings"`
	Description    string      `json:"description,omitempty"`
	Recommendation string      `json:"recommendation,omitempty"`
	Updated        string      `json:"updated,omitempty"`
	Affects        []Affect    `json:"affects"`
	Properties     []Property  `json:"properties"`
}

type Source struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type Reference struct {
	ID     string `json:"id"`
	Source Source `json:"source"`
}

type Rating struct {
	Source   Source `json:"source"`
	Severity string `json:"severity"`
}

type Affect struct {
	Ref string `json:"ref"`
}

const (
	propPolicySHA256  = "depscan:policy:sha256"
	propResult        = "depscan:result"
	propViolations    = "depscan:violations"
	propWarnings      = "depscan:warnings"
	propCommit        = "depscan:commit"
	propDirect        = "depscan:direct"
	propLicenseStatus = "depscan:license:status"
	propLicenseReason = "depscan:license:reason"
	propPolicyStatus  = "depscan:policy:status"
)

func Build(in Input) (*BOM, error) {
	if in.Result == nil {
		return nil, errors.New("report: nil scan result")
	}
	if in.Policy == nil {
		return nil, errors.New("report: nil policy")
	}
	if in.ScannedAt.IsZero() {
		return nil, errors.New("report: ScannedAt is required")
	}
	digest, err := in.Policy.Digest()
	if err != nil {
		return nil, err
	}

	toolVersion := in.ToolVersion
	if toolVersion == "" {
		toolVersion = "dev"
	}
	subject := in.Subject
	if subject == "" {
		subject = "unknown"
	}

	result := "pass"
	if len(in.Result.Violations) > 0 {
		result = "fail"
	}
	meta := []Property{
		{propPolicySHA256, digest},
		{propResult, result},
		{propViolations, strconv.Itoa(len(in.Result.Violations))},
		{propWarnings, strconv.Itoa(len(in.Result.Warnings))},
	}
	if in.Commit != "" {
		meta = append(meta, Property{propCommit, in.Commit})
	}

	return &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: Metadata{
			Timestamp: in.ScannedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
			Tools: Tools{Components: []Component{
				{Type: "application", Name: "depscan", Version: toolVersion},
			}},
			Component:  Component{Type: "application", Name: subject},
			Properties: meta,
		},
		Components:      components(in.Result),
		Vulnerabilities: vulnerabilities(in.Result),
	}, nil
}

func (b *BOM) Encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "<" and "&" readable; still deterministic
	enc.SetIndent("", "  ")
	if err := enc.Encode(b); err != nil {
		return nil, fmt.Errorf("encoding report: %w", err)
	}
	return buf.Bytes(), nil
}

func components(r *model.ScanResult) []Component {
	licStatus := map[string]outcome{}
	for _, v := range r.Warnings {
		if v.Kind == "license" {
			licStatus[PURL(v.Dep)] = outcome{"warn", v.Reason}
		}
	}
	for _, v := range r.Violations { // a block overrides a warning
		if v.Kind == "license" {
			licStatus[PURL(v.Dep)] = outcome{"block", v.Reason}
		}
	}

	byRef := map[string]*Component{}
	direct := map[string]bool{}
	for _, d := range r.Deps {
		ref := PURL(d)
		direct[ref] = direct[ref] || d.Direct
		if _, ok := byRef[ref]; ok {
			continue
		}
		c := &Component{
			Type:    "library",
			BOMRef:  ref,
			Name:    d.Name,
			Version: d.Version,
			PURL:    ref,
		}
		if lic := strings.TrimSpace(d.License); lic != "" && !strings.EqualFold(lic, "non-standard") && !strings.EqualFold(lic, "NOASSERTION") {
			c.Licenses = []License{{Expression: lic}}
		}
		byRef[ref] = c
	}

	out := make([]Component, 0, len(byRef))
	for ref, c := range byRef {
		c.Properties = []Property{{propDirect, strconv.FormatBool(direct[ref])}}
		if s, ok := licStatus[ref]; ok {
			c.Properties = append(c.Properties,
				Property{propLicenseStatus, s.status},
				Property{propLicenseReason, s.reason})
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BOMRef < out[j].BOMRef })
	return out
}

// outcome is the policy result attached to a report entry.
type outcome struct {
	status string // "block" or "warn"
	reason string
}

func vulnerabilities(r *model.ScanResult) []Vulnerability {
	status := map[string]string{}
	for _, v := range r.Warnings {
		if v.Kind == "vulnerability" {
			status[v.ID+"|"+PURL(v.Dep)] = "warn"
		}
	}
	for _, v := range r.Violations {
		if v.Kind == "vulnerability" {
			status[v.ID+"|"+PURL(v.Dep)] = "block"
		}
	}

	seen := map[string]bool{}
	out := make([]Vulnerability, 0, len(r.Findings))
	for _, f := range r.Findings {
		ref := PURL(f.Dep)
		key := f.VulnID + "|" + ref
		if seen[key] {
			continue
		}
		seen[key] = true

		s := status[key]
		if s == "" {

			s = "allowed"
		}

		v := Vulnerability{
			BOMRef:      f.VulnID + "/" + ref,
			ID:          f.VulnID,
			Source:      Source{Name: "OSV", URL: "https://osv.dev/vulnerability/" + url.PathEscape(f.VulnID)},
			Ratings:     []Rating{{Source: Source{Name: "OSV"}, Severity: severity(f.Severity)}},
			Description: f.Summary,
			Updated:     f.Modified,
			Affects:     []Affect{{Ref: ref}},
			Properties:  []Property{{propPolicyStatus, s}},
		}
		if f.FixedVersion != "" {
			v.Recommendation = "Upgrade to " + f.FixedVersion
		}

		aliases := append([]string(nil), f.Aliases...)
		sort.Strings(aliases)
		for _, a := range aliases {
			if a == f.VulnID {
				continue
			}
			v.References = append(v.References, Reference{
				ID:     a,
				Source: Source{Name: "OSV", URL: "https://osv.dev/vulnerability/" + url.PathEscape(a)},
			})
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BOMRef < out[j].BOMRef })
	return out
}

func severity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	}
	return "unknown"
}

func PURL(d model.Dependency) string {
	switch d.Ecosystem {
	case "Go":

		return "pkg:golang/" + escapePath(d.Name) + "@v" + escapeSegment(strings.TrimPrefix(d.Version, "v"))
	case "npm":
		return "pkg:npm/" + escapePath(d.Name) + "@" + escapeSegment(d.Version)
	}
	return "pkg:generic/" + escapeSegment(d.Name) + "@" + escapeSegment(d.Version)
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = escapeSegment(s)
	}
	return strings.Join(parts, "/")
}

func escapeSegment(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}
