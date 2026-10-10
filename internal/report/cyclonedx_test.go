package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/report"
)

var (
	gin    = model.Dependency{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "1.9.0", Direct: true, License: "MIT"}
	crypto = model.Dependency{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "0.0.0-20190308221718-c2843e01d9a2", License: "BSD-3-Clause"}
	types  = model.Dependency{Ecosystem: "npm", Name: "@types/node", Version: "20.0.0", Direct: true, License: ""}
	gpl    = model.Dependency{Ecosystem: "npm", Name: "gpl-lib", Version: "1.0.0", License: "GPL-3.0-only"}

	scannedAt = time.Date(2026, 10, 10, 9, 30, 15, 123456789, time.FixedZone("IST", 5*3600+1800))
)

func sampleResult() *model.ScanResult {
	critical := model.Finding{Dep: crypto, VulnID: "GHSA-crit", Aliases: []string{"GO-2", "CVE-2"}, Severity: "CRITICAL", Summary: "auth bypass", FixedVersion: "0.52.0", Modified: "2025-01-02T03:04:05Z"}
	moderate := model.Finding{Dep: gin, VulnID: "GHSA-mod", Severity: "MODERATE", Summary: "path traversal", FixedVersion: "1.9.1", Modified: "2024-06-01T00:00:00Z"}
	low := model.Finding{Dep: gin, VulnID: "GHSA-low", Severity: "LOW", Summary: "minor"}

	return &model.ScanResult{
		Deps:     []model.Dependency{gin, crypto, types, gpl},
		Findings: []model.Finding{critical, moderate, low},
		Violations: []model.Violation{
			{Kind: "vulnerability", Dep: crypto, ID: "GHSA-crit", Reason: "GHSA-crit (CRITICAL)"},
			{Kind: "license", Dep: gpl, Reason: "license denied by policy: GPL-3.0-only"},
		},
		Warnings: []model.Violation{
			{Kind: "vulnerability", Dep: gin, ID: "GHSA-mod", Reason: "GHSA-mod (MODERATE)"},
			{Kind: "license", Dep: types, Reason: "license could not be determined"},
		},
	}
}

func build(t *testing.T, r *model.ScanResult) *report.BOM {
	t.Helper()
	bom, err := report.Build(report.Input{
		Result:      r,
		Policy:      &policy.Policy{BlockSeverities: []string{"CRITICAL", "HIGH"}},
		Subject:     "depscan-go/depscan",
		Commit:      "abc123",
		ScannedAt:   scannedAt,
		ToolVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return bom
}

func encode(t *testing.T, bom *report.BOM) []byte {
	t.Helper()
	b, err := bom.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func prop(props []report.Property, name string) string {
	for _, p := range props {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func TestBuild_IsDeterministic(t *testing.T) {
	first := encode(t, build(t, sampleResult()))

	// Same data, every slice in reverse order.
	r := sampleResult()
	reverse := func(n int, swap func(i, j int)) {
		for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
			swap(i, j)
		}
	}
	reverse(len(r.Deps), func(i, j int) { r.Deps[i], r.Deps[j] = r.Deps[j], r.Deps[i] })
	reverse(len(r.Findings), func(i, j int) { r.Findings[i], r.Findings[j] = r.Findings[j], r.Findings[i] })
	reverse(len(r.Violations), func(i, j int) { r.Violations[i], r.Violations[j] = r.Violations[j], r.Violations[i] })
	reverse(len(r.Warnings), func(i, j int) { r.Warnings[i], r.Warnings[j] = r.Warnings[j], r.Warnings[i] })
	second := encode(t, build(t, r))

	if !bytes.Equal(first, second) {
		t.Fatalf("input order changed the output:\n--- first\n%s\n--- second\n%s", first, second)
	}
}

func TestBuild_Metadata(t *testing.T) {
	bom := build(t, sampleResult())

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || bom.Version != 1 {
		t.Errorf("header = %s %s v%d", bom.BOMFormat, bom.SpecVersion, bom.Version)
	}

	if got := bom.Metadata.Timestamp; got != "2026-10-10T04:00:15Z" {
		t.Errorf("timestamp = %q, want UTC to the second", got)
	}
	if got := bom.Metadata.Component.Name; got != "depscan-go/depscan" {
		t.Errorf("subject = %q", got)
	}
	props := bom.Metadata.Properties
	if prop(props, "depscan:result") != "fail" || prop(props, "depscan:violations") != "2" || prop(props, "depscan:warnings") != "2" {
		t.Errorf("result properties = %+v", props)
	}
	if prop(props, "depscan:commit") != "abc123" {
		t.Errorf("commit property missing: %+v", props)
	}
	if len(prop(props, "depscan:policy:sha256")) != 64 {
		t.Errorf("policy digest missing: %+v", props)
	}
}

func TestBuild_Components(t *testing.T) {
	bom := build(t, sampleResult())

	want := []string{
		"pkg:golang/github.com/gin-gonic/gin@v1.9.0",
		"pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2",
		"pkg:npm/%40types/node@20.0.0",
		"pkg:npm/gpl-lib@1.0.0",
	}
	if len(bom.Components) != len(want) {
		t.Fatalf("got %d components, want %d", len(bom.Components), len(want))
	}
	for i, w := range want {
		c := bom.Components[i]
		if c.PURL != w || c.BOMRef != w {
			t.Errorf("component[%d] purl = %q, want %q (sorted)", i, c.PURL, w)
		}
	}

	ginC, typesC, gplC := bom.Components[0], bom.Components[2], bom.Components[3]
	if len(ginC.Licenses) != 1 || ginC.Licenses[0].Expression != "MIT" {
		t.Errorf("gin licenses = %+v", ginC.Licenses)
	}
	if prop(ginC.Properties, "depscan:direct") != "true" {
		t.Errorf("gin should be direct: %+v", ginC.Properties)
	}
	if len(typesC.Licenses) != 0 || prop(typesC.Properties, "depscan:license:status") != "warn" {
		t.Errorf("unknown license should be omitted and warned: %+v", typesC)
	}
	if prop(gplC.Properties, "depscan:license:status") != "block" {
		t.Errorf("GPL package should be blocked: %+v", gplC.Properties)
	}
}

func TestBuild_Vulnerabilities(t *testing.T) {
	bom := build(t, sampleResult())

	type want struct{ id, severity, status, updated, rec string }
	wants := []want{
		{"GHSA-crit", "critical", "block", "2025-01-02T03:04:05Z", "Upgrade to 0.52.0"},
		{"GHSA-low", "low", "allowed", "", ""},
		{"GHSA-mod", "medium", "warn", "2024-06-01T00:00:00Z", "Upgrade to 1.9.1"},
	}
	if len(bom.Vulnerabilities) != len(wants) {
		t.Fatalf("got %d vulnerabilities, want %d", len(bom.Vulnerabilities), len(wants))
	}
	for i, w := range wants {
		v := bom.Vulnerabilities[i]
		if v.ID != w.id || v.Ratings[0].Severity != w.severity || prop(v.Properties, "depscan:policy:status") != w.status ||
			v.Updated != w.updated || v.Recommendation != w.rec {
			t.Errorf("vuln[%d] = %s/%s/%s/%q/%q, want %+v", i, v.ID, v.Ratings[0].Severity,
				prop(v.Properties, "depscan:policy:status"), v.Updated, v.Recommendation, w)
		}
	}

	crit := bom.Vulnerabilities[0]
	if crit.Affects[0].Ref != "pkg:golang/golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2" {
		t.Errorf("affects = %+v", crit.Affects)
	}
	if len(crit.References) != 2 || crit.References[0].ID != "CVE-2" || crit.References[1].ID != "GO-2" {
		t.Errorf("aliases should be sorted references: %+v", crit.References)
	}
}

func TestEncode_ValidJSONWithoutLocalData(t *testing.T) {
	out := encode(t, build(t, sampleResult()))

	var generic map[string]interface{}
	if err := json.Unmarshal(out, &generic); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if !bytes.HasSuffix(out, []byte("}\n")) {
		t.Error("report should end with a single newline")
	}
	if strings.Contains(string(out), `C:\`) || strings.Contains(string(out), "/home/") {
		t.Error("report must not contain local paths")
	}
}

func TestBuild_CleanScanPasses(t *testing.T) {
	bom := build(t, &model.ScanResult{Deps: []model.Dependency{gin}})
	if prop(bom.Metadata.Properties, "depscan:result") != "pass" {
		t.Error("a scan without violations should pass")
	}
	out := encode(t, bom)
	if !strings.Contains(string(out), `"vulnerabilities": []`) {
		t.Error("an empty vulnerability list should encode as [] not null")
	}
}

func TestBuild_RejectsMissingInputs(t *testing.T) {
	p := &policy.Policy{}
	r := &model.ScanResult{}
	cases := map[string]report.Input{
		"nil result": {Policy: p, ScannedAt: scannedAt},
		"nil policy": {Result: r, ScannedAt: scannedAt},
		"zero time":  {Result: r, Policy: p},
	}
	for name, in := range cases {
		if _, err := report.Build(in); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestPURL(t *testing.T) {
	cases := map[string]model.Dependency{
		"pkg:golang/github.com/gin-gonic/gin@v1.9.0":    {Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "1.9.0"},
		"pkg:golang/github.com/x/y@v2.0.0+incompatible": {Ecosystem: "Go", Name: "github.com/x/y", Version: "v2.0.0+incompatible"},
		"pkg:npm/%40babel/core@7.0.0":                   {Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0"},
		"pkg:npm/lodash@4.17.21":                        {Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
	}
	for want, d := range cases {
		if got := report.PURL(d); got != want {
			t.Errorf("PURL(%s) = %q, want %q", d.Name, got, want)
		}
	}
}
