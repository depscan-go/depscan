package osv

import (
	"reflect"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
)

var (
	crypto = model.Dependency{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "0.0.0-20190308221718-c2843e01d9a2"}
	gin    = model.Dependency{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "1.9.0"}
)

func TestDedupe_MergesGoAndGHSARecords(t *testing.T) {

	in := []model.Finding{
		{Dep: crypto, VulnID: "GO-2020-0012", Aliases: []string{"CVE-2020-9283", "GHSA-ffhg-7mh4-33c4"}, Severity: "UNKNOWN", Summary: "Go DB summary"},
		{Dep: crypto, VulnID: "GHSA-ffhg-7mh4-33c4", Aliases: []string{"CVE-2020-9283"}, Severity: "HIGH", Summary: "GitHub summary", FixedVersion: "0.0.0-20200220183623-bac4c82f6975"},
	}

	got := dedupe(in)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.VulnID != "GHSA-ffhg-7mh4-33c4" || f.Severity != "HIGH" || f.Summary != "GitHub summary" {
		t.Errorf("kept %s (%s), want the GHSA record with its severity", f.VulnID, f.Severity)
	}
	if want := []string{"CVE-2020-9283", "GO-2020-0012"}; !reflect.DeepEqual(f.Aliases, want) {
		t.Errorf("aliases = %v, want %v", f.Aliases, want)
	}
}

func TestDedupe_LinksThroughASharedCVE(t *testing.T) {
	// Neither record names the other directly; they only share a CVE.
	in := []model.Finding{
		{Dep: crypto, VulnID: "GO-2021-0001", Aliases: []string{"CVE-2021-1"}, Severity: "UNKNOWN"},
		{Dep: crypto, VulnID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2021-1"}, Severity: "MODERATE"},
	}
	if got := dedupe(in); len(got) != 1 || got[0].VulnID != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("got %+v, want one GHSA finding", got)
	}
}

func TestDedupe_FillsMissingFixFromDuplicate(t *testing.T) {
	in := []model.Finding{
		{Dep: crypto, VulnID: "GHSA-x", Aliases: []string{"GO-1"}, Severity: "HIGH"},
		{Dep: crypto, VulnID: "GO-1", Severity: "UNKNOWN", FixedVersion: "0.31.0"},
	}
	if got := dedupe(in); got[0].FixedVersion != "0.31.0" {
		t.Errorf("FixedVersion = %q, want it filled from the GO record", got[0].FixedVersion)
	}
}

func TestDedupe_KeepsDistinctVulnerabilities(t *testing.T) {
	in := []model.Finding{
		{Dep: crypto, VulnID: "GHSA-one", Aliases: []string{"CVE-1"}, Severity: "HIGH"},
		{Dep: crypto, VulnID: "GHSA-two", Aliases: []string{"CVE-2"}, Severity: "LOW"},
		{Dep: crypto, VulnID: "GO-only", Severity: "UNKNOWN"}, // no GHSA twin: stays
	}
	if got := dedupe(in); len(got) != 3 {
		t.Fatalf("got %d findings, want 3 (nothing shared)", len(got))
	}
}

func TestDedupe_NeverMergesAcrossPackages(t *testing.T) {

	in := []model.Finding{
		{Dep: crypto, VulnID: "GHSA-shared", Severity: "HIGH"},
		{Dep: gin, VulnID: "GHSA-shared", Severity: "HIGH"},
	}
	if got := dedupe(in); len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (different packages)", len(got))
	}
}

func TestDedupe_ResultDoesNotDependOnInputOrder(t *testing.T) {
	a := model.Finding{Dep: crypto, VulnID: "GO-2020-0012", Aliases: []string{"GHSA-ffhg-7mh4-33c4"}, Severity: "UNKNOWN"}
	b := model.Finding{Dep: crypto, VulnID: "GHSA-ffhg-7mh4-33c4", Severity: "HIGH"}

	x, y := dedupe([]model.Finding{a, b}), dedupe([]model.Finding{b, a})
	if !reflect.DeepEqual(x, y) {
		t.Errorf("order changed the result:\n%+v\n%+v", x, y)
	}
}
