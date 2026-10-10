package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/policy"
)

// fakeVulns returns canned findings, or an error, without touching the network.
type fakeVulns struct {
	findings []model.Finding
	err      error
	got      []model.Dependency // what the engine passed in
}

func (f *fakeVulns) QueryBatch(_ context.Context, deps []model.Dependency) ([]model.Finding, error) {
	f.got = append([]model.Dependency(nil), deps...)
	return f.findings, f.err
}

// fakeLicenses sets a license per package name and counts calls.
type fakeLicenses struct {
	byName map[string]string
	calls  int
}

func (f *fakeLicenses) Enrich(_ context.Context, deps []model.Dependency) []error {
	f.calls++
	for i := range deps {
		deps[i].License = f.byName[deps[i].Name]
	}
	return nil
}

// repoWithGoMod creates a temp repo containing one go.mod with two requirements.
func repoWithGoMod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gomod := "module example.com/app\n\ngo 1.22\n\nrequire (\n" +
		"\tgithub.com/good/lib v1.0.0\n" +
		"\tgithub.com/copyleft/lib v1.2.0 // indirect\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRun_LicensesAreFilledBeforeVulnsAndPolicy(t *testing.T) {
	vulns := &fakeVulns{}
	lics := &fakeLicenses{byName: map[string]string{
		"github.com/good/lib":     "MIT",
		"github.com/copyleft/lib": "GPL-3.0-only",
	}}
	e := &Engine{
		Vulns:    vulns,
		Licenses: lics,
		Policy:   &policy.Policy{DeniedLicenses: []string{"GPL-3.0-only"}},
	}

	res, err := e.Run(context.Background(), repoWithGoMod(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(res.Violations) != 1 || res.Violations[0].Kind != "license" || res.Violations[0].Dep.Name != "github.com/copyleft/lib" {
		t.Fatalf("want one license violation for copyleft/lib, got %+v", res.Violations)
	}
	// The vuln source must see the enriched dependencies too, so the result
	// and the stored report agree on every field.
	for _, d := range vulns.got {
		if d.License == "" {
			t.Errorf("vuln source saw %s without a license", d.Name)
		}
	}
}

func TestRun_SkipLicenseCheckDoesNotCallLicenseSource(t *testing.T) {
	lics := &fakeLicenses{}
	e := &Engine{
		Vulns:    &fakeVulns{},
		Licenses: lics,
		Policy:   &policy.Policy{SkipLicenseCheck: true},
	}

	if _, err := e.Run(context.Background(), repoWithGoMod(t)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if lics.calls != 0 {
		t.Errorf("license source called %d times, want 0", lics.calls)
	}
}

func TestRun_NilLicenseSourceIsAllowed(t *testing.T) {
	e := &Engine{Vulns: &fakeVulns{}, Policy: &policy.Policy{}}
	res, err := e.Run(context.Background(), repoWithGoMod(t))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Deps) != 2 {
		t.Errorf("got %d deps, want 2", len(res.Deps))
	}
}

func TestRun_VulnSourceErrorFailsTheScan(t *testing.T) {
	e := &Engine{
		Vulns:  &fakeVulns{err: errors.New("osv down")},
		Policy: &policy.Policy{},
	}
	if _, err := e.Run(context.Background(), repoWithGoMod(t)); err == nil {
		t.Fatal("want an error when the vulnerability source fails")
	}
}

func TestNew_SkipLicenseCheckLeavesLicenseSourceNil(t *testing.T) {
	if e := New(&policy.Policy{SkipLicenseCheck: true}); e.Licenses != nil {
		t.Error("Licenses should be nil when skip_license_check is set")
	}
	if e := New(&policy.Policy{}); e.Licenses == nil {
		t.Error("Licenses should be set by default")
	}
}
