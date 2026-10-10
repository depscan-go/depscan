package report_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/report"
)

const abcHex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestDigest_KnownAnswer(t *testing.T) {
	if got := report.Digest([]byte("abc")); got != "sha256:"+abcHex {
		t.Errorf("Digest(abc) = %s", got)
	}
}

func TestVerify(t *testing.T) {
	data := []byte("abc")

	ok := []string{
		"sha256:" + abcHex,
		abcHex,
		"SHA256:" + strings.ToUpper(abcHex),
		"  sha256:" + abcHex + "\n",
	}
	for _, d := range ok {
		if err := report.Verify(data, d); err != nil {
			t.Errorf("Verify(%q) = %v, want nil", d, err)
		}
	}

	if err := report.Verify([]byte("abd"), "sha256:"+abcHex); !errors.Is(err, report.ErrMismatch) {
		t.Errorf("one changed byte: got %v, want ErrMismatch", err)
	}

	bad := []string{"", "sha256:", "sha256:abc", "md5:" + abcHex, "sha256:" + strings.Repeat("z", 64)}
	for _, d := range bad {
		if err := report.Verify(data, d); !errors.Is(err, report.ErrBadDigest) {
			t.Errorf("Verify(%q) = %v, want ErrBadDigest", d, err)
		}
	}
}

func TestDigest_SameReportSameHash(t *testing.T) {
	a := encode(t, build(t, sampleResult()))
	b := encode(t, build(t, sampleResult()))
	if report.Digest(a) != report.Digest(b) {
		t.Fatal("identical inputs produced different report digests")
	}

	r := sampleResult()
	r.Warnings = r.Warnings[:1]
	if report.Digest(encode(t, build(t, r))) == report.Digest(a) {
		t.Fatal("a different result produced the same digest")
	}
}

func TestChecksumLine_MatchesSha256sumFormat(t *testing.T) {
	got := report.ChecksumLine([]byte("abc"), "bin/report.cdx.json")
	if want := abcHex + "  report.cdx.json\n"; got != want {
		t.Errorf("ChecksumLine = %q, want %q", got, want)
	}
}
