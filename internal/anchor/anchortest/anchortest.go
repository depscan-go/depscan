package anchortest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/report"
)

// Run checks the Anchorer contract on a fresh backend.
func Run(t *testing.T, a anchor.Anchorer) {
	t.Helper()
	ctx := context.Background()
	digest := report.Digest([]byte("a report"))
	other := report.Digest([]byte("a different report"))

	t.Run("anchor then verify", func(t *testing.T) {
		r, err := a.Anchor(ctx, digest)
		if err != nil {
			t.Fatalf("Anchor: %v", err)
		}
		if r.Digest != digest || r.Backend != a.Name() || r.AnchoredAt.IsZero() {
			t.Fatalf("receipt = %+v", r)
		}
		if err := a.Verify(ctx, r); err != nil {
			t.Fatalf("Verify of a fresh receipt: %v", err)
		}
	})

	t.Run("digest is normalized", func(t *testing.T) {
		bare := strings.ToUpper(strings.TrimPrefix(digest, report.DigestPrefix))
		r, err := a.Anchor(ctx, bare)
		if err != nil {
			t.Fatalf("Anchor: %v", err)
		}
		if r.Digest != digest {
			t.Errorf("receipt digest = %q, want canonical %q", r.Digest, digest)
		}
	})

	t.Run("tampered receipt fails", func(t *testing.T) {
		r, err := a.Anchor(ctx, digest)
		if err != nil {
			t.Fatalf("Anchor: %v", err)
		}
		r.Digest = other // someone swaps in a different report's digest
		if err := a.Verify(ctx, r); !errors.Is(err, anchor.ErrNotAnchored) {
			t.Errorf("Verify of a swapped digest = %v, want ErrNotAnchored", err)
		}
	})

	t.Run("malformed digest is rejected", func(t *testing.T) {
		if _, err := a.Anchor(ctx, "sha256:nothex"); !errors.Is(err, report.ErrBadDigest) {
			t.Errorf("Anchor(bad) = %v, want ErrBadDigest", err)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := a.Anchor(cctx, digest); err == nil {
			t.Error("Anchor with a cancelled context should fail")
		}
	})
}
