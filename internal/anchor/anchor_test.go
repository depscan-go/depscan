package anchor_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/anchor/anchortest"
	"github.com/depscan-go/depscan/internal/report"
)

func TestNoop_Conformance(t *testing.T) {
	anchortest.Run(t, anchor.NewNoop())
}

func TestNoop_OnlyVerifiesItsOwnReceipts(t *testing.T) {
	r, err := anchor.NewNoop().Anchor(context.Background(), report.Digest([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	// A different instance (say, a later CLI run) never saw this digest.
	if err := anchor.NewNoop().Verify(context.Background(), r); !errors.Is(err, anchor.ErrNotAnchored) {
		t.Errorf("Verify on a fresh noop = %v, want ErrNotAnchored", err)
	}
}

func TestNoop_RejectsOtherBackendsReceipts(t *testing.T) {
	n := anchor.NewNoop()
	r, _ := n.Anchor(context.Background(), report.Digest([]byte("x")))
	r.Backend = "solana"
	if err := n.Verify(context.Background(), r); err == nil {
		t.Error("noop must not vouch for a solana receipt")
	}
}

func TestNew(t *testing.T) {
	if a, err := anchor.New("noop"); err != nil || a.Name() != "noop" {
		t.Errorf("New(noop) = %v, %v", a, err)
	}
	if _, err := anchor.New("ethereum"); !errors.Is(err, anchor.ErrUnknownBackend) {
		t.Errorf("New(ethereum) = %v, want ErrUnknownBackend", err)
	}
}

func TestReceipt_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.anchor.json")
	want := anchor.Receipt{
		Digest:     report.Digest([]byte("x")),
		Backend:    "solana",
		Network:    "devnet",
		TxID:       "5h3...sig",
		URL:        "https://explorer.solana.com/tx/5h3...sig?cluster=devnet",
		AnchoredAt: time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC),
	}
	if err := anchor.WriteReceipt(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := anchor.ReadReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}
