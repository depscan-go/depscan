package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/anchor/anchortest"
	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/report"
)

func outcome() github.Outcome {
	dep := model.Dependency{Ecosystem: "Go", Name: "golang.org/x/net", Version: "0.10.0"}
	return github.Outcome{
		Job:       github.Job{Repo: "acme/shop", PR: 3, HeadSHA: strings.Repeat("a", 40)},
		Result:    &model.ScanResult{Deps: []model.Dependency{dep}},
		StartedAt: time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC),
	}
}

type flaky struct {
	fails []error
	calls int
}

func (f *flaky) Anchor(_ context.Context, digest string) (anchor.Receipt, error) {
	f.calls++
	if f.calls <= len(f.fails) {
		return anchor.Receipt{}, f.fails[f.calls-1]
	}
	return anchor.Receipt{Digest: digest, Backend: "solana", TxID: "tx"}, nil
}

func fastRetries(t *testing.T) {
	old := anchorRetries
	anchorRetries = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { anchorRetries = old })
}

func TestAnchorScan_OnTheLedger(t *testing.T) {
	isolate(t)
	node, srv := anchortest.NewSolanaNode(t)
	t.Setenv("DEPSCAN_ANCHOR", "solana")
	t.Setenv("DEPSCAN_SOLANA_RPC", srv.URL)
	t.Setenv("DEPSCAN_SOLANA_KEY", anchortest.Base58(make([]byte, 32)))
	a, err := newServerAnchorer()
	if err != nil || a == nil {
		t.Fatalf("newServerAnchorer: %v", err)
	}

	data, info, err := anchorScan(context.Background(), a, &policy.Policy{}, outcome())
	if err != nil {
		t.Fatal(err)
	}
	if info.Digest != report.Digest(data) || info.Anchor == nil || info.Anchor.Digest != info.Digest {
		t.Fatalf("info = %+v", info)
	}
	if tx, ok := node.Tx(info.Anchor.TxID); !ok || tx.Memo != anchor.MemoFor(info.Digest) {
		t.Errorf("ledger holds %+v", tx)
	}
	note := anchorNote(info)
	if note.TxID != info.Anchor.TxID || note.Signer != a.Address() || note.Err != "" {
		t.Errorf("note = %+v", note)
	}
	if !strings.Contains(string(data), `"acme/shop"`) || !strings.Contains(string(data), strings.Repeat("a", 40)) {
		t.Error("the report should name the repository and commit")
	}
}

func TestAnchorScan_RetriesThenSucceeds(t *testing.T) {
	fastRetries(t)
	f := &flaky{fails: []error{errors.New("blockhash expired"), errors.New("503")}}
	_, info, err := anchorScan(context.Background(), f, &policy.Policy{}, outcome())
	if err != nil || f.calls != 3 || info.Anchor == nil {
		t.Errorf("err %v after %d calls, %+v", err, f.calls, info)
	}
}

func TestAnchorScan_EmptyWalletIsNotRetried(t *testing.T) {
	fastRetries(t)
	f := &flaky{fails: []error{anchor.ErrUnfunded, anchor.ErrUnfunded, anchor.ErrUnfunded}}
	data, info, err := anchorScan(context.Background(), f, &policy.Policy{}, outcome())
	if !errors.Is(err, anchor.ErrUnfunded) || f.calls != 1 {
		t.Errorf("err %v after %d calls", err, f.calls)
	}
	if data == nil || info.AnchorError == "" || anchorNote(info).Err == "" {
		t.Error("the report is still kept, and the comment says why it was not anchored")
	}
}

func TestNewServerAnchorer(t *testing.T) {
	isolate(t)
	if a, err := newServerAnchorer(); a != nil || err != nil {
		t.Errorf("off by default: %v, %v", a, err)
	}
	t.Setenv("DEPSCAN_ANCHOR", "solana")
	if _, err := newServerAnchorer(); err == nil || !strings.Contains(err.Error(), "DEPSCAN_SOLANA_KEY") {
		t.Errorf("solana without a key: %v", err)
	}
	t.Setenv("DEPSCAN_ANCHOR", "ethereum")
	if _, err := newServerAnchorer(); err == nil {
		t.Error("an unknown backend must be an error")
	}
}

func isolate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	for _, k := range []string{"DEPSCAN_ANCHOR", "DEPSCAN_SOLANA_KEY", "DEPSCAN_SOLANA_KEYPAIR", "DEPSCAN_SOLANA_RPC"} {
		t.Setenv(k, "")
	}
}
