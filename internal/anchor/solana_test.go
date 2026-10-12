package anchor_test

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/anchor/anchortest"
	"github.com/depscan-go/depscan/internal/report"
)

func testKey(n byte) ed25519.PrivateKey {
	seed := make([]byte, 32)
	binary.BigEndian.PutUint32(seed, uint32(n)+7)
	return ed25519.NewKeyFromSeed(seed)
}

func newTestSolana(t *testing.T, url string, key ed25519.PrivateKey) *anchor.Solana {
	t.Helper()
	s, err := anchor.NewSolana(anchor.SolanaConfig{RPCURL: url, Network: "devnet", Key: key, Poll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSolana_Conformance(t *testing.T) {
	_, srv := anchortest.NewSolanaNode(t)
	anchortest.Run(t, newTestSolana(t, srv.URL, testKey(1)))
}

func TestSolana_ReceiptAndCrossCheck(t *testing.T) {
	fake, srv := anchortest.NewSolanaNode(t)
	s := newTestSolana(t, srv.URL, testKey(1))
	digest := report.Digest([]byte("shop-api report"))
	r, err := s.Anchor(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	if r.Backend != "solana" || r.Network != "devnet" || r.Signer != s.Address() || len(r.TxID) < 80 {
		t.Errorf("receipt = %+v", r)
	}
	if !strings.HasPrefix(r.URL, "https://explorer.solana.com/tx/"+r.TxID) || !strings.HasSuffix(r.URL, "?cluster=devnet") {
		t.Errorf("explorer URL = %s", r.URL)
	}
	if r.AnchoredAt.Unix() != 1760000000+1001 {
		t.Errorf("anchored_at should be the block time, got %s", r.AnchoredAt)
	}
	if got, _ := fake.Tx(r.TxID); got.Memo != "depscan:v1:"+digest || got.Program != anchor.MemoProgramID {
		t.Errorf("ledger holds %+v", got)
	}

	// A later run, on another machine, with no keypair at all, can verify it.
	reader := newTestSolana(t, srv.URL, nil)
	p, err := reader.Lookup(context.Background(), r)
	if err != nil {
		t.Fatalf("verify-only Lookup: %v", err)
	}
	if p.Signer != s.Address() || p.BlockTime.IsZero() || p.Memo != anchor.MemoFor(digest) {
		t.Errorf("proof = %+v", p)
	}
}

func TestSolana_VerifyRejectsForgedReceipts(t *testing.T) {
	_, srv := anchortest.NewSolanaNode(t)
	s := newTestSolana(t, srv.URL, testKey(1))
	r, err := s.Anchor(context.Background(), report.Digest([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	wrongSigner := r
	wrongSigner.Signer = newTestSolana(t, srv.URL, testKey(2)).Address()
	if err := s.Verify(ctx, wrongSigner); !errors.Is(err, anchor.ErrNotAnchored) {
		t.Errorf("receipt naming another signer: %v, want ErrNotAnchored", err)
	}

	unknownTx := r
	other, _ := s.Anchor(ctx, report.Digest([]byte("y")))
	unknownTx.TxID = strings.Repeat("1", 20) + other.TxID[20:]
	if err := s.Verify(ctx, unknownTx); err == nil {
		t.Error("a transaction ID that is not on the ledger must not verify")
	}

	if err := s.Verify(ctx, anchor.Receipt{Backend: "solana", Digest: r.Digest, TxID: "nope"}); err == nil || !strings.Contains(err.Error(), "transaction ID") {
		t.Errorf("malformed tx id: %v", err)
	}

	mainnet := r
	mainnet.Network = "mainnet-beta"
	if err := s.Verify(ctx, mainnet); err == nil || !strings.Contains(err.Error(), "DEPSCAN_SOLANA_RPC") {
		t.Errorf("network mismatch should say how to fix it: %v", err)
	}
}

func TestSolana_FailedTransactionIsNotAnAnchor(t *testing.T) {
	fake, srv := anchortest.NewSolanaNode(t)
	fake.FailTx = true
	s := newTestSolana(t, srv.URL, testKey(1))
	_, err := s.Anchor(context.Background(), report.Digest([]byte("x")))
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Errorf("Anchor of a failing transaction = %v", err)
	}
}

func TestSolana_UnfundedWalletSaysWhatToDo(t *testing.T) {
	fake, srv := anchortest.NewSolanaNode(t)
	fake.Unfunded = true
	s := newTestSolana(t, srv.URL, testKey(3))
	_, err := s.Anchor(context.Background(), report.Digest([]byte("x")))
	if err == nil || !strings.Contains(err.Error(), "faucet.solana.com") || !strings.Contains(err.Error(), s.Address()) {
		t.Errorf("err = %v", err)
	}
}

func TestSolana_NoKeypairCanVerifyButNotAnchor(t *testing.T) {
	_, srv := anchortest.NewSolanaNode(t)
	s := newTestSolana(t, srv.URL, nil)
	_, err := s.Anchor(context.Background(), report.Digest([]byte("x")))
	if err == nil || !strings.Contains(err.Error(), "depscan keygen") {
		t.Errorf("err = %v", err)
	}
}

func TestSolana_WaitsUntilConfirmedOrCancelled(t *testing.T) {
	_, srv := anchortest.NewSolanaNode(t)
	s := newTestSolana(t, srv.URL, testKey(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Anchor(ctx, report.Digest([]byte("x"))); err == nil {
		t.Error("a cancelled context must stop anchoring")
	}
}

func TestLoadSolanaKeypair(t *testing.T) {
	dir := t.TempDir()
	key := testKey(4)
	good := filepath.Join(dir, "id.json")
	if err := os.WriteFile(good, anchor.SolanaKeypairJSON(key), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := anchor.LoadSolanaKeypair(good)
	if err != nil || !got.Equal(key) {
		t.Fatalf("round trip: %v", err)
	}

	tampered := anchor.SolanaKeypairJSON(key)
	var nums []int
	_ = json.Unmarshal(tampered, &nums)
	nums[63] ^= 1
	bad, _ := json.Marshal(nums)
	badPath := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(badPath, bad, 0o600)
	if _, err := anchor.LoadSolanaKeypair(badPath); err == nil {
		t.Error("a keypair whose public half does not match must be rejected")
	}
	_ = os.WriteFile(badPath, []byte(`{"not":"a keypair"}`), 0o600)
	if _, err := anchor.LoadSolanaKeypair(badPath); err == nil {
		t.Error("JSON that is not a 64-number array must be rejected")
	}
}

func TestSolanaFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("DEPSCAN_SOLANA_KEYPAIR", "")
	t.Setenv("DEPSCAN_SOLANA_RPC", "testnet")
	s, err := anchor.SolanaFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if s.Network() != "testnet" || s.Address() != "" {
		t.Errorf("network %s, address %q: no keypair file exists, so verify-only", s.Network(), s.Address())
	}

	t.Setenv("DEPSCAN_SOLANA_KEYPAIR", filepath.Join(dir, "missing.json"))
	if _, err := anchor.SolanaFromEnv(); err == nil {
		t.Error("an explicitly named keypair that does not exist is an error")
	}

	t.Setenv("DEPSCAN_SOLANA_KEYPAIR", "")
	t.Setenv("DEPSCAN_SOLANA_RPC", "")
	a, err := anchor.ForReceipt(anchor.Receipt{Backend: "solana", Network: "mainnet-beta"})
	if err != nil || a.(*anchor.Solana).Network() != "mainnet-beta" {
		t.Errorf("ForReceipt picks the receipt's network: %v", err)
	}
	if _, err := anchor.ForReceipt(anchor.Receipt{Backend: "solana", Network: "custom"}); err == nil {
		t.Error("a custom network needs DEPSCAN_SOLANA_RPC")
	}
}
