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

func TestParseSolanaKey(t *testing.T) {
	key := testKey(5)
	full := anchortest.Base58(key)                    // what Phantom exports
	seed := anchortest.Base58(key[:ed25519.SeedSize]) // 32-byte form
	arr := strings.TrimSpace(string(anchor.SolanaKeypairJSON(key)))
	for name, in := range map[string]string{"base58 keypair": full, "base58 seed": seed, "JSON array": arr, "padded": "  " + full + "\n"} {
		got, err := anchor.ParseSolanaKey(in)
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := append([]byte(nil), key...)
	bad[63] ^= 1
	for name, in := range map[string]string{"mismatched halves": anchortest.Base58(bad), "too short": anchortest.Base58(key[:20]), "not base58": "0OIl" + full, "bad JSON": "[1,2,"} {
		_, err := anchor.ParseSolanaKey(in)
		if err == nil {
			t.Errorf("%s: should fail", name)
			continue
		}
		if strings.Contains(err.Error(), full[:10]) {
			t.Errorf("%s: the error must not echo the key: %v", name, err)
		}
	}
}

func TestSolanaFromEnv_KeyFromSecret(t *testing.T) {
	_, srv := anchortest.NewSolanaNode(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DEPSCAN_SOLANA_RPC", srv.URL)
	t.Setenv("DEPSCAN_SOLANA_KEYPAIR", "")
	t.Setenv("DEPSCAN_SOLANA_KEY", anchortest.Base58(testKey(6)))
	s, err := anchor.SolanaFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if s.Address() != anchor.SolanaAddress(testKey(6)) {
		t.Errorf("address = %s", s.Address())
	}
	t.Setenv("DEPSCAN_SOLANA_KEYPAIR", "/some/file.json")
	if _, err := anchor.SolanaFromEnv(); err == nil {
		t.Error("setting both the key and a keypair file is ambiguous and must fail")
	}
}

func TestSolana_FindRebuildsALostReceipt(t *testing.T) {
	_, srv := anchortest.NewSolanaNode(t)
	s := newTestSolana(t, srv.URL, testKey(7))
	ctx := context.Background()
	want, err := s.Anchor(ctx, report.Digest([]byte("report A")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Anchor(ctx, report.Digest([]byte("report B"))); err != nil {
		t.Fatal(err)
	}

	// The receipt file is gone; the report and the server's address are enough.
	reader := newTestSolana(t, srv.URL, nil)
	got, proof, err := reader.Find(ctx, report.Digest([]byte("report A")), s.Address())
	if err != nil {
		t.Fatal(err)
	}
	if got.TxID != want.TxID || got.Signer != s.Address() || proof.Memo != anchor.MemoFor(want.Digest) || got.AnchoredAt.IsZero() {
		t.Errorf("found %+v, want tx %s", got, want.TxID)
	}
	if _, _, err := reader.Find(ctx, report.Digest([]byte("never anchored")), s.Address()); !errors.Is(err, anchor.ErrNotAnchored) {
		t.Errorf("unknown digest: %v", err)
	}
	if _, _, err := reader.Find(ctx, want.Digest, anchor.SolanaAddress(testKey(8))); !errors.Is(err, anchor.ErrNotAnchored) {
		t.Errorf("another signer's history: %v", err)
	}
}
