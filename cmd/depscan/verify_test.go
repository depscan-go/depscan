package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/anchor/anchortest"
	"github.com/depscan-go/depscan/internal/report"
)

// writeReport puts a report and its .sha256 file in a temp folder, the way
// `depscan -report` does.
func writeTestReport(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.cdx.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", []byte(report.ChecksumLine([]byte(body), path)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func verify(t *testing.T, args ...string) (int, string, verifyResult) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runVerify(append([]string{"-json"}, args...), &out, &errb)
	var res verifyResult
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatalf("bad JSON %q: %v", out.String(), err)
		}
	}
	return code, out.String() + errb.String(), res
}

// isolate keeps the developer's own Solana keypair and settings out of the test.
func isolate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("DEPSCAN_SOLANA_KEYPAIR", "")
	t.Setenv("DEPSCAN_SOLANA_KEY", "")
	t.Setenv("DEPSCAN_SOLANA_RPC", "")
}

func TestVerify_ChecksumOnly(t *testing.T) {
	isolate(t)
	path := writeTestReport(t, `{"bomFormat":"CycloneDX"}`)
	code, out, res := verify(t, path)
	if code != exitClean || !res.Verified || res.Checksum != checkOK || res.Anchor != checkMissing {
		t.Fatalf("code %d, %+v\n%s", code, res, out)
	}
}

func TestVerify_EditedReportFails(t *testing.T) {
	isolate(t)
	path := writeTestReport(t, `{"result":"fail"}`)
	if err := os.WriteFile(path, []byte(`{"result":"pass"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, res := verify(t, path)
	if code != exitViolation || res.Verified || res.Checksum != checkMismatch {
		t.Errorf("code %d, %+v", code, res)
	}
}

func TestVerify_NothingToCheckAgainst(t *testing.T) {
	isolate(t)
	path := writeTestReport(t, "x")
	_ = os.Remove(path + ".sha256")
	code, _, res := verify(t, path)
	if code != exitToolError || res.Verified {
		t.Errorf("a report with no checksum and no anchor cannot be verified: code %d, %+v", code, res)
	}
	if code, _, _ := verify(t, filepath.Join(t.TempDir(), "missing.json")); code != exitToolError {
		t.Errorf("a missing report should exit 2, got %d", code)
	}
}

func TestVerify_ReceiptForAnotherReport(t *testing.T) {
	isolate(t)
	path := writeTestReport(t, "this report")
	r := anchor.Receipt{Digest: report.Digest([]byte("another report")), Backend: "noop", AnchoredAt: time.Now()}
	if err := anchor.WriteReceipt(path+".anchor.json", r); err != nil {
		t.Fatal(err)
	}
	code, _, res := verify(t, path)
	if code != exitViolation || res.Anchor != checkMismatch {
		t.Errorf("code %d, %+v", code, res)
	}
}

func TestVerify_NoopReceiptIsSkippedNotTrusted(t *testing.T) {
	isolate(t)
	path := writeTestReport(t, "r")
	r, _ := anchor.NewNoop().Anchor(context.Background(), report.Digest([]byte("r")))
	_ = anchor.WriteReceipt(path+".anchor.json", r)
	code, _, res := verify(t, path)
	if code != exitClean || res.Anchor != checkSkipped || !strings.Contains(res.Detail, "noop") {
		t.Errorf("code %d, %+v", code, res)
	}
}

func TestVerify_SolanaAnchorOnTheLedger(t *testing.T) {
	isolate(t)
	node, srv := anchortest.NewSolanaNode(t)
	seed := bytes.Repeat([]byte{9}, 32)
	sol, err := anchor.NewSolana(anchor.SolanaConfig{RPCURL: srv.URL, Network: "devnet", Key: ed25519.NewKeyFromSeed(seed), Poll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"bomFormat":"CycloneDX","result":"fail"}`
	path := writeTestReport(t, body)
	r, err := sol.Anchor(context.Background(), report.Digest([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.WriteReceipt(path+".anchor.json", r); err != nil {
		t.Fatal(err)
	}
	if _, ok := node.Tx(r.TxID); !ok {
		t.Fatal("the node has no such transaction")
	}

	// Verifying needs no keypair, only the RPC.
	t.Setenv("DEPSCAN_SOLANA_RPC", srv.URL)
	code, out, res := verify(t, path)
	if code != exitClean || res.Anchor != checkOK || res.Signer != sol.Address() || res.AnchoredAt == "" {
		t.Fatalf("code %d, %+v\n%s", code, res, out)
	}

	// The same receipt next to an edited report fails before any RPC call.
	_ = os.WriteFile(path, []byte(strings.Replace(body, "fail", "pass", 1)), 0o600)
	if code, _, res := verify(t, path); code != exitViolation || res.Anchor != checkMismatch {
		t.Errorf("edited report: code %d, %+v", code, res)
	}

	// A forged receipt, rewritten for the edited report, is caught by the ledger.
	forged := r
	forged.Digest = report.Digest([]byte(strings.Replace(body, "fail", "pass", 1)))
	_ = anchor.WriteReceipt(path+".anchor.json", forged)
	_ = os.WriteFile(path+".sha256", []byte(report.ChecksumLine([]byte(strings.Replace(body, "fail", "pass", 1)), path)), 0o600)
	code, _, res = verify(t, path)
	if code != exitViolation || res.Anchor != checkMismatch || !strings.Contains(res.Detail, "ledger memo") {
		t.Errorf("forged receipt: code %d, %+v", code, res)
	}

	// -offline does not ask the ledger, so it cannot vouch for the anchor.
	code, _, res = verify(t, "-offline", path)
	if code != exitClean || res.Anchor != checkSkipped {
		t.Errorf("offline: code %d, %+v", code, res)
	}
}

func TestVerify_UnreachableLedgerIsNotAFailure(t *testing.T) {
	isolate(t)
	body := "r"
	path := writeTestReport(t, body)
	r := anchor.Receipt{Digest: report.Digest([]byte(body)), Backend: "solana", Network: "devnet", TxID: strings.Repeat("2", 87), AnchoredAt: time.Now()}
	_ = anchor.WriteReceipt(path+".anchor.json", r)
	t.Setenv("DEPSCAN_SOLANA_RPC", "http://127.0.0.1:1") // nothing listens here
	code, _, res := verify(t, "-timeout", "3s", path)
	if code != exitToolError || res.Verified || !strings.Contains(res.Detail, "could not ask the ledger") {
		t.Errorf("code %d, %+v", code, res)
	}
}

func TestVerify_HumanOutput(t *testing.T) {
	isolate(t)
	path := writeTestReport(t, "r")
	var out bytes.Buffer
	if code := runVerify([]string{path}, &out, &out); code != exitClean {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "VERIFIED") || !strings.Contains(out.String(), "not that the project is still safe") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestKeygen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "id.json")
	var out bytes.Buffer
	if code := runKeygen([]string{"-out", path}, &out, &out); code != exitClean {
		t.Fatalf("code %d\n%s", code, out.String())
	}
	key, err := anchor.LoadSolanaKeypair(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), anchor.SolanaAddress(key)) || !strings.Contains(out.String(), "faucet.solana.com") {
		t.Errorf("output:\n%s", out.String())
	}
	if info, _ := os.Stat(path); info != nil && info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("keypair is readable by others: %v", info.Mode())
	}
	out.Reset()
	if code := runKeygen([]string{"-out", path}, &out, &out); code != exitToolError || !strings.Contains(out.String(), "never overwrites") {
		t.Errorf("second keygen must refuse: code %d\n%s", code, out.String())
	}
}

func TestVerify_RecoversALostReceiptFromTheLedger(t *testing.T) {
	isolate(t)
	_, srv := anchortest.NewSolanaNode(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	sol, err := anchor.NewSolana(anchor.SolanaConfig{RPCURL: srv.URL, Network: "devnet", Key: key, Poll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"bomFormat":"CycloneDX","serial":"x"}`
	path := writeTestReport(t, body)
	if _, err := sol.Anchor(context.Background(), report.Digest([]byte(body))); err != nil {
		t.Fatal(err)
	}
	// The server anchored it, but the receipt never reached disk.
	t.Setenv("DEPSCAN_SOLANA_RPC", srv.URL)
	code, out, res := verify(t, "-signer", sol.Address(), "-save", path)
	if code != exitClean || !res.Recovered || res.Anchor != checkOK || res.TxID == "" {
		t.Fatalf("code %d, %+v\n%s", code, res, out)
	}
	saved, err := anchor.ReadReceipt(path + ".anchor.json")
	if err != nil || saved.TxID != res.TxID {
		t.Fatalf("-save should write the receipt: %v", err)
	}
	// From now on the saved receipt is used, without -signer.
	if code, _, res := verify(t, path); code != exitClean || res.Recovered || res.Anchor != checkOK {
		t.Errorf("with the saved receipt: code %d, %+v", code, res)
	}

	other := writeTestReport(t, "a report nobody anchored")
	if code, _, res := verify(t, "-signer", sol.Address(), other); code != exitViolation || res.Anchor != checkMismatch {
		t.Errorf("unanchored report: code %d, %+v", code, res)
	}
}
