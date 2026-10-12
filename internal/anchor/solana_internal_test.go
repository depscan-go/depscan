package anchor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/depscan-go/depscan/internal/report"
)

// The expected values below were produced by the official Solana JavaScript
// SDK (@solana/web3.js 1.98.0) from the same seed, blockhash and memo:
//
//	kp := Keypair.fromSeed([1..32]); blockhash := bytes (i*7+3)&255
//	new Transaction({feePayer, recentBlockhash}).add(new TransactionInstruction({
//	  keys: [], programId: MEMO, data: Buffer.from(memo) })).sign(kp).serialize()
//
// Matching them byte for byte shows depscan builds and signs transactions
// exactly as Solana expects.
const (
	refAddress   = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj"
	refBlockhash = "Cs8KY3PiWrCMAytMsBRQo8EdGbticVtdvufLnb2UhXh"
	refSignature = "4TVYKb4ETAMb7CYfYLa2SaGgH5MqbWBKHPWmE5rPm9EpwFLuqGNDT7osQWtLkRuU62SFnCBewJShZtoccfj1qiGZ"
	refTx        = "AazlkWdkz3Mhk0Ao8AUYi4XVNvDywO5I/n4MY0O3dCw4+ywzhN9DSPnyN2o9yDdVMtunYbEtDWAI0DoVlyaaygoBAAECebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQFSlNamSkhBk0k6HFg2jh8fDW13bySu4HkH6hAQQVEjQMKERgfJi00O0JJUFdeZWxzeoGIj5adpKuyucDHztXcAQEAUmRlcHNjYW46djE6c2hhMjU2OjkwYmQzNWRmNjBmMWUyN2QyMjM2MjQ1YTRhNDlmNzNlMWRmYjAxOTM2ZjJjMjE1OWM3MGEyYmRlOTNlYjI5Nzc="
)

func refKey() ed25519.PrivateKey {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestMemoTx_MatchesSolanaWeb3(t *testing.T) {
	key := refKey()
	if got := SolanaAddress(key); got != refAddress {
		t.Fatalf("address = %s, want %s", got, refAddress)
	}
	hash, err := decode32(refBlockhash)
	if err != nil {
		t.Fatal(err)
	}
	var want [32]byte
	for i := range want {
		want[i] = byte((i*7 + 3) & 255)
	}
	if hash != want {
		t.Fatalf("blockhash decoded to %x", hash)
	}
	memo := MemoFor(report.Digest([]byte("a report")))
	tx, sig, err := signedMemoTx(key, hash, memo)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(tx); got != refTx {
		t.Errorf("transaction differs from @solana/web3.js:\n got %s\nwant %s", got, refTx)
	}
	if got := base58Encode(sig); got != refSignature {
		t.Errorf("signature = %s, want %s", got, refSignature)
	}
}

func TestBase58(t *testing.T) {
	for _, tc := range []struct {
		in  []byte
		out string
	}{
		{nil, ""},
		{[]byte{0}, "1"},
		{[]byte{0, 0, 1}, "112"},
		{[]byte("hello world"), "StV1DL6CwTryKyV"},
		{make([]byte, 32), "11111111111111111111111111111111"}, // the System Program's address
	} {
		if got := base58Encode(tc.in); got != tc.out {
			t.Errorf("encode(%x) = %q, want %q", tc.in, got, tc.out)
		}
		if tc.out == "" {
			continue
		}
		back, err := base58Decode(tc.out)
		if err != nil || !bytes.Equal(back, tc.in) {
			t.Errorf("decode(%q) = %x, %v", tc.out, back, err)
		}
	}
	for _, bad := range []string{"", "0OIl", "abc!"} {
		if _, err := base58Decode(bad); err == nil {
			t.Errorf("decode(%q) should fail", bad)
		}
	}
	if _, err := decode32("2"); err == nil {
		t.Error("a 1-byte value is not a public key")
	}
}

func TestCompactU16(t *testing.T) {
	for n, want := range map[int][]byte{0: {0}, 1: {1}, 127: {0x7f}, 128: {0x80, 0x01}, 300: {0xac, 0x02}, 16383: {0xff, 0x7f}, 16384: {0x80, 0x80, 0x01}} {
		if got := compactU16(n); !bytes.Equal(got, want) {
			t.Errorf("compactU16(%d) = %x, want %x", n, got, want)
		}
	}
}

func TestNetworkOf(t *testing.T) {
	for url, want := range map[string]string{
		"https://api.devnet.solana.com":         "devnet",
		"https://api.devnet.solana.com/":        "devnet",
		"https://api.mainnet-beta.solana.com":   "mainnet-beta",
		"https://devnet.helius-rpc.com/?key=x":  "devnet",
		"http://127.0.0.1:8899":                 "custom",
		"https://solana-mainnet.g.alchemy.com/": "mainnet-beta",
	} {
		if got := networkOf(url); got != want {
			t.Errorf("networkOf(%s) = %s, want %s", url, got, want)
		}
	}
}
