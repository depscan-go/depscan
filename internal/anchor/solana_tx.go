package anchor

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
)

// This file holds the small part of Solana's wire format depscan needs: one
// legacy transaction, paid and signed by one key, with one Memo instruction.
// Reference: https://solana.com/docs/core/transactions

// MemoProgramID is the SPL Memo program (v2). It records UTF-8 text in a
// transaction and does nothing else, which is exactly what anchoring needs.
const MemoProgramID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

// memoPrefix versions what depscan writes, so a reader of the ledger can tell
// these memos apart from any other and a future format can coexist.
const memoPrefix = "depscan:v1:"

// MemoFor returns the memo text depscan anchors for a canonical digest.
func MemoFor(digest string) string { return memoPrefix + digest }

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var errBase58 = errors.New("invalid base58")

func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(b)
	radix, mod := big.NewInt(58), new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errBase58
	}
	n, radix := new(big.Int), big.NewInt(58)
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	for i := 0; i < len(s); i++ {
		d := indexByte(b58Alphabet, s[i])
		if d < 0 {
			return nil, fmt.Errorf("%w: unexpected %q", errBase58, s[i])
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(d)))
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}

// decode32 decodes a base58 public key or blockhash, which is always 32 bytes.
func decode32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base58Decode(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%w: %q is %d bytes, want 32", errBase58, s, len(b))
	}
	copy(out[:], b)
	return out, nil
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// compactU16 is Solana's "shortvec" length prefix: 7 bits per byte, low
// bits first, high bit set when another byte follows.
func compactU16(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// memoMessage builds the message the payer signs: two accounts (the payer,
// a writable signer that pays the fee, and the read-only Memo program), the
// recent blockhash, and one instruction carrying the memo text.
func memoMessage(payer ed25519.PublicKey, blockhash [32]byte, memo string) ([]byte, error) {
	if len(payer) != ed25519.PublicKeySize {
		return nil, errors.New("payer key must be 32 bytes")
	}
	program, err := decode32(MemoProgramID)
	if err != nil {
		return nil, err
	}
	m := []byte{
		1, // signatures required: the payer
		0, // read-only signed accounts
		1, // read-only unsigned accounts: the Memo program
	}
	m = append(m, compactU16(2)...)
	m = append(m, payer...)
	m = append(m, program[:]...)
	m = append(m, blockhash[:]...)
	m = append(m, compactU16(1)...) // one instruction
	m = append(m, 1)                // program: account index 1
	m = append(m, compactU16(0)...) // no accounts passed to the memo
	m = append(m, compactU16(len(memo))...)
	m = append(m, memo...)
	return m, nil
}

// signedMemoTx returns the serialized transaction and its signature, which
// is also the transaction's ID once encoded in base58.
func signedMemoTx(key ed25519.PrivateKey, blockhash [32]byte, memo string) (tx []byte, sig []byte, err error) {
	msg, err := memoMessage(key.Public().(ed25519.PublicKey), blockhash, memo)
	if err != nil {
		return nil, nil, err
	}
	sig = ed25519.Sign(key, msg)
	tx = append(compactU16(1), sig...)
	tx = append(tx, msg...)
	return tx, sig, nil
}
