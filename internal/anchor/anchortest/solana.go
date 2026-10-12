package anchortest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// SolanaNode is a tiny Solana JSON-RPC node for tests. It decodes every
// transaction it is sent with its own parser, checks the signature, and keeps
// the memo, so tests exercise the real wire format rather than a mock.
type SolanaNode struct {
	mu        sync.Mutex
	blockhash [32]byte
	slot      uint64
	txs       map[string]LedgerTx // by base58 signature
	polls     map[string]int
	// Unfunded makes sendTransaction fail the way it does for an empty wallet.
	Unfunded bool
	// FailTx makes transactions land but fail, like a bad instruction would.
	FailTx bool
	sends  int
}

// LedgerTx is a transaction the node accepted.
type LedgerTx struct {
	Payer, Memo, Program string
	Slot                 uint64
	Failed               bool
}

// NewSolanaNode starts a node; it stops when the test ends.
func NewSolanaNode(t *testing.T) (*SolanaNode, *httptest.Server) {
	t.Helper()
	f := &SolanaNode{slot: 1000, txs: map[string]LedgerTx{}, polls: map[string]int{}}
	for i := range f.blockhash {
		f.blockhash[i] = byte(200 - i)
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *SolanaNode) serve(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}
	fail := func(code int, msg string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": code, "message": msg}})
	}
	switch req.Method {
	case "getLatestBlockhash":
		reply(map[string]any{"context": map[string]any{"slot": f.slot}, "value": map[string]any{"blockhash": b58(f.blockhash[:]), "lastValidBlockHeight": 5000}})
	case "getBlockHeight":
		reply(4000)
	case "sendTransaction":
		var b64 string
		_ = json.Unmarshal(req.Params[0], &b64)
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			fail(-32602, "invalid base64")
			return
		}
		sig, tx, err := f.parse(raw)
		if err != nil {
			fail(-32602, "invalid transaction: "+err.Error())
			return
		}
		if f.Unfunded {
			fail(-32002, "Transaction simulation failed: Attempt to debit an account but found no record of a prior credit.")
			return
		}
		f.sends++
		f.slot++
		tx.Slot, tx.Failed = f.slot, f.FailTx
		f.txs[sig] = tx
		reply(sig)
	case "getSignatureStatuses":
		var sigs []string
		_ = json.Unmarshal(req.Params[0], &sigs)
		out := make([]any, len(sigs))
		for i, s := range sigs {
			tx, ok := f.txs[s]
			if !ok {
				continue
			}
			f.polls[s]++
			status := "processed"
			if f.polls[s] > 1 {
				status = "confirmed"
			}
			var errVal any
			if tx.Failed {
				errVal = map[string]any{"InstructionError": []any{0, "InvalidInstructionData"}}
			}
			out[i] = map[string]any{"slot": tx.Slot, "confirmations": 0, "err": errVal, "confirmationStatus": status}
		}
		reply(map[string]any{"context": map[string]any{"slot": f.slot}, "value": out})
	case "getBlockTime":
		reply(1760000000 + int64(f.slot))
	case "getTransaction":
		var s string
		_ = json.Unmarshal(req.Params[0], &s)
		tx, ok := f.txs[s]
		if !ok {
			reply(nil)
			return
		}
		var errVal any
		if tx.Failed {
			errVal = map[string]any{"InstructionError": []any{0, "InvalidInstructionData"}}
		}
		reply(map[string]any{
			"slot":      tx.Slot,
			"blockTime": 1760000000 + int64(tx.Slot),
			"meta":      map[string]any{"err": errVal, "fee": 5000},
			"transaction": map[string]any{
				"signatures": []string{s},
				"message": map[string]any{
					"accountKeys":  []string{tx.Payer, tx.Program},
					"instructions": []any{map[string]any{"programIdIndex": 1, "accounts": []int{}, "data": b58([]byte(tx.Memo))}},
				},
			},
		})
	default:
		fail(-32601, "Method not found")
	}
}

// parse decodes a legacy transaction the way a validator does and checks
// the payer's signature over the message.
func (f *SolanaNode) parse(raw []byte) (string, LedgerTx, error) {
	rd := &reader{b: raw}
	if n := rd.compact(); n != 1 {
		return "", LedgerTx{}, errors.New("want exactly one signature")
	}
	sig := rd.take(64)
	msg := rd.b[rd.i:]
	header := rd.take(3)
	nkeys := rd.compact()
	keys := make([][]byte, nkeys)
	for i := range keys {
		keys[i] = rd.take(32)
	}
	bh := rd.take(32)
	if rd.err != nil || header[0] != 1 || nkeys != 2 {
		return "", LedgerTx{}, errors.New("bad message header")
	}
	if string(bh) != string(f.blockhash[:]) {
		return "", LedgerTx{}, errors.New("unknown blockhash")
	}
	if rd.compact() != 1 {
		return "", LedgerTx{}, errors.New("want one instruction")
	}
	prog := int(rd.take(1)[0])
	accounts := rd.compact()
	rd.take(accounts)
	data := rd.take(rd.compact())
	if rd.err != nil || rd.i != len(raw) {
		return "", LedgerTx{}, errors.New("trailing or missing bytes")
	}
	if !ed25519.Verify(keys[0], msg, sig) {
		return "", LedgerTx{}, errors.New("signature does not verify")
	}
	return b58(sig), LedgerTx{Payer: b58(keys[0]), Program: b58(keys[prog]), Memo: string(data)}, nil
}

type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || r.i+n > len(r.b) {
		r.err = errors.New("short")
		return make([]byte, n)
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out
}

func (r *reader) compact() int {
	n, shift := 0, 0
	for {
		b := r.take(1)[0]
		n |= int(b&0x7f) << shift
		if b&0x80 == 0 || r.err != nil {
			return n
		}
		shift += 7
	}
}

func b58(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int).SetBytes(b)
	var out []byte
	for n.Sign() > 0 {
		m := new(big.Int)
		n.DivMod(n, big.NewInt(58), m)
		out = append([]byte{alphabet[m.Int64()]}, out...)
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append([]byte{'1'}, out...)
	}
	return string(out)
}

// Tx returns what the ledger holds for a transaction signature.
func (f *SolanaNode) Tx(sig string) (LedgerTx, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	tx, ok := f.txs[sig]
	return tx, ok
}
