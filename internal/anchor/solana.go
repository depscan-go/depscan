package anchor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/depscan-go/depscan/internal/httpx"
)

// Solana anchors a digest by writing it into the memo of a Solana
// transaction. The ledger then records when it arrived, and anyone can read
// it back later without trusting the depscan server.
//
// Anchoring needs a funded keypair; verifying only needs an RPC endpoint.
// Devnet is the default: its SOL is free, from a faucet.
type Solana struct {
	rpcURL  string
	network string
	key     ed25519.PrivateKey
	http    *http.Client
	retry   httpx.Policy
	poll    time.Duration
	now     func() time.Time
}

// SolanaConfig configures a Solana backend. Zero values mean devnet, no
// keypair (verify only) and sensible timings.
type SolanaConfig struct {
	RPCURL  string             // JSON-RPC endpoint; default https://api.devnet.solana.com
	Network string             // label kept in receipts; inferred from RPCURL when empty
	Key     ed25519.PrivateKey // payer and signer; nil allows Verify only
	HTTP    *http.Client
	Poll    time.Duration // how often to check for confirmation; default 500ms
}

// ErrUnfunded means the payer has no SOL for the fee. Retrying will not help
// until someone funds the wallet.
var ErrUnfunded = errors.New("no SOL to pay the transaction fee")

// Cluster RPC endpoints, by the network names receipts record.
var clusters = map[string]string{
	"devnet":       "https://api.devnet.solana.com",
	"testnet":      "https://api.testnet.solana.com",
	"mainnet-beta": "https://api.mainnet-beta.solana.com",
}

// DefaultSolanaKeypair is where the Solana CLI keeps its keypair.
func DefaultSolanaKeypair() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "solana", "id.json")
}

func NewSolana(cfg SolanaConfig) (*Solana, error) {
	if cfg.RPCURL == "" {
		cfg.RPCURL = clusters["devnet"]
	}
	u, err := url.Parse(cfg.RPCURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid Solana RPC URL %q", cfg.RPCURL)
	}
	if cfg.Network == "" {
		cfg.Network = networkOf(cfg.RPCURL)
	}
	if cfg.Key != nil && len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("solana: keypair must be 64 bytes")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 500 * time.Millisecond
	}
	return &Solana{rpcURL: cfg.RPCURL, network: cfg.Network, key: cfg.Key, http: cfg.HTTP, retry: httpx.Default, poll: cfg.Poll, now: time.Now}, nil
}

// SolanaFromEnv configures the backend from the environment:
//
//	DEPSCAN_SOLANA_RPC      JSON-RPC URL, or devnet, testnet, mainnet-beta (default devnet)
//	DEPSCAN_SOLANA_KEY      the secret key itself, base58 or a JSON array; for servers,
//	                        where it comes from a secret store
//	DEPSCAN_SOLANA_KEYPAIR  keypair file in Solana CLI format (default ~/.config/solana/id.json)
//
// A missing keypair is not an error here: verifying works without one, and
// Anchor explains how to create one.
func SolanaFromEnv() (*Solana, error) {
	return solanaFromEnv("")
}

func solanaFromEnv(network string) (*Solana, error) {
	rpc := strings.TrimSpace(os.Getenv("DEPSCAN_SOLANA_RPC"))
	if c, ok := clusters[rpc]; ok {
		rpc = c
	}
	if rpc == "" && network != "" {
		c, ok := clusters[network]
		if !ok {
			return nil, fmt.Errorf("solana: the receipt is from network %q; set DEPSCAN_SOLANA_RPC to its RPC URL", network)
		}
		rpc = c
	}
	cfg := SolanaConfig{RPCURL: rpc}
	path := strings.TrimSpace(os.Getenv("DEPSCAN_SOLANA_KEYPAIR"))
	explicit := path != ""
	if secret := strings.TrimSpace(os.Getenv("DEPSCAN_SOLANA_KEY")); secret != "" {
		if explicit {
			return nil, errors.New("solana: set DEPSCAN_SOLANA_KEY or DEPSCAN_SOLANA_KEYPAIR, not both")
		}
		key, err := ParseSolanaKey(secret)
		if err != nil {
			return nil, fmt.Errorf("DEPSCAN_SOLANA_KEY: %w", err)
		}
		cfg.Key = key
		return NewSolana(cfg)
	}
	if !explicit {
		path = DefaultSolanaKeypair()
	}
	if path != "" {
		key, err := LoadSolanaKeypair(path)
		switch {
		case err == nil:
			cfg.Key = key
		case explicit || !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	return NewSolana(cfg)
}

// LoadSolanaKeypair reads a keypair file written by `solana-keygen` or
// `depscan keygen`: a JSON array of 64 numbers, the secret seed followed by
// the public key.
func LoadSolanaKeypair(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading Solana keypair: %w", err)
	}
	var nums []int
	if err := json.Unmarshal(data, &nums); err != nil || len(nums) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s is not a Solana keypair file (want a JSON array of 64 numbers)", path)
	}
	raw := make([]byte, len(nums))
	for i, n := range nums {
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("%s is not a Solana keypair file (value %d out of range)", path, n)
		}
		raw[i] = byte(n)
	}
	key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if !bytes.Equal(key[ed25519.SeedSize:], raw[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("%s: the public key does not match the secret key", path)
	}
	return key, nil
}

// ParseSolanaKey reads a secret key given as text, in any of the forms
// wallets export it: base58 of the 64-byte keypair (Phantom, Solflare),
// base58 of the 32-byte seed, or the JSON array solana-keygen writes. The
// error never contains the key.
func ParseSolanaKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	var raw []byte
	if strings.HasPrefix(s, "[") {
		var nums []int
		if err := json.Unmarshal([]byte(s), &nums); err != nil {
			return nil, errors.New("not a JSON array of numbers")
		}
		raw = make([]byte, len(nums))
		for i, n := range nums {
			if n < 0 || n > 255 {
				return nil, errors.New("JSON array value out of range")
			}
			raw[i] = byte(n)
		}
	} else {
		b, err := base58Decode(s)
		if err != nil {
			return nil, errors.New("not base58 and not a JSON array")
		}
		raw = b
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(key[ed25519.SeedSize:], raw[ed25519.SeedSize:]) {
			return nil, errors.New("the public half does not match the secret half")
		}
		return key, nil
	}
	return nil, fmt.Errorf("a key is 32 or 64 bytes, this is %d", len(raw))
}

// SolanaKeypairJSON encodes a key in the Solana CLI file format.
func SolanaKeypairJSON(key ed25519.PrivateKey) []byte {
	nums := make([]int, len(key))
	for i, b := range key {
		nums[i] = int(b)
	}
	data, _ := json.Marshal(nums) // a slice of ints always encodes
	return append(data, '\n')
}

// SolanaAddress is the base58 address of a key, as wallets and explorers show it.
func SolanaAddress(key ed25519.PrivateKey) string {
	return base58Encode(key.Public().(ed25519.PublicKey))
}

func (s *Solana) Name() string { return "solana" }

// Network is the cluster name recorded in receipts, e.g. "devnet".
func (s *Solana) Network() string { return s.network }

// Address is the payer's address, or "" without a keypair.
func (s *Solana) Address() string {
	if s.key == nil {
		return ""
	}
	return SolanaAddress(s.key)
}

func (s *Solana) Anchor(ctx context.Context, digest string) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	d, err := normalize(digest)
	if err != nil {
		return Receipt{}, err
	}
	if s.key == nil {
		return Receipt{}, errors.New("solana: no keypair. Create one with `depscan keygen`, fund it on devnet at https://faucet.solana.com, or point DEPSCAN_SOLANA_KEYPAIR at an existing Solana CLI keypair")
	}

	var bh struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	if err := s.call(ctx, "getLatestBlockhash", []any{map[string]string{"commitment": "confirmed"}}, &bh); err != nil {
		return Receipt{}, err
	}
	hash, err := decode32(bh.Value.Blockhash)
	if err != nil {
		return Receipt{}, fmt.Errorf("solana: bad blockhash from RPC: %w", err)
	}
	tx, sigBytes, err := signedMemoTx(s.key, hash, MemoFor(d))
	if err != nil {
		return Receipt{}, err
	}
	sig := base58Encode(sigBytes)

	var sent string
	err = s.call(ctx, "sendTransaction", []any{base64.StdEncoding.EncodeToString(tx), map[string]any{"encoding": "base64", "preflightCommitment": "confirmed"}}, &sent)
	if err != nil {
		return Receipt{}, s.explainSend(err)
	}
	if sent != sig {
		return Receipt{}, fmt.Errorf("solana: RPC returned signature %s, expected %s", sent, sig)
	}

	slot, err := s.confirm(ctx, sig, bh.Value.LastValidBlockHeight)
	if err != nil {
		return Receipt{}, err
	}
	at := s.now().UTC()
	var bt *int64
	if s.call(ctx, "getBlockTime", []any{slot}, &bt) == nil && bt != nil {
		at = time.Unix(*bt, 0).UTC()
	}
	return Receipt{
		Digest:     d,
		Backend:    s.Name(),
		Network:    s.network,
		TxID:       sig,
		URL:        s.explorer(sig),
		Signer:     s.Address(),
		AnchoredAt: at.Truncate(time.Second),
	}, nil
}

// Balance returns the payer's balance in lamports (1 SOL = 1e9 lamports).
func (s *Solana) Balance(ctx context.Context) (uint64, error) {
	if s.key == nil {
		return 0, errors.New("solana: no keypair")
	}
	var out struct {
		Value uint64 `json:"value"`
	}
	err := s.call(ctx, "getBalance", []any{s.Address(), map[string]string{"commitment": "confirmed"}}, &out)
	return out.Value, err
}

// confirm waits until the transaction is confirmed, fails, or can no longer
// land because its blockhash expired. It returns the slot it landed in.
func (s *Solana) confirm(ctx context.Context, sig string, lastValid uint64) (uint64, error) {
	t := time.NewTicker(s.poll)
	defer t.Stop()
	for {
		var st struct {
			Value []*struct {
				Slot               uint64          `json:"slot"`
				Err                json.RawMessage `json:"err"`
				ConfirmationStatus string          `json:"confirmationStatus"`
			} `json:"value"`
		}
		if err := s.call(ctx, "getSignatureStatuses", []any{[]string{sig}, map[string]bool{"searchTransactionHistory": true}}, &st); err != nil {
			return 0, err
		}
		if len(st.Value) == 1 && st.Value[0] != nil {
			v := st.Value[0]
			if len(v.Err) > 0 && string(v.Err) != "null" {
				return 0, fmt.Errorf("solana: transaction %s failed: %s", sig, v.Err)
			}
			if v.ConfirmationStatus == "confirmed" || v.ConfirmationStatus == "finalized" {
				return v.Slot, nil
			}
		} else {
			var height uint64
			if err := s.call(ctx, "getBlockHeight", []any{map[string]string{"commitment": "confirmed"}}, &height); err == nil && height > lastValid {
				return 0, fmt.Errorf("solana: transaction %s expired before it was confirmed; run the command again", sig)
			}
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("solana: waiting for %s to be confirmed: %w", sig, ctx.Err())
		case <-t.C:
		}
	}
}

// Proof is what the ledger says about an anchor.
type Proof struct {
	Memo      string
	Signer    string
	Slot      uint64
	BlockTime time.Time // zero if the RPC does not know it
}

func (s *Solana) Verify(ctx context.Context, r Receipt) error {
	_, err := s.Lookup(ctx, r)
	return err
}

// Lookup reads the receipt's transaction from the ledger and checks that it
// succeeded, carries exactly this digest's memo, and was signed by the
// receipt's signer. A mismatch wraps ErrNotAnchored.
func (s *Solana) Lookup(ctx context.Context, r Receipt) (Proof, error) {
	if err := ctx.Err(); err != nil {
		return Proof{}, err
	}
	if r.Backend != s.Name() {
		return Proof{}, fmt.Errorf("receipt is from backend %q, not %q", r.Backend, s.Name())
	}
	if r.Network != "" && s.network != "custom" && r.Network != s.network {
		return Proof{}, fmt.Errorf("solana: the receipt is on %s but this RPC is %s; set DEPSCAN_SOLANA_RPC", r.Network, s.network)
	}
	d, err := normalize(r.Digest)
	if err != nil {
		return Proof{}, err
	}
	if sig, err := base58Decode(r.TxID); err != nil || len(sig) != ed25519.SignatureSize {
		return Proof{}, fmt.Errorf("solana: receipt has no valid transaction ID (%q)", r.TxID)
	}

	var tx *struct {
		Slot      uint64 `json:"slot"`
		BlockTime *int64 `json:"blockTime"`
		Meta      *struct {
			Err json.RawMessage `json:"err"`
		} `json:"meta"`
		Transaction struct {
			Message struct {
				AccountKeys  []string `json:"accountKeys"`
				Instructions []struct {
					ProgramIDIndex int    `json:"programIdIndex"`
					Data           string `json:"data"`
				} `json:"instructions"`
			} `json:"message"`
		} `json:"transaction"`
	}
	opts := map[string]any{"encoding": "json", "commitment": "confirmed", "maxSupportedTransactionVersion": 0}
	if err := s.call(ctx, "getTransaction", []any{r.TxID, opts}, &tx); err != nil {
		return Proof{}, err
	}
	if tx == nil {
		return Proof{}, fmt.Errorf("%w: transaction %s is not on %s", ErrNotAnchored, r.TxID, s.network)
	}
	if tx.Meta != nil && len(tx.Meta.Err) > 0 && string(tx.Meta.Err) != "null" {
		return Proof{}, fmt.Errorf("%w: transaction %s failed on chain: %s", ErrNotAnchored, r.TxID, tx.Meta.Err)
	}
	keys := tx.Transaction.Message.AccountKeys
	p := Proof{Slot: tx.Slot}
	if len(keys) > 0 {
		p.Signer = keys[0] // the fee payer signs first
	}
	if tx.BlockTime != nil {
		p.BlockTime = time.Unix(*tx.BlockTime, 0).UTC()
	}
	for _, in := range tx.Transaction.Message.Instructions {
		if in.ProgramIDIndex < 0 || in.ProgramIDIndex >= len(keys) || keys[in.ProgramIDIndex] != MemoProgramID {
			continue
		}
		if data, err := base58Decode(in.Data); err == nil {
			p.Memo = string(data)
			break
		}
	}
	want := MemoFor(d)
	switch {
	case p.Memo == "":
		return p, fmt.Errorf("%w: transaction %s has no memo", ErrNotAnchored, r.TxID)
	case p.Memo != want:
		return p, fmt.Errorf("%w: the ledger memo is %q, the report needs %q", ErrNotAnchored, p.Memo, want)
	case r.Signer != "" && p.Signer != r.Signer:
		return p, fmt.Errorf("%w: transaction was signed by %s, the receipt says %s", ErrNotAnchored, p.Signer, r.Signer)
	}
	return p, nil
}

// Find looks for an anchor of digest among the signer's recent
// transactions, so a lost receipt can be rebuilt from the ledger alone. It
// checks up to the newest 5,000 transactions and confirms the match with
// Lookup. Nothing found wraps ErrNotAnchored.
func (s *Solana) Find(ctx context.Context, digest, signer string) (Receipt, Proof, error) {
	d, err := normalize(digest)
	if err != nil {
		return Receipt{}, Proof{}, err
	}
	if _, err := decode32(signer); err != nil {
		return Receipt{}, Proof{}, fmt.Errorf("solana: %q is not a Solana address", signer)
	}
	want := MemoFor(d)
	before := ""
	for page := 0; page < 5; page++ {
		opts := map[string]any{"limit": 1000, "commitment": "confirmed"}
		if before != "" {
			opts["before"] = before
		}
		var list []struct {
			Signature string          `json:"signature"`
			Err       json.RawMessage `json:"err"`
			Memo      *string         `json:"memo"`
			BlockTime *int64          `json:"blockTime"`
		}
		if err := s.call(ctx, "getSignaturesForAddress", []any{signer, opts}, &list); err != nil {
			return Receipt{}, Proof{}, err
		}
		for _, e := range list {
			// The node formats memos as "[length] text"; the match is confirmed below.
			if e.Memo == nil || !strings.Contains(*e.Memo, want) || (len(e.Err) > 0 && string(e.Err) != "null") {
				continue
			}
			r := Receipt{Digest: d, Backend: s.Name(), Network: s.network, TxID: e.Signature, URL: s.explorer(e.Signature), Signer: signer}
			if e.BlockTime != nil {
				r.AnchoredAt = time.Unix(*e.BlockTime, 0).UTC()
			}
			p, err := s.Lookup(ctx, r)
			if err != nil {
				return Receipt{}, Proof{}, err
			}
			if !p.BlockTime.IsZero() {
				r.AnchoredAt = p.BlockTime
			}
			return r, p, nil
		}
		if len(list) < 1000 {
			break
		}
		before = list[len(list)-1].Signature
	}
	return Receipt{}, Proof{}, fmt.Errorf("%w: no transaction from %s on %s carries %s", ErrNotAnchored, signer, s.network, d)
}

func (s *Solana) explorer(sig string) string {
	switch s.network {
	case "mainnet-beta":
		return "https://explorer.solana.com/tx/" + sig
	case "devnet", "testnet":
		return "https://explorer.solana.com/tx/" + sig + "?cluster=" + s.network
	}
	return "https://explorer.solana.com/tx/" + sig + "?cluster=custom&customUrl=" + url.QueryEscape(s.rpcURL)
}

func networkOf(rpc string) string {
	for name, u := range clusters {
		if strings.TrimRight(rpc, "/") == u {
			return name
		}
	}
	switch h := strings.ToLower(rpc); {
	case strings.Contains(h, "devnet"):
		return "devnet"
	case strings.Contains(h, "testnet"):
		return "testnet"
	case strings.Contains(h, "mainnet"):
		return "mainnet-beta"
	}
	return "custom"
}

/* ------------------------------------------------------------------ JSON-RPC */

// RPCError is an error answer from a Solana node.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("solana RPC error %d: %s", e.Code, e.Message) }

func (s *Solana) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	// Retrying is safe for every call here: sending the same signed
	// transaction twice cannot pay or land twice.
	status, data, err := httpx.Do(ctx, s.http, s.retry, 4<<20, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.rpcURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "depscan")
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("solana %s: %w", method, err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("solana %s: RPC answered %d", method, status)
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("solana %s: %w", method, err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("solana %s: decoding result: %w", method, err)
	}
	return nil
}

// explainSend turns the usual first-run failure, an unfunded wallet, into
// instructions.
func (s *Solana) explainSend(err error) error {
	var re *RPCError
	if errors.As(err, &re) {
		text := strings.ToLower(re.Message + string(re.Data))
		if strings.Contains(text, "no record of a prior credit") || strings.Contains(text, "insufficient") {
			how := "fund it with SOL"
			if s.network == "devnet" || s.network == "testnet" {
				how = "get free " + s.network + " SOL at https://faucet.solana.com"
			}
			return fmt.Errorf("solana: wallet %s on %s: %w; %s", s.Address(), s.network, ErrUnfunded, how)
		}
	}
	return fmt.Errorf("solana: sending the transaction: %w", err)
}
