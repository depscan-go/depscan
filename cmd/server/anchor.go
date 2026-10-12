package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/api"
	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/report"
)

// Anchoring on the server, for pull request scans:
//
//	DEPSCAN_ANCHOR=solana   turn it on (default off)
//	DEPSCAN_SOLANA_KEY      the payer's secret key, base58 or JSON array (from a secret store)
//	DEPSCAN_SOLANA_RPC      devnet (default), testnet, mainnet-beta or an RPC URL
//
// After each pull request scan the server builds the CycloneDX report,
// anchors its SHA-256 in a Solana memo, keeps the report at
// GET /scans/{id}/report, and puts the transaction in the pull request
// comment. The ledger is the durable record: if the server restarts and the
// report is gone, `depscan verify -signer <address>` still finds the anchor
// of any copy of the report.

// newServerAnchorer reads DEPSCAN_ANCHOR. It returns nil when anchoring is off.
func newServerAnchorer() (*anchor.Solana, error) {
	switch mode := strings.ToLower(strings.TrimSpace(os.Getenv("DEPSCAN_ANCHOR"))); mode {
	case "", "off":
		return nil, nil
	case "solana":
		s, err := anchor.SolanaFromEnv()
		if err != nil {
			return nil, err
		}
		if s.Address() == "" {
			return nil, errors.New("DEPSCAN_ANCHOR=solana needs DEPSCAN_SOLANA_KEY (or a DEPSCAN_SOLANA_KEYPAIR file)")
		}
		return s, nil
	default:
		return nil, fmt.Errorf("DEPSCAN_ANCHOR=%q: use solana or off", mode)
	}
}

type anchorer interface {
	Anchor(ctx context.Context, digest string) (anchor.Receipt, error)
}

// anchorRetries are the waits between attempts. A blockhash that expires or a
// node that drops the transaction is worth another try; an empty wallet is not.
var anchorRetries = []time.Duration{2 * time.Second, 5 * time.Second}

// anchorScan builds the scan's report and anchors its digest. It returns the
// report bytes even when anchoring fails, so the report can still be served.
func anchorScan(ctx context.Context, a anchorer, p *policy.Policy, o github.Outcome) ([]byte, api.ReportInfo, error) {
	bom, err := report.Build(report.Input{
		Result:      o.Result,
		Policy:      p,
		Subject:     o.Job.Repo,
		Commit:      o.Job.HeadSHA,
		ScannedAt:   o.StartedAt,
		ToolVersion: "server",
	})
	if err != nil {
		return nil, api.ReportInfo{}, err
	}
	data, err := bom.Encode()
	if err != nil {
		return nil, api.ReportInfo{}, err
	}
	info := api.ReportInfo{Digest: report.Digest(data)}

	for attempt := 0; ; attempt++ {
		r, err := a.Anchor(ctx, info.Digest)
		if err == nil {
			info.Anchor = &r
			return data, info, nil
		}
		permanent := errors.Is(err, anchor.ErrUnfunded) || errors.Is(err, report.ErrBadDigest) || ctx.Err() != nil
		if permanent || attempt >= len(anchorRetries) {
			info.AnchorError = err.Error()
			return data, info, err
		}
		select {
		case <-ctx.Done():
			info.AnchorError = err.Error()
			return data, info, err
		case <-time.After(anchorRetries[attempt]):
		}
	}
}

// anchorNote turns the result into the line the pull request comment shows.
func anchorNote(info api.ReportInfo) *github.AnchorNote {
	if info.Digest == "" {
		return nil
	}
	n := &github.AnchorNote{Digest: info.Digest, Err: info.AnchorError}
	if r := info.Anchor; r != nil {
		n.Network, n.TxID, n.URL, n.Signer = r.Network, r.TxID, r.URL, r.Signer
	}
	return n
}

// logBalance warns at startup when the wallet cannot pay for anchors.
func logBalance(s *anchor.Solana, logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lamports, err := s.Balance(ctx)
	switch {
	case err != nil:
		logf("anchoring: could not read the balance of %s: %v", s.Address(), err)
	case lamports < 5_000:
		logf("anchoring: WARNING %s has no SOL on %s; anchors will fail until it is funded (devnet: https://faucet.solana.com)", s.Address(), s.Network())
	default:
		logf("anchoring: %s holds %.4f SOL on %s, about %d anchors", s.Address(), float64(lamports)/1e9, s.Network(), lamports/5_000)
	}
}
