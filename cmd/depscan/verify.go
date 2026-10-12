package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/report"
)

// Check outcomes, as printed and as written to -json.
const (
	checkOK       = "ok"
	checkMismatch = "mismatch"
	checkMissing  = "missing"
	checkSkipped  = "skipped"
)

type verifyResult struct {
	Report     string `json:"report"`
	Digest     string `json:"digest"`
	Checksum   string `json:"checksum"`
	Anchor     string `json:"anchor"`
	Backend    string `json:"backend,omitempty"`
	Network    string `json:"network,omitempty"`
	TxID       string `json:"tx_id,omitempty"`
	URL        string `json:"url,omitempty"`
	Signer     string `json:"signer,omitempty"`
	AnchoredAt string `json:"anchored_at,omitempty"`
	Recovered  bool   `json:"recovered,omitempty"` // found on the ledger by -signer, with no receipt file
	Verified   bool   `json:"verified"`
	Detail     string `json:"detail,omitempty"`
}

// prover is a backend that can say what the ledger holds, not only yes or no.
type prover interface {
	Lookup(ctx context.Context, r anchor.Receipt) (anchor.Proof, error)
}

// runVerify implements `depscan verify`. Exit codes: 0 verified, 1 the
// report or its anchor does not match, 2 the check could not be done.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	receiptPath := fs.String("receipt", "", "anchor receipt to check (default <report>.anchor.json)")
	offline := fs.Bool("offline", false, "check the checksum and receipt files only, without asking the ledger")
	signer := fs.String("signer", "", "with no receipt file, search this Solana address's transactions for the report's anchor")
	save := fs.Bool("save", false, "with -signer, write the receipt that was found to the receipt file")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	timeout := fs.Duration("timeout", 60*time.Second, "how long to wait for the ledger")
	fs.Usage = func() {
		say(stderr, "usage: depscan verify [flags] report.cdx.json\n")
		say(stderr, "\nRe-hashes the report and checks it against report.cdx.json.sha256 and, if it was\n")
		say(stderr, "anchored, against the transaction named in report.cdx.json.anchor.json.\n")
		say(stderr, "Exit status: 0 verified, 1 changed or not anchored, 2 could not check.\n")
		say(stderr, "\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitToolError
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitToolError
	}
	path := fs.Arg(0)
	if *receiptPath == "" {
		*receiptPath = path + ".anchor.json"
	}

	res, code := verifyReport(path, verifyOpts{receipt: *receiptPath, offline: *offline, timeout: *timeout, signer: *signer, save: *save})
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			say(stderr, "writing JSON: %v\n", err)
			return exitToolError
		}
		return code
	}
	printVerify(stdout, res, code)
	return code
}

type verifyOpts struct {
	receipt string
	offline bool
	timeout time.Duration
	signer  string // Solana address to search when there is no receipt
	save    bool
}

func verifyReport(path string, o verifyOpts) (verifyResult, int) {
	receiptPath, offline, timeout := o.receipt, o.offline, o.timeout
	res := verifyResult{Report: path, Checksum: checkMissing, Anchor: checkMissing}
	data, err := os.ReadFile(path)
	if err != nil {
		res.Detail = fmt.Sprintf("cannot read the report: %v", err)
		return res, exitToolError
	}
	res.Digest = report.Digest(data)
	failed, toolErr := false, false

	// 1. The sha256sum file written next to the report.
	if want, err := readChecksum(path + ".sha256"); err == nil {
		if report.Verify(data, want) == nil {
			res.Checksum = checkOK
		} else {
			res.Checksum, failed = checkMismatch, true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		res.Checksum, failed = checkMismatch, true
		res.Detail = err.Error()
	}

	// 2. The anchor receipt, then the ledger.
	r, err := anchor.ReadReceipt(receiptPath)
	switch {
	case errors.Is(err, os.ErrNotExist) && o.signer != "" && !offline:
		// No receipt: the ledger itself can say whether this report was anchored.
		f, ferr := recoverReceipt(res.Digest, o.signer, timeout)
		switch {
		case ferr == nil:
			res.Anchor, res.Recovered = checkOK, true
			res.Backend, res.Network, res.TxID, res.URL, res.Signer = f.Backend, f.Network, f.TxID, f.URL, f.Signer
			res.AnchoredAt = f.AnchoredAt.UTC().Format(time.RFC3339)
			if o.save {
				if werr := anchor.WriteReceipt(receiptPath, f); werr != nil {
					res.Detail, toolErr = "found the anchor but could not save the receipt: "+werr.Error(), true
				} else {
					res.Detail = "receipt saved to " + receiptPath
				}
			}
		case errors.Is(ferr, anchor.ErrNotAnchored):
			res.Anchor, failed = checkMismatch, true
			res.Detail = ferr.Error()
		default:
			res.Anchor, toolErr = checkSkipped, true
			res.Detail = "could not ask the ledger: " + ferr.Error()
		}
	case errors.Is(err, os.ErrNotExist):
		// not anchored; the checksum alone decides
	case err != nil:
		res.Anchor, toolErr = checkMismatch, true
		res.Detail = err.Error()
	default:
		res.Backend, res.Network, res.TxID, res.URL, res.Signer = r.Backend, r.Network, r.TxID, r.URL, r.Signer
		if !r.AnchoredAt.IsZero() {
			res.AnchoredAt = r.AnchoredAt.UTC().Format(time.RFC3339)
		}
		if report.Verify(data, r.Digest) != nil {
			res.Anchor, failed = checkMismatch, true
			res.Detail = "the receipt was written for a different report: " + r.Digest
			break
		}
		if offline || r.Backend == "noop" {
			res.Anchor = checkSkipped
			if r.Backend == "noop" {
				res.Detail = "the noop backend keeps nothing, so there is no ledger to check"
			}
			break
		}
		a, err := anchor.ForReceipt(r)
		if err != nil {
			res.Anchor, toolErr = checkSkipped, true
			res.Detail = err.Error()
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if p, ok := a.(prover); ok {
			var proof anchor.Proof
			proof, err = p.Lookup(ctx, r)
			if err == nil && !proof.BlockTime.IsZero() {
				res.AnchoredAt = proof.BlockTime.Format(time.RFC3339)
			}
		} else {
			err = a.Verify(ctx, r)
		}
		switch {
		case err == nil:
			res.Anchor = checkOK
		case errors.Is(err, anchor.ErrNotAnchored):
			res.Anchor, failed = checkMismatch, true
			res.Detail = err.Error()
		default:
			res.Anchor, toolErr = checkSkipped, true
			res.Detail = "could not ask the ledger: " + err.Error()
		}
	}

	switch {
	case failed:
		return res, exitViolation
	case toolErr:
		return res, exitToolError
	case res.Checksum == checkMissing && res.Anchor != checkOK:
		res.Detail = joinDetail(res.Detail, "nothing to check against: no .sha256 file and no anchor receipt")
		return res, exitToolError
	}
	res.Verified = true
	return res, exitClean
}

func recoverReceipt(digest, signer string, timeout time.Duration) (anchor.Receipt, error) {
	s, err := anchor.SolanaFromEnv()
	if err != nil {
		return anchor.Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r, _, err := s.Find(ctx, digest, signer)
	return r, err
}

// readChecksum reads a sha256sum line ("<hex>  <file>") and returns the digest.
func readChecksum(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", fmt.Errorf("%s is empty", path)
	}
	h, err := report.ParseDigest(fields[0])
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return report.DigestPrefix + h, nil
}

func printVerify(w io.Writer, r verifyResult, code int) {
	label := map[string]string{checkOK: "OK", checkMismatch: "DOES NOT MATCH", checkMissing: "not found", checkSkipped: "not checked"}
	say(w, "Report:    %s\n", r.Report)
	if r.Digest != "" {
		say(w, "Digest:    %s\n", r.Digest)
	}
	say(w, "Checksum:  %s\n", label[r.Checksum])
	anchorLine := label[r.Anchor]
	if r.Backend != "" {
		anchorLine += fmt.Sprintf(" (%s", r.Backend)
		if r.Network != "" {
			anchorLine += ", " + r.Network
		}
		anchorLine += ")"
	}
	say(w, "Anchor:    %s\n", anchorLine)
	if r.TxID != "" {
		say(w, "           tx %s\n", r.TxID)
	}
	if r.Signer != "" {
		say(w, "           signed by %s\n", r.Signer)
	}
	if r.URL != "" {
		say(w, "           %s\n", r.URL)
	}
	if r.Detail != "" {
		say(w, "Detail:    %s\n", r.Detail)
	}
	say(w, "\n")
	switch code {
	case exitClean:
		if r.Anchor == checkOK {
			say(w, "VERIFIED: this report is exactly the one anchored at %s.\n", r.AnchoredAt)
			if r.Recovered {
				say(w, "The receipt file was missing; the anchor was found on the ledger by its signer.\n")
			}
		} else {
			say(w, "VERIFIED: this report matches its checksum file.\n")
		}
		say(w, "It proves the report has not changed, not that the project is still safe: scan again for today's advisories.\n")
	case exitViolation:
		say(w, "FAILED: the report was changed after it was written, or its anchor does not match.\n")
	default:
		say(w, "NOT CHECKED: see the detail above.\n")
	}
}

func joinDetail(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
