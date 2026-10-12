package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/depscan-go/depscan/internal/anchor"
)

// runKeygen implements `depscan keygen`: it creates the Solana keypair that
// pays for and signs anchors, in the same file format as solana-keygen, so
// people who do not use the Solana CLI can still anchor on devnet.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", anchor.DefaultSolanaKeypair(), "where to write the keypair")
	fs.Usage = func() {
		say(stderr, "usage: depscan keygen [-out file]\n")
		say(stderr, "\nCreates a Solana keypair for -anchor solana. It never overwrites a file.\n")
		say(stderr, "\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			fs.Usage()
		}
		return exitToolError
	}
	if *out == "" {
		say(stderr, "cannot find your home folder; pass -out\n")
		return exitToolError
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		say(stderr, "generating a key: %v\n", err)
		return exitToolError
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		say(stderr, "creating %s: %v\n", filepath.Dir(*out), err)
		return exitToolError
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		say(stderr, "%s already exists; depscan never overwrites a keypair. Use it, or pass -out for a new file.\n", *out)
		return exitToolError
	}
	if err != nil {
		say(stderr, "writing the keypair: %v\n", err)
		return exitToolError
	}
	if _, err := f.Write(anchor.SolanaKeypairJSON(key)); err != nil {
		_ = f.Close()
		say(stderr, "writing the keypair: %v\n", err)
		return exitToolError
	}
	if err := f.Close(); err != nil {
		say(stderr, "writing the keypair: %v\n", err)
		return exitToolError
	}

	addr := anchor.SolanaAddress(key)
	say(stdout, "Keypair:  %s\n", *out)
	say(stdout, "Address:  %s\n\n", addr)
	say(stdout, "Next:\n")
	say(stdout, "  1. Get free devnet SOL for this address at https://faucet.solana.com\n")
	say(stdout, "     (one anchor costs 0.000005 SOL; 1 SOL is enough for thousands).\n")
	if *out != anchor.DefaultSolanaKeypair() {
		say(stdout, "  2. Point depscan at it:  export DEPSCAN_SOLANA_KEYPAIR=%s\n", *out)
		say(stdout, "  3. Anchor a report:      depscan -path . -report report.cdx.json -anchor solana\n")
	} else {
		say(stdout, "  2. Anchor a report:      depscan -path . -report report.cdx.json -anchor solana\n")
	}
	say(stdout, "\nKeep this file private: anyone with it can spend this address's SOL.\n")
	return exitClean
}

// say writes a line for the person at the terminal. If that write fails
// there is no one to tell, so the error is dropped on purpose.
func say(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}
