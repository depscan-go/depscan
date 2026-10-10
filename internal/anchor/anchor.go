package anchor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/depscan-go/depscan/internal/report"
)

var (
	ErrNotAnchored = errors.New("digest is not anchored")

	ErrUnknownBackend = errors.New("unknown anchor backend")
)

// Anchorer stores a report digest and later confirms it is still there.
type Anchorer interface {
	// Name identifies the backend, e.g. "noop" or "solana".
	Name() string

	Anchor(ctx context.Context, digest string) (Receipt, error)

	Verify(ctx context.Context, r Receipt) error
}

type Receipt struct {
	Digest     string    `json:"digest"`
	Backend    string    `json:"backend"`
	Network    string    `json:"network,omitempty"`
	TxID       string    `json:"tx_id,omitempty"`
	URL        string    `json:"url,omitempty"`
	AnchoredAt time.Time `json:"anchored_at"`
}

// New returns the backend with the given name.
func New(name string) (Anchorer, error) {
	switch name {
	case "noop":
		return NewNoop(), nil
	}
	return nil, fmt.Errorf("%w: %q (available: noop)", ErrUnknownBackend, name)
}

// normalize validates a digest and returns it in canonical "sha256:<hex>" form,
// so every backend stores and compares digests the same way.
func normalize(digest string) (string, error) {
	h, err := report.ParseDigest(digest)
	if err != nil {
		return "", err
	}
	return report.DigestPrefix + h, nil
}

// WriteReceipt saves a receipt as indented JSON.
func WriteReceipt(path string, r Receipt) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding receipt: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// ReadReceipt loads a receipt written by WriteReceipt.
func ReadReceipt(path string) (Receipt, error) {
	var r Receipt
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("decoding receipt %s: %w", path, err)
	}
	return r, nil
}
