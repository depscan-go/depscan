package report

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const DigestPrefix = "sha256:"

var (
	ErrMismatch = errors.New("report does not match digest")

	ErrBadDigest = errors.New("malformed digest")
)

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return DigestPrefix + hex.EncodeToString(sum[:])
}

func ParseDigest(s string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(s))
	h = strings.TrimPrefix(h, DigestPrefix)
	if len(h) != sha256.Size*2 {
		return "", fmt.Errorf("%w: want %d hex characters, got %d", ErrBadDigest, sha256.Size*2, len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadDigest, err)
	}
	return h, nil
}

func Verify(data []byte, digest string) error {
	want, err := ParseDigest(digest)
	if err != nil {
		return err
	}
	got := strings.TrimPrefix(Digest(data), DigestPrefix)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("%w: got %s%s, want %s%s", ErrMismatch, DigestPrefix, got, DigestPrefix, want)
	}
	return nil
}

func ChecksumLine(data []byte, reportPath string) string {
	return strings.TrimPrefix(Digest(data), DigestPrefix) + "  " + filepath.Base(reportPath) + "\n"
}
