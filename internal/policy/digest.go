package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func (p *Policy) Digest() (string, error) {
	b, err := json.Marshal(p) // struct fields encode in a fixed order
	if err != nil {
		return "", fmt.Errorf("encoding policy: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
