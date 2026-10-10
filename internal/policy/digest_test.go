package policy_test

import (
	"testing"

	"github.com/depscan-go/depscan/internal/policy"
)

func TestDigest_StableAndSensitiveToRules(t *testing.T) {
	a := &policy.Policy{BlockSeverities: []string{"CRITICAL", "HIGH"}}
	b := &policy.Policy{BlockSeverities: []string{"CRITICAL", "HIGH"}}
	c := &policy.Policy{BlockSeverities: []string{"CRITICAL"}}

	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, _ := b.Digest()
	dc, _ := c.Digest()

	if len(da) != 64 {
		t.Errorf("digest %q is not 64 hex characters", da)
	}
	if da != db {
		t.Error("identical policies must have the same digest")
	}
	if da == dc {
		t.Error("a rule change must change the digest")
	}
}
