package store_test

import (
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/store"
	"github.com/depscan-go/depscan/internal/store/storetest"
)

func TestMemory(t *testing.T) {
	storetest.Run(t, func(t *testing.T, lim store.Limits) (store.Store, func() store.Store) {
		return store.NewMemory(lim), nil
	})
}

func TestLimits_MatchTheSpec(t *testing.T) {
	month := 30 * 24 * time.Hour
	if l := store.PostgresLimits; l.OtherMaxAge != month || l.MaxBytes != 700*store.MB || l.TargetBytes != 600*store.MB {
		t.Errorf("PostgresLimits = %+v", l)
	}
	if l := store.MemoryLimits; l.OtherMaxAge != month || l.MaxBytes != 100*store.MB || l.TargetBytes != 80*store.MB {
		t.Errorf("MemoryLimits = %+v", l)
	}
}
