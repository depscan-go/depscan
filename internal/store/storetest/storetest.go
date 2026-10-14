// Package storetest checks a store.Store against the behavior every version
// must share. Each version's tests call Run.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/store"
)

// Opener returns an empty store with the given limits. reopen, when not nil,
// opens a second store on the same data, as a restarted server would.
type Opener func(t *testing.T, lim store.Limits) (s store.Store, reopen func() store.Store)

const day = 24 * time.Hour

// noSpaceRule keeps only the 30-day rule, so tests about other things never
// trip the space rule.
var noSpaceRule = store.Limits{OtherMaxAge: 30 * day}

// Run checks everything both versions promise.
func Run(t *testing.T, open Opener) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("save then read back", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		mustSave(t, s, store.Scan{ID: id(1), Kind: store.PR, ScannedAt: now, Record: []byte(`{"n":1}`)})
		got, err := s.Get(ctx, id(1))
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != id(1) || got.Kind != store.PR || !got.ScannedAt.Equal(now) || string(got.Record) != `{"n":1}` || got.Report != nil {
			t.Errorf("Get = %+v", got)
		}
		if _, err := s.Report(ctx, id(1)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Report before SetReport = %v, want ErrNotFound", err)
		}
	})

	t.Run("the report comes back byte for byte", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		mustSave(t, s, scan(2, store.PR, now))
		report := []byte("{\"bom\":\"\x00\xff\xfe\"}\n") // a null byte and invalid UTF-8
		if err := s.SetReport(ctx, id(2), []byte(`{"n":2,"report":{}}`), report); err != nil {
			t.Fatal(err)
		}
		got, err := s.Report(ctx, id(2))
		if err != nil || !bytes.Equal(got, report) {
			t.Errorf("Report = %q, %v; want %q", got, err, report)
		}
		rec, err := s.Get(ctx, id(2))
		if err != nil || string(rec.Record) != `{"n":2,"report":{}}` {
			t.Errorf("record after SetReport = %q, %v", rec.Record, err)
		}
	})

	t.Run("unknown ids", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		if _, err := s.Get(ctx, id(404)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get = %v, want ErrNotFound", err)
		}
		if _, err := s.Report(ctx, id(404)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Report = %v, want ErrNotFound", err)
		}
		if err := s.SetReport(ctx, id(404), []byte(`{}`), []byte("r")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetReport = %v, want ErrNotFound", err)
		}
	})

	t.Run("saving an existing id is an error", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		mustSave(t, s, store.Scan{ID: id(3), Kind: store.Other, ScannedAt: now, Record: []byte(`{"first":true}`)})
		err := s.Save(ctx, store.Scan{ID: id(3), Kind: store.Other, ScannedAt: now, Record: []byte(`{"second":true}`)})
		if !errors.Is(err, store.ErrExists) {
			t.Errorf("second Save = %v, want ErrExists", err)
		}
		if got, _ := s.Get(ctx, id(3)); string(got.Record) != `{"first":true}` {
			t.Errorf("the first scan was overwritten: %s", got.Record)
		}
	})

	t.Run("bad scans are refused", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		for _, bad := range []store.Scan{
			{ID: "", Kind: store.PR, ScannedAt: now, Record: []byte(`{}`)},
			{ID: id(5), Kind: "weekly", ScannedAt: now, Record: []byte(`{}`)},
			{ID: id(6), Kind: store.PR, ScannedAt: now},
		} {
			if err := s.Save(ctx, bad); err == nil {
				t.Errorf("Save(%+v) = nil, want an error", bad)
			}
		}
	})

	t.Run("the caller's bytes are copied", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		rec := []byte(`{"n":7}`)
		mustSave(t, s, store.Scan{ID: id(7), Kind: store.PR, ScannedAt: now, Record: rec})
		rec[2] = 'x'
		got, _ := s.Get(ctx, id(7))
		got.Record[2] = 'y'
		if again, _ := s.Get(ctx, id(7)); string(again.Record) != `{"n":7}` {
			t.Errorf("stored record changed to %s", again.Record)
		}
	})

	t.Run("list is newest first and leaves out expired scans", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		mustSave(t, s, scan(10, store.Other, now.Add(-3*time.Hour)))
		mustSave(t, s, scan(11, store.PR, now.Add(-1*time.Hour)))
		mustSave(t, s, scan(12, store.Other, now.Add(-2*time.Hour)))
		mustSave(t, s, scan(13, store.Other, now.Add(-31*day)))   // expired
		mustSave(t, s, scan(14, store.PR, now.Add(-3*365*day)))   // old, but PR scans don't expire
		all, err := s.List(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := ids(all), ids2(11, 12, 10, 14); got != want {
			t.Errorf("List(0) = %s, want %s", got, want)
		}
		for _, sc := range all {
			if sc.Report != nil || len(sc.Record) == 0 {
				t.Errorf("listed scan %s: record %q, report %q", sc.ID, sc.Record, sc.Report)
			}
		}
		top, err := s.List(ctx, 2)
		if err != nil || ids(top) != ids2(11, 12) {
			t.Errorf("List(2) = %s, %v", ids(top), err)
		}
	})

	t.Run("an expired upload is not served", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		mustSave(t, s, scan(20, store.Other, now.Add(-31*day)))
		mustSave(t, s, scan(21, store.Other, now.Add(-29*day)))
		mustSave(t, s, scan(22, store.PR, now.Add(-3*365*day)))
		gone(t, s, 20)
		present(t, s, 21, 22)
	})

	t.Run("prune deletes uploads past 30 days", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		mustSave(t, s, scan(30, store.Other, now.Add(-10*day)))
		mustSave(t, s, scan(31, store.Other, now.Add(-1*day)))
		mustSave(t, s, scan(32, store.PR, now.Add(-10*day)))
		// Pretend 25 days have passed: scan 30 is now 35 days old. Today's
		// clock still sees it as 10 days old, so only a delete hides it.
		if err := s.Prune(ctx, now.Add(25*day)); err != nil {
			t.Fatal(err)
		}
		gone(t, s, 30)
		present(t, s, 31, 32)
	})

	t.Run("prune frees space, uploads first, oldest first", func(t *testing.T) {
		s, _ := open(t, store.Limits{OtherMaxAge: 30 * day, MaxBytes: 1000, TargetBytes: 600})
		// 300 bytes each.
		mustSave(t, s, sized(40, store.PR, now.Add(-4*time.Hour)))
		mustSave(t, s, sized(41, store.Other, now.Add(-3*time.Hour)))
		mustSave(t, s, sized(42, store.Other, now.Add(-2*time.Hour)))
		mustSave(t, s, sized(43, store.PR, now.Add(-1*time.Hour)))
		mustPrune(t, s, now) // 1200 > 1000: both uploads go, 600 left
		gone(t, s, 41, 42)
		present(t, s, 40, 43)

		mustSave(t, s, sized(44, store.PR, now))
		mustPrune(t, s, now) // 900: under the limit, nothing goes
		present(t, s, 40, 43, 44)

		mustSave(t, s, sized(45, store.PR, now.Add(time.Second)))
		mustPrune(t, s, now) // 1200 again, only PR scans: the two oldest go
		gone(t, s, 40, 43)
		present(t, s, 44, 45)
	})

	t.Run("a large scan round-trips", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		record := bytes.Repeat([]byte("r"), 3<<20)
		report := bytes.Repeat([]byte("p"), 3<<20)
		mustSave(t, s, store.Scan{ID: id(50), Kind: store.PR, ScannedAt: now, Record: record})
		if err := s.SetReport(ctx, id(50), record, report); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, id(50))
		if err != nil || !bytes.Equal(got.Record, record) {
			t.Errorf("large record: %d bytes back, %v", len(got.Record), err)
		}
		rep, err := s.Report(ctx, id(50))
		if err != nil || !bytes.Equal(rep, report) {
			t.Errorf("large report: %d bytes back, %v", len(rep), err)
		}
	})

	t.Run("parallel saves and reads", func(t *testing.T) {
		s, _ := open(t, noSpaceRule)
		var wg sync.WaitGroup
		errs := make(chan error, 60)
		for i := 0; i < 20; i++ {
			wg.Add(3)
			go func() { defer wg.Done(); errs <- s.Save(ctx, scan(100+i, store.Other, now)) }()
			go func() { defer wg.Done(); _, err := s.List(ctx, 10); errs <- err }()
			go func() {
				defer wg.Done()
				_, err := s.Get(ctx, id(100+i))
				if errors.Is(err, store.ErrNotFound) {
					err = nil // not saved yet
				}
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
		if all, err := s.List(ctx, 0); err != nil || len(all) != 20 {
			t.Errorf("List after parallel saves: %d scans, %v", len(all), err)
		}
	})

	t.Run("a second store finds the first one's scans", func(t *testing.T) {
		s, reopen := open(t, noSpaceRule)
		if reopen == nil {
			t.Skip("this version keeps nothing between processes")
		}
		mustSave(t, s, scan(200, store.PR, now))
		if err := s.SetReport(ctx, id(200), []byte(`{"n":200,"report":{}}`), []byte("report-200")); err != nil {
			t.Fatal(err)
		}
		s2 := reopen()
		got, err := s2.Get(ctx, id(200))
		if err != nil || string(got.Record) != `{"n":200,"report":{}}` {
			t.Errorf("after reopening: %q, %v", got.Record, err)
		}
		if rep, err := s2.Report(ctx, id(200)); err != nil || string(rep) != "report-200" {
			t.Errorf("report after reopening: %q, %v", rep, err)
		}
	})
}

// id makes a scan ID in the format the API uses: 32 lowercase hex characters.
func id(n int) string { return fmt.Sprintf("%032x", n) }

func scan(n int, k store.Kind, at time.Time) store.Scan {
	return store.Scan{ID: id(n), Kind: k, ScannedAt: at, Record: []byte(fmt.Sprintf(`{"n":%d}`, n))}
}

// sized is a scan whose record is exactly 300 bytes.
func sized(n int, k store.Kind, at time.Time) store.Scan {
	head := fmt.Sprintf(`{"n":%d,"pad":"`, n)
	return store.Scan{ID: id(n), Kind: k, ScannedAt: at, Record: []byte(head + strings.Repeat("x", 300-len(head)-2) + `"}`)}
}

func ids(list []store.Scan) string {
	var out []string
	for _, s := range list {
		out = append(out, s.ID)
	}
	return strings.Join(out, " ")
}

func ids2(ns ...int) string {
	var out []string
	for _, n := range ns {
		out = append(out, id(n))
	}
	return strings.Join(out, " ")
}

func mustSave(t *testing.T, s store.Store, sc store.Scan) {
	t.Helper()
	if err := s.Save(context.Background(), sc); err != nil {
		t.Fatalf("Save %s: %v", sc.ID, err)
	}
}

func mustPrune(t *testing.T, s store.Store, now time.Time) {
	t.Helper()
	if err := s.Prune(context.Background(), now); err != nil {
		t.Fatalf("Prune: %v", err)
	}
}

func present(t *testing.T, s store.Store, ns ...int) {
	t.Helper()
	for _, n := range ns {
		if _, err := s.Get(context.Background(), id(n)); err != nil {
			t.Errorf("scan %d should still be there: %v", n, err)
		}
	}
}

func gone(t *testing.T, s store.Store, ns ...int) {
	t.Helper()
	for _, n := range ns {
		if _, err := s.Get(context.Background(), id(n)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("scan %d should be gone, got %v", n, err)
		}
	}
}
