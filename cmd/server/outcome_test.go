package main

import (
	"context"
	"errors"
	"testing"

	"github.com/depscan-go/depscan/internal/api"
	"github.com/depscan-go/depscan/internal/policy"
	"github.com/depscan-go/depscan/internal/report"
	"github.com/depscan-go/depscan/internal/scan"
	"github.com/depscan-go/depscan/internal/store"
)

// flakyStore is a memory store whose writes can fail, like Neon when it's
// down or full.
type flakyStore struct {
	store.Store
	saveErr, reportErr error
}

func (f flakyStore) Save(ctx context.Context, s store.Scan) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return f.Store.Save(ctx, s)
}

func (f flakyStore) SetReport(ctx context.Context, id string, record, rep []byte) error {
	if f.reportErr != nil {
		return f.reportErr
	}
	return f.Store.SetReport(ctx, id, record, rep)
}

func handlerWith(t *testing.T, saveErr, reportErr error) *api.Handler {
	t.Helper()
	h, err := api.New(scan.New(&policy.Policy{}), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.Scans = flakyStore{Store: store.NewMemory(store.MemoryLimits), saveErr: saveErr, reportErr: reportErr}
	return h
}

var errFull = errors.New("could not extend file: project size limit exceeded")

func TestSaveOutcome_ScanAndReportSaved(t *testing.T) {
	h := handlerWith(t, nil, nil)
	o := outcome()
	id := saveOutcome(h, &flaky{}, &policy.Policy{}, &o, "github.com/acme/shop#3@aaaaaaa")
	if id == "" || o.Anchor == nil || !o.Anchor.ReportSaved {
		t.Fatalf("id = %q, anchor = %+v", id, o.Anchor)
	}
	data, err := h.Scans.Report(context.Background(), id)
	if err != nil || report.Verify(data, o.Anchor.Digest) != nil {
		t.Errorf("the saved report must hash to the anchored digest (%v)", err)
	}
}

func TestSaveOutcome_ScanNotSaved(t *testing.T) {
	h := handlerWith(t, errFull, nil)
	o := outcome()
	if id := saveOutcome(h, &flaky{}, &policy.Policy{}, &o, "label"); id != "" {
		t.Errorf("id = %q: the status and comment would link to a scan that isn't there", id)
	}
	if o.Anchor == nil || o.Anchor.TxID == "" || o.Anchor.ReportSaved {
		t.Errorf("anchor = %+v: the transaction should still show, without a download", o.Anchor)
	}
}

func TestSaveOutcome_ReportNotSaved(t *testing.T) {
	h := handlerWith(t, nil, errFull)
	o := outcome()
	if id := saveOutcome(h, &flaky{}, &policy.Policy{}, &o, "label"); id == "" {
		t.Error("the scan was saved, so its link should stay")
	}
	if o.Anchor == nil || o.Anchor.ReportSaved {
		t.Errorf("anchor = %+v: no download link for a report that wasn't saved", o.Anchor)
	}
}

func TestSaveOutcome_AnchoringOff(t *testing.T) {
	h := handlerWith(t, nil, nil)
	o := outcome()
	if id := saveOutcome(h, nil, &policy.Policy{}, &o, "label"); id == "" || o.Anchor != nil {
		t.Errorf("id = %q, anchor = %+v", id, o.Anchor)
	}
}
