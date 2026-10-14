package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/report"
	"github.com/depscan-go/depscan/internal/store"
)

func TestReport_AttachedAndServedByteForByte(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	rec, err := h.Record(ctx, store.PR, "github.com/acme/shop#3@aaaaaaa", &model.ScanResult{})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"bomFormat":"CycloneDX"}` + "\n")
	info := ReportInfo{Digest: report.Digest(data), Anchor: &anchor.Receipt{Backend: "solana", TxID: "tx1"}}
	if err := h.AttachReport(ctx, rec, data, info); err != nil {
		t.Fatalf("AttachReport on a saved scan: %v", err)
	}
	if err := h.AttachReport(ctx, &ScanRecord{ID: newID()}, data, info); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("AttachReport on an unknown scan = %v, want ErrNotFound", err)
	}

	w := get(h.GetReport, rec.ID)
	if w.Code != http.StatusOK || w.Body.String() != string(data) || w.Header().Get("Content-Type") != "application/vnd.cyclonedx+json" {
		t.Fatalf("GET report: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if report.Verify(w.Body.Bytes(), info.Digest) != nil {
		t.Error("the served report must hash to the anchored digest")
	}

	w = get(h.GetScan, rec.ID)
	var got ScanRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Report == nil || got.Report.Anchor.TxID != "tx1" {
		t.Errorf("scan record = %s (%v)", w.Body.String(), err)
	}

	if w := get(h.GetReport, "nope"); w.Code != http.StatusNotFound {
		t.Errorf("missing report: %d", w.Code)
	}
}

func TestReport_AttachWhileReading(t *testing.T) {
	h := newTestHandler(t)
	h.AllowList = true
	ctx := context.Background()
	rec, err := h.Record(ctx, store.PR, "x", &model.ScanResult{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = h.AttachReport(ctx, rec, []byte("r"), ReportInfo{Digest: "d"}) }()
		go func() {
			defer wg.Done()
			h.ListScans(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/scans", nil))
		}()
	}
	wg.Wait()
}
