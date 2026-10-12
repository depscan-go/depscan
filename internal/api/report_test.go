package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/report"
)

func TestReport_AttachedAndServedByteForByte(t *testing.T) {
	h := newTestHandler(t)
	rec := h.Record("github.com/acme/shop#3@aaaaaaa", &model.ScanResult{})
	data := []byte(`{"bomFormat":"CycloneDX"}` + "\n")
	info := ReportInfo{Digest: report.Digest(data), Anchor: &anchor.Receipt{Backend: "solana", TxID: "tx1"}}
	if !h.AttachReport(rec.ID, data, info) {
		t.Fatal("AttachReport on a known scan returned false")
	}
	if h.AttachReport("unknown", data, info) {
		t.Error("AttachReport on an unknown scan should return false")
	}

	req := httptest.NewRequest(http.MethodGet, "/scans/"+rec.ID+"/report", nil)
	req.SetPathValue("id", rec.ID)
	w := httptest.NewRecorder()
	h.GetReport(w, req)
	if w.Code != http.StatusOK || w.Body.String() != string(data) || w.Header().Get("Content-Type") != "application/vnd.cyclonedx+json" {
		t.Fatalf("GET report: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if report.Verify(w.Body.Bytes(), info.Digest) != nil {
		t.Error("the served report must hash to the anchored digest")
	}

	req = httptest.NewRequest(http.MethodGet, "/scans/"+rec.ID, nil)
	req.SetPathValue("id", rec.ID)
	w = httptest.NewRecorder()
	h.GetScan(w, req)
	var got ScanRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Report == nil || got.Report.Anchor.TxID != "tx1" {
		t.Errorf("scan record = %s (%v)", w.Body.String(), err)
	}

	req = httptest.NewRequest(http.MethodGet, "/scans/nope/report", nil)
	req.SetPathValue("id", "nope")
	w = httptest.NewRecorder()
	h.GetReport(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing report: %d", w.Code)
	}
}

func TestReport_AttachWhileReading(t *testing.T) {
	h := newTestHandler(t)
	rec := h.Record("x", &model.ScanResult{})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); h.AttachReport(rec.ID, []byte("r"), ReportInfo{Digest: "d"}) }()
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/scans", nil)
			h.ListScans(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()
}
