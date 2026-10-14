package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/store"
)

// get calls a handler as the mux would for a request whose {id} is id.
func get(h http.HandlerFunc, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/scans/x", nil)
	if id != "" {
		req.SetPathValue("id", id)
	}
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

var errDown = errors.New("dial tcp: connection refused")

// downStore fails every call, like Neon when it's down or out of compute hours.
type downStore struct{}

func (downStore) Save(context.Context, store.Scan) error                   { return errDown }
func (downStore) SetReport(context.Context, string, []byte, []byte) error { return errDown }
func (downStore) Get(context.Context, string) (store.Scan, error)         { return store.Scan{}, errDown }
func (downStore) Report(context.Context, string) ([]byte, error)          { return nil, errDown }
func (downStore) List(context.Context, int) ([]store.Scan, error)         { return nil, errDown }
func (downStore) Prune(context.Context, time.Time) error                  { return errDown }
func (downStore) Close()                                                   {}

// spyStore wraps a memory store. It counts reads, notes each save's kind,
// refuses a canceled context like Postgres would, and signals every prune.
type spyStore struct {
	store.Store
	reads  atomic.Int32
	kinds  chan store.Kind
	pruned chan struct{}
}

func newSpy() *spyStore {
	return &spyStore{Store: store.NewMemory(store.MemoryLimits), kinds: make(chan store.Kind, 10), pruned: make(chan struct{}, 10)}
}

func (s *spyStore) Save(ctx context.Context, sc store.Scan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.kinds <- sc.Kind
	return s.Store.Save(ctx, sc)
}

func (s *spyStore) Get(ctx context.Context, id string) (store.Scan, error) {
	s.reads.Add(1)
	return s.Store.Get(ctx, id)
}

func (s *spyStore) Report(ctx context.Context, id string) ([]byte, error) {
	s.reads.Add(1)
	return s.Store.Report(ctx, id)
}

func (s *spyStore) Prune(ctx context.Context, now time.Time) error {
	s.pruned <- struct{}{}
	return s.Store.Prune(ctx, now)
}

func TestRecord_SavesEvenIfTheCallerGaveUp(t *testing.T) {
	h := newTestHandler(t)
	h.Scans = newSpy()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the client left right after its scan finished
	rec, err := h.Record(ctx, store.Other, "shop", &model.ScanResult{})
	if err != nil {
		t.Fatalf("Record with a canceled context: %v", err)
	}
	if w := get(h.GetScan, rec.ID); w.Code != http.StatusOK {
		t.Errorf("GET the saved scan: %d", w.Code)
	}
}

func TestRecord_PrunesAtMostOnceAnHour(t *testing.T) {
	h := newTestHandler(t)
	spy := newSpy()
	h.Scans = spy
	for i := 0; i < 2; i++ {
		if _, err := h.Record(context.Background(), store.Other, "shop", &model.ScanResult{}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-spy.pruned:
	case <-time.After(2 * time.Second):
		t.Fatal("the first save should start a prune")
	}
	select {
	case <-spy.pruned:
		t.Error("a second save within the hour started another prune")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUploads_SavedAsOther(t *testing.T) {
	h, _ := newUploadHandler(t)
	spy := newSpy()
	h.Scans = spy
	postUpload(http.HandlerFunc(h.ScanUpload), uploadBody(t, uploadRequest{Name: "shop", Files: []uploadFile{{Path: "go.mod", Content: testGoMod}}}, false), nil)
	select {
	case k := <-spy.kinds:
		if k != store.Other {
			t.Errorf("kind = %q, want other", k)
		}
	default:
		t.Error("the upload wasn't saved")
	}
}

func TestGetScan_ServesTheSameJSONAsTheScan(t *testing.T) {
	h, _ := newUploadHandler(t)
	body := uploadBody(t, uploadRequest{Name: "<shop> & co", Files: []uploadFile{{Path: "go.mod", Content: testGoMod}}}, false)
	post := postUpload(http.HandlerFunc(h.ScanUpload), body, nil)
	var rec ScanRecord
	if err := json.Unmarshal(post.Body.Bytes(), &rec); err != nil || rec.ID == "" {
		t.Fatalf("upload: %d %s", post.Code, post.Body)
	}
	w := get(h.GetScan, rec.ID)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), post.Body.Bytes()) {
		t.Errorf("GET differs from the upload's response:\nGET  %d %s\nPOST %s", w.Code, w.Body, post.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestStoreDown_ScansStillAnswer(t *testing.T) {
	h, _ := newUploadHandler(t)
	h.Scans = downStore{}
	post := postUpload(http.HandlerFunc(h.ScanUpload), uploadBody(t, uploadRequest{Name: "shop", Files: []uploadFile{{Path: "go.mod", Content: testGoMod}}}, false), nil)
	var rec ScanRecord
	if err := json.Unmarshal(post.Body.Bytes(), &rec); err != nil || rec.ID == "" || rec.Result == nil {
		t.Fatalf("with the store down an upload should still return its result: %d %s", post.Code, post.Body)
	}
	if w := get(h.GetScan, rec.ID); w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /scans/{id} with the store down: %d, want 503 (a 404 would say the scan doesn't exist)", w.Code)
	}
	if w := get(h.GetReport, rec.ID); w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /scans/{id}/report with the store down: %d, want 503", w.Code)
	}
	h.AllowList = true
	if w := get(h.ListScans, ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /scans with the store down: %d, want 503", w.Code)
	}
}

func TestGetScan_MadeUpIDsNeverReachTheStore(t *testing.T) {
	h := newTestHandler(t)
	spy := newSpy()
	h.Scans = spy
	for _, id := range []string{"nope", "no-such-id", strings.Repeat("A", 32), strings.Repeat("a", 33), strings.Repeat("g", 32), "../" + strings.Repeat("a", 29)} {
		if w := get(h.GetScan, id); w.Code != http.StatusNotFound {
			t.Errorf("GET /scans/%s: %d, want 404", id, w.Code)
		}
		if w := get(h.GetReport, id); w.Code != http.StatusNotFound {
			t.Errorf("GET /scans/%s/report: %d, want 404", id, w.Code)
		}
	}
	if n := spy.reads.Load(); n != 0 {
		t.Errorf("made-up IDs reached the store %d times", n)
	}
	unknown := strings.Repeat("a", 32)
	if w := get(h.GetScan, unknown); w.Code != http.StatusNotFound || spy.reads.Load() != 1 {
		t.Errorf("a well-formed unknown ID: %d after %d reads", w.Code, spy.reads.Load())
	}
}

func TestListScans_OnlyOnALocalServer(t *testing.T) {
	h := newTestHandler(t)
	if w := get(h.ListScans, ""); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "local server") {
		t.Errorf("list on a public server: %d %s", w.Code, w.Body)
	}
	h.AllowList = true
	for i := 0; i < listLimit+1; i++ {
		if _, err := h.Record(context.Background(), store.Other, fmt.Sprint(i), &model.ScanResult{}); err != nil {
			t.Fatal(err)
		}
	}
	w := get(h.ListScans, "")
	var got []ScanRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK {
		t.Fatalf("list: %d %v", w.Code, err)
	}
	if len(got) != listLimit {
		t.Errorf("listed %d scans, want %d", len(got), listLimit)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ScannedAt.After(got[i-1].ScannedAt) {
			t.Fatalf("not newest first at %d: %s after %s", i, got[i].ScannedAt, got[i-1].ScannedAt)
		}
	}
}

// ctxStore fails reads with the request's context error, as Postgres does
// when the client has gone.
type ctxStore struct{ store.Store }

func (c ctxStore) Get(ctx context.Context, id string) (store.Scan, error) {
	if err := ctx.Err(); err != nil {
		return store.Scan{}, err
	}
	return c.Store.Get(ctx, id)
}

func (c ctxStore) Report(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Store.Report(ctx, id)
}

func (c ctxStore) List(ctx context.Context, limit int) ([]store.Scan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Store.List(ctx, limit)
}

func TestStoreReads_ClientGoneIsNotAnAlarm(t *testing.T) {
	h := newTestHandler(t)
	h.Scans = ctxStore{Store: store.NewMemory(store.MemoryLimits)}
	h.AllowList = true
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for name, handle := range map[string]http.HandlerFunc{"scan": h.GetScan, "report": h.GetReport, "list": h.ListScans} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // the visitor closed the tab while the database woke up
		req := httptest.NewRequest(http.MethodGet, "/scans/x", nil).WithContext(ctx)
		req.SetPathValue("id", strings.Repeat("a", 32))
		w := httptest.NewRecorder()
		handle(w, req)
		if w.Code >= 500 {
			t.Errorf("%s: %d: a client that left must not look like a server failure", name, w.Code)
		}
	}
	if strings.Contains(logs.String(), "store:") {
		t.Errorf("a client that left was logged as a store failure:\n%s", logs.String())
	}
}
