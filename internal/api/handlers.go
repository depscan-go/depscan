package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/depscan-go/depscan/internal/anchor"
	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/scan"
	"github.com/depscan-go/depscan/internal/store"
)

type ScanRecord struct {
	ID        string            `json:"id"`
	Path      string            `json:"path"`
	ScannedAt time.Time         `json:"scanned_at"`
	Result    *model.ScanResult `json:"result"`
	Report    *ReportInfo       `json:"report,omitempty"`
}

// ReportInfo describes the CycloneDX report the server kept for a scan and,
// if it was anchored, where. The report itself is at GET /scans/{id}/report.
type ReportInfo struct {
	Digest      string          `json:"digest"`
	Anchor      *anchor.Receipt `json:"anchor,omitempty"`
	AnchorError string          `json:"anchor_error,omitempty"`
}

// listLimit is how many scans GET /scans returns, newest first: as many as
// the dashboard keeps in a browser.
const listLimit = 300

type Handler struct {
	engine   *scan.Engine
	scanRoot string

	// Scans keeps scan records and reports. New starts with a memory store;
	// main swaps in Postgres before serving when DATABASE_URL is set.
	Scans store.Store
	// AllowList lets GET /scans list every scan. Set it only on a server that
	// accepts connections from its own computer only.
	AllowList bool

	pruneMu   sync.Mutex
	lastPrune time.Time

	// uploads holds one slot per upload being scanned; see maxUploadsAtOnce.
	uploads chan struct{}
}

func New(engine *scan.Engine, scanRoot string) (*Handler, error) {
	root, err := filepath.Abs(scanRoot)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	return &Handler{
		engine:   engine,
		scanRoot: root,
		Scans:    store.NewMemory(store.MemoryLimits),
		uploads:  make(chan struct{}, maxUploadsAtOnce),
	}, nil
}

var errOutsideRoot = errors.New("path must be inside the scan root")

func (h *Handler) resolveScanPath(p string) (string, error) {
	candidate := p
	if !filepath.IsAbs(p) {
		candidate = filepath.Join(h.scanRoot, p)
	}
	target, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(h.scanRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errOutsideRoot
	}
	return target, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		// Headers are already sent, so we can only log it.
		log.Printf("writing JSON response: %v", err)
	}
}

// writeRecord sends a saved record, formatted exactly like writeJSON.
func writeRecord(w http.ResponseWriter, data []byte) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		log.Printf("store: reading a damaged record failed: %v", err)
		writeError(w, http.StatusInternalServerError, "this scan's saved record is damaged")
		return
	}
	buf.WriteByte('\n')
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Printf("writing JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// statusClientClosed is nginx's code for a request whose client left first.
const statusClientClosed = 499

// storeFailed answers a request the store couldn't serve, with a 503 and a
// "store: … failed" line, which the Watchdog alerts on. A client that has
// already gone isn't a store failure (Postgres just stops the query), so it
// gets 499 and no log line.
func storeFailed(w http.ResponseWriter, r *http.Request, what string, err error) {
	if r.Context().Err() != nil {
		w.WriteHeader(statusClientClosed)
		return
	}
	log.Printf("store: %s failed: %v", what, err)
	writeError(w, http.StatusServiceUnavailable, "scan storage is unavailable; try again in a minute")
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {

		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// validID says whether id looks like one newID made: 32 lowercase hex
// characters. No other ID can exist, so it never reaches the store, and a
// request for a made-up ID never wakes the database.
func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Healthz never touches the store: the dashboard calls it every minute while
// a tab is open, which would keep the database awake.
func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

type scanRequest struct {
	Path string `json:"path"`
}

func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	target, err := h.resolveScanPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}

	result, err := h.engine.Run(r.Context(), target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// A failed save is logged; the result is still the answer.
	record, _ := h.Record(r.Context(), store.Other, req.Path, result)

	status := http.StatusOK
	if len(result.Violations) > 0 {
		status = http.StatusUnprocessableEntity
	}

	writeJSON(w, status, record)
}

// Record saves a finished scan and returns its record. If saving fails it
// still returns the record, with the error (already logged): the caller has
// the result, and only its link won't work later. A finished scan is saved
// even if the caller has gone, so ctx's cancellation is ignored.
func (h *Handler) Record(ctx context.Context, kind store.Kind, label string, result *model.ScanResult) (*ScanRecord, error) {
	record := &ScanRecord{
		ID:        newID(),
		Path:      label,
		ScannedAt: time.Now().UTC(),
		Result:    result,
	}
	data, err := json.Marshal(record)
	if err == nil {
		err = h.Scans.Save(context.WithoutCancel(ctx), store.Scan{ID: record.ID, Kind: kind, ScannedAt: record.ScannedAt, Record: data})
	}
	if err != nil {
		log.Printf("store: saving scan %s failed: %v", record.ID, err)
		return record, err
	}
	h.maybePrune()
	return record, nil
}

// maybePrune applies the retention rules in the background, at most once an
// hour per process: in practice, at the first save after each wake-up.
func (h *Handler) maybePrune() {
	h.pruneMu.Lock()
	due := time.Since(h.lastPrune) >= time.Hour
	if due {
		h.lastPrune = time.Now()
	}
	h.pruneMu.Unlock()
	if !due {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := h.Scans.Prune(ctx, time.Now()); err != nil {
			log.Printf("store: pruning failed: %v", err)
		}
	}()
}

// AttachReport saves a pull request scan's report, byte for byte as it was
// hashed, and adds its digest and anchor to the scan's saved record.
func (h *Handler) AttachReport(ctx context.Context, rec *ScanRecord, data []byte, info ReportInfo) error {
	updated := *rec
	updated.Report = &info
	record, err := json.Marshal(&updated)
	if err == nil {
		err = h.Scans.SetReport(context.WithoutCancel(ctx), rec.ID, record, data)
	}
	if err != nil {
		log.Printf("store: saving the report of scan %s failed: %v", rec.ID, err)
	}
	return err
}

// GetReport serves the CycloneDX report of a scan, byte for byte as it was
// hashed and anchored, so `depscan verify` can check it.
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var data []byte
	err := store.ErrNotFound
	if validID(id) {
		data, err = h.Scans.Report(r.Context(), id)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no report for this scan (only pull request scans have one)")
		return
	case err != nil:
		storeFailed(w, r, "reading the report of scan "+id, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="report.cdx.json"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(data); err != nil {
		log.Printf("writing report %s: %v", id, err)
	}
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var s store.Scan
	err := store.ErrNotFound
	if validID(id) {
		s, err = h.Scans.Get(r.Context(), id)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "scan not found")
	case err != nil:
		storeFailed(w, r, "reading scan "+id, err)
	default:
		writeRecord(w, s.Record)
	}
}

// ListScans returns the newest scans. Only a local server lists them; on a
// public one, each scan opens through its own link.
func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	if !h.AllowList {
		writeError(w, http.StatusNotFound, "the scan list is only available on a local server; open a scan through its link")
		return
	}
	scans, err := h.Scans.List(r.Context(), listLimit)
	if err != nil {
		storeFailed(w, r, "listing scans", err)
		return
	}
	records := make([]json.RawMessage, len(scans))
	for i, s := range scans {
		records[i] = s.Record
	}
	writeJSON(w, http.StatusOK, records)
}
