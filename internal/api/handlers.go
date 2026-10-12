package api

import (
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

type Handler struct {
	engine   *scan.Engine
	scanRoot string
	mu       sync.RWMutex
	scans    map[string]*ScanRecord
	reports  map[string][]byte // report bytes by scan ID
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
		scans:    make(map[string]*ScanRecord),
		reports:  make(map[string][]byte),
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

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {

		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

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

	record := h.Record(req.Path, result)

	status := http.StatusOK
	if len(result.Violations) > 0 {
		status = http.StatusUnprocessableEntity
	}

	writeJSON(w, status, record)
}

func (h *Handler) Record(label string, result *model.ScanResult) *ScanRecord {
	record := &ScanRecord{
		ID:        newID(),
		Path:      label,
		ScannedAt: time.Now().UTC(),
		Result:    result,
	}
	h.mu.Lock()
	h.scans[record.ID] = record
	h.mu.Unlock()
	return record
}

// AttachReport keeps a scan's report bytes and anchor details with its
// record, until the server restarts.
func (h *Handler) AttachReport(id string, data []byte, info ReportInfo) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	rec, ok := h.scans[id]
	if !ok {
		return false
	}
	// Records are never changed in place: a request may be encoding the old one.
	updated := *rec
	updated.Report = &info
	h.scans[id] = &updated
	h.reports[id] = data
	return true
}

// GetReport serves the CycloneDX report of a scan, byte for byte as it was
// hashed and anchored, so `depscan verify` can check it.
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.mu.RLock()
	data, ok := h.reports[id]
	h.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "no report for this scan (reports are kept for pull request scans until the server restarts)")
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
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing scan id")
		return
	}

	h.mu.RLock()
	record, ok := h.scans[id]
	h.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}

	writeJSON(w, http.StatusOK, record)
}

func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	records := make([]*ScanRecord, 0, len(h.scans))
	for _, rec := range h.scans {
		records = append(records, rec)
	}
	h.mu.RUnlock()

	writeJSON(w, http.StatusOK, records)
}
