package api

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/depscan-go/depscan/internal/model"
	"github.com/depscan-go/depscan/internal/scan"
)

type ScanRecord struct {
	ID        string            `json:"id"`
	Path      string            `json:"path"`
	ScannedAt time.Time         `json:"scanned_at"`
	Result    *model.ScanResult `json:"result"`
}

type Handler struct {
	engine   *scan.Engine
	scanRoot string
	mu       sync.RWMutex
	scans    map[string]*ScanRecord
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

// dashboardHTML is the single-page UI. It lives in its own file so it can be
// edited with HTML/CSS tooling, and is compiled into the binary by go:embed.
//
//go:embed dashboard.html
var dashboardHTML string

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	root, err := json.Marshal(h.scanRoot)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding scan root")
		return
	}
	page := strings.Replace(dashboardHTML, "__SCAN_ROOT_JSON__", string(root), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write([]byte(page)); err != nil {
		log.Printf("writing dashboard: %v", err)
	}
}
