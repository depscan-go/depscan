package api

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/depscan-go/depscan/internal/store"
)

// Scanning a folder picked in the browser.
//
// Browsers never tell a page where a folder lives on disk, so the dashboard
// reads the lockfiles itself and sends only those. ScanUpload writes them to
// a temporary folder with the same layout, runs the normal scan engine on it
// and deletes the folder again. Nothing else on the machine is read, so this
// works for any folder the user can open, on any drive, and inside Docker.

const (
	maxUploadFiles   = 500
	maxUploadPathLen = 512
	maxUploadNameLen = 120
	// maxUploadsAtOnce is how many uploads are scanned at the same time. Each
	// one can use a few times its unpacked size in memory, so more would wait
	// in line on a 1 GiB app; instead they get 429 and try again.
	maxUploadsAtOnce = 2
)

var (
	// maxUploadUnpacked caps the request after gzip is undone. The request as
	// sent is already capped at 1 MB by the MaxBytes middleware. Real lockfiles
	// are far smaller: a large monorepo's package-lock.json is about 2 MB.
	maxUploadUnpacked int64 = 10 << 20

	// uploadTempDir is where scans are staged; "" means the system default.
	// Tests point it at a private folder.
	uploadTempDir = ""
)

// uploadable lists the lockfile names internal/parser understands. Anything
// else is rejected instead of being written to disk and silently ignored.
// Keep it in sync with the parser registry and with LOCKFILES in picker.js.
var uploadable = map[string]bool{
	"go.mod":            true,
	"package-lock.json": true,
}

type uploadFile struct {
	Path    string `json:"path"`    // relative, forward slashes, e.g. "web/package-lock.json"
	Content string `json:"content"` // the file as text
}

type uploadRequest struct {
	Name  string       `json:"name"` // the folder's name, used as the scan label
	Files []uploadFile `json:"files"`
}

// ScanUpload handles POST /scans/upload. The body is JSON, optionally sent
// with Content-Encoding: gzip so large lockfiles fit under the 1 MB limit.
// It answers like POST /scans: 200 when the policy passes, 422 when it does
// not, with the same scan record.
func (h *Handler) ScanUpload(w http.ResponseWriter, r *http.Request) {
	// The server listens on the user's machine, so a page on another site must
	// not be able to make the browser post files here. Browsers send
	// Sec-Fetch-Site on every request; requiring JSON also forces a CORS
	// preflight for cross-origin callers, which this server never approves.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeError(w, http.StatusForbidden, "uploads from other sites are not allowed")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	// Take a slot before reading the body, so a burst of uploads can't run the
	// app out of memory. No free slot: try again in a few seconds.
	select {
	case h.uploads <- struct{}{}:
		defer func() { <-h.uploads }()
	default:
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "the server is busy with other uploads; try again in a few seconds")
		return
	}

	body := io.Reader(r.Body)
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			writeError(w, uploadReadStatus(err), uploadReadMessage(err, "body is not valid gzip"))
			return
		}
		defer func() { _ = zr.Close() }() // reading only
		body = zr
	default:
		writeError(w, http.StatusUnsupportedMediaType, "unsupported Content-Encoding: "+enc)
		return
	}

	limited := &io.LimitedReader{R: body, N: maxUploadUnpacked + 1}
	var req uploadRequest
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
		if limited.N <= 0 {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("lockfiles are larger than %d MB unpacked", maxUploadUnpacked>>20))
			return
		}
		writeError(w, uploadReadStatus(err), uploadReadMessage(err, "invalid JSON body"))
		return
	}

	if err := validateUpload(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := uploadLabel(req.Name)

	dir, err := os.MkdirTemp(uploadTempDir, "depscan-upload-")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create a temporary folder")
		return
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("upload: removing %s: %v", dir, err)
		}
	}()

	for _, f := range req.Files {
		dst := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			writeError(w, http.StatusBadRequest, "cannot stage "+f.Path+": "+err.Error())
			return
		}
		if err := os.WriteFile(dst, []byte(f.Content), 0o600); err != nil {
			writeError(w, http.StatusBadRequest, "cannot stage "+f.Path+": "+err.Error())
			return
		}
	}

	result, err := h.engine.Run(r.Context(), dir)
	if err != nil {
		// Errors can mention the temporary folder; show the folder's name instead.
		writeError(w, http.StatusInternalServerError, strings.ReplaceAll(err.Error(), dir, name))
		return
	}

	// A failed save is logged; the result is still the answer.
	record, _ := h.Record(r.Context(), store.Other, name, result)
	status := http.StatusOK
	if len(result.Violations) > 0 {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, record)
}

// validateUpload checks every path before anything touches the disk: relative,
// forward slashes only, no "." or ".." segments, a known lockfile name, and
// characters every operating system accepts.
func validateUpload(req *uploadRequest) error {
	if len(req.Files) == 0 {
		return errors.New("no lockfiles in the upload: send go.mod or package-lock.json files")
	}
	if len(req.Files) > maxUploadFiles {
		return fmt.Errorf("too many lockfiles: %d (the limit is %d)", len(req.Files), maxUploadFiles)
	}
	seen := make(map[string]bool, len(req.Files))
	for _, f := range req.Files {
		if err := checkUploadPath(f.Path); err != nil {
			return err
		}
		key := strings.ToLower(f.Path) // Windows and macOS folders ignore case
		if seen[key] {
			return fmt.Errorf("%q is in the upload twice", f.Path)
		}
		seen[key] = true
	}
	return nil
}

func checkUploadPath(p string) error {
	if p == "" || len(p) > maxUploadPathLen || !utf8.ValidString(p) {
		return fmt.Errorf("invalid file path %q", p)
	}
	if strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return fmt.Errorf("%q: paths must be relative, like web/package-lock.json", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." || strings.TrimSpace(seg) == "" {
			return fmt.Errorf("%q: path segments cannot be empty, \".\" or \"..\"", p)
		}
		for _, c := range seg {
			// \ and : are rejected so C:\ or ..\ can never mean anything here.
			if c < 0x20 || c == 0x7f || strings.ContainsRune(`\:<>"|?*`, c) {
				return fmt.Errorf("%q: unsupported character %q", p, c)
			}
		}
	}
	if !uploadable[path.Base(p)] {
		return fmt.Errorf("%q: only go.mod and package-lock.json files can be scanned", p)
	}
	return nil
}

// uploadLabel turns the folder name into a short, printable scan label.
func uploadLabel(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if r := []rune(name); len(r) > maxUploadNameLen {
		name = string(r[:maxUploadNameLen])
	}
	if name == "" {
		return "picked folder"
	}
	return name
}

func uploadReadStatus(err error) int {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func uploadReadMessage(err error, fallback string) string {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return fmt.Sprintf("upload is larger than %d bytes even compressed: scan this folder by path or with the depscan CLI", tooBig.Limit)
	}
	return fallback
}
