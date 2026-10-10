package api

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strings"
	"time"
)

// The dashboard lives in web/: index.html plus the CSS and JS files it loads
// from /assets/. Everything is compiled into the binary with go:embed, so the
// server is still one file to ship and needs no Node build step.
//
//go:embed web/index.html
var indexHTML string

//go:embed web
var webFS embed.FS

// asset is one static file, read and hashed once at startup.
type asset struct {
	body  []byte
	ctype string
	etag  string
}

// assetTypes is spelled out instead of using mime.TypeByExtension, which
// reads the Windows registry and can map .js to text/plain.
var assetTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
	".svg": "image/svg+xml",
}

var assets = loadAssets(webFS, "web")

// loadAssets indexes the servable files directly inside dir. index.html is
// not one of them: it is served by Dashboard with the scan root filled in.
func loadAssets(fsys fs.FS, dir string) map[string]asset {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		panic("api: reading embedded web files: " + err.Error()) // fixed at build time
	}
	out := make(map[string]asset, len(entries))
	for _, e := range entries {
		ctype, ok := assetTypes[path.Ext(e.Name())]
		if e.IsDir() || !ok {
			continue
		}
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			panic("api: reading embedded " + e.Name() + ": " + err.Error())
		}
		sum := sha256.Sum256(body)
		out[e.Name()] = asset{body: body, ctype: ctype, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
	}
	return out
}

// Dashboard serves the UI with the scan root filled in, so the page can show
// which folders are allowed and suggest a matching path.
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	// "GET /" matches every path the mux does not know; only "/" is the page.
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	// json.Marshal escapes <, > and &, so the value is safe inside <script>.
	root, err := json.Marshal(h.scanRoot)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encoding scan root")
		return
	}
	page := strings.Replace(indexHTML, "__SCAN_ROOT_JSON__", string(root), 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write([]byte(page)); err != nil {
		log.Printf("writing dashboard: %v", err)
	}
}

// Asset serves the dashboard's CSS and JS from /assets/{name}. Each response
// carries a content-hash ETag, so a reload revalidates with a 304 instead of
// downloading the file again, and a new build is picked up at once.
func (h *Handler) Asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	a, ok := assets[name]
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", a.ctype)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", a.etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(a.body))
}
