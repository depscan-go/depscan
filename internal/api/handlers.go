package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
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
	engine *scan.Engine
	mu     sync.RWMutex
	scans  map[string]*ScanRecord
}

func New(engine *scan.Engine) *Handler {
	return &Handler{
		engine: engine,
		scans:  make(map[string]*ScanRecord),
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
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

	result, err := h.engine.Run(r.Context(), req.Path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	record := &ScanRecord{
		ID:        newID(),
		Path:      req.Path,
		ScannedAt: time.Now().UTC(),
		Result:    result,
	}

	h.mu.Lock()
	h.scans[record.ID] = record
	h.mu.Unlock()

	status := http.StatusOK
	if len(result.Violations) > 0 {
		status = http.StatusUnprocessableEntity
	}

	writeJSON(w, status, record)
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	// Extract {id} from the URL path manually (no chi dependency in handler)
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

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DepScan</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #070910; --panel: rgba(20,24,38,.72); --panel-solid: #121626; --panel-2: #1a2036;
      --line: rgba(255,255,255,.08); --line-2: rgba(255,255,255,.14);
      --text: #eef0fa; --mute: #8e96b3; --dim: #5d6585;
      --accent: #8b7bff; --accent-2: #38d0f5; --ok: #3ddc97; --warn: #ffb454; --bad: #ff5d73;
      --sans: "Sora", system-ui, -apple-system, "Segoe UI", sans-serif;
      --mono: "JetBrains Mono", ui-monospace, "Cascadia Code", Consolas, monospace;
      --ease: cubic-bezier(.2,.8,.2,1);
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body { margin: 0; min-height: 100vh; font-family: var(--sans); color: var(--text); background: var(--bg); overflow-x: hidden; -webkit-font-smoothing: antialiased; }
 
    /* ambient background: drifting glows + faint grid fading out */
    .bg { position: fixed; inset: 0; z-index: -1; overflow: hidden; pointer-events: none; }
    .bg i { position: absolute; border-radius: 50%; filter: blur(120px); opacity: .26; }
    .bg i:nth-child(1) { width: 55vmax; height: 55vmax; background: var(--accent); top: -22vmax; left: -14vmax; animation: d1 28s ease-in-out infinite alternate; }
    .bg i:nth-child(2) { width: 50vmax; height: 50vmax; background: var(--accent-2); bottom: -26vmax; right: -16vmax; opacity: .18; animation: d2 34s ease-in-out infinite alternate; }
    .bg::after { content: ""; position: absolute; inset: 0;
      background-image: linear-gradient(var(--line) 1px, transparent 1px), linear-gradient(90deg, var(--line) 1px, transparent 1px);
      background-size: 56px 56px; opacity: .35;
      -webkit-mask-image: radial-gradient(70% 55% at 50% 0%, #000, transparent); mask-image: radial-gradient(70% 55% at 50% 0%, #000, transparent); }
    @keyframes d1 { to { transform: translate(16vmax, 10vmax) scale(1.15); } }
    @keyframes d2 { to { transform: translate(-14vmax, -9vmax) scale(1.1); } }
 
    .wrap { max-width: 1040px; margin: 0 auto; padding: 56px 24px 90px; }
 
    /* header */
    header { display: flex; align-items: center; gap: 16px; }
    .logo { width: 50px; height: 50px; flex: none; filter: drop-shadow(0 6px 18px rgba(139,123,255,.55)); }
    h1 { margin: 0; font-size: 34px; font-weight: 700; letter-spacing: -.03em;
      background: linear-gradient(120deg, #fff 30%, #b9b0ff 70%, var(--accent-2)); -webkit-background-clip: text; background-clip: text; color: transparent; }
    .tagline { color: var(--mute); margin: 8px 0 32px; font-size: 14px; }
 
    /* scan bar */
    .scanbar { display: flex; gap: 8px; padding: 7px; border-radius: 18px; background: var(--panel); border: 1px solid var(--line);
      backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); transition: border-color .25s, box-shadow .3s; }
    .scanbar:focus-within { border-color: rgba(139,123,255,.7); box-shadow: 0 0 0 4px rgba(139,123,255,.15), 0 18px 50px -18px rgba(139,123,255,.6); }
    .scanbar svg { width: 20px; height: 20px; align-self: center; margin-left: 12px; color: var(--dim); flex: none; }
    .scanbar input { flex: 1; min-width: 0; background: transparent; border: 0; outline: 0; color: var(--text); font: 500 15px var(--mono); padding: 13px 8px; }
    .scanbar input::placeholder { color: var(--dim); }
    .btn { border: 0; border-radius: 12px; padding: 0 26px; cursor: pointer; font: 600 14px var(--sans); color: #070910;
      background: linear-gradient(135deg, var(--accent), var(--accent-2)); transition: transform .15s, filter .2s, box-shadow .25s; }
    .btn:hover { filter: brightness(1.12); box-shadow: 0 8px 26px -8px var(--accent); }
    .btn:active { transform: scale(.97); }
    .btn:disabled { opacity: .55; cursor: progress; }
    :focus-visible { outline: 2px solid var(--accent-2); outline-offset: 2px; }
 
    /* loading */
    .spinner { display: none; margin: 30px 0; }
    .spinner .txt { color: var(--mute); font-size: 13px; margin-bottom: 12px; }
    .track { height: 4px; border-radius: 4px; background: var(--panel-solid); overflow: hidden; position: relative; }
    .track::after { content: ""; position: absolute; inset: 0 auto 0 0; width: 35%; border-radius: 4px;
      background: linear-gradient(90deg, transparent, var(--accent), var(--accent-2), transparent); animation: beam 1.2s ease-in-out infinite; }
    @keyframes beam { from { transform: translateX(-100%); } to { transform: translateX(300%); } }
    .skel { margin-top: 22px; display: grid; gap: 12px; }
    .skel div { height: 74px; border-radius: 16px; background: linear-gradient(100deg, var(--panel-solid) 30%, var(--panel-2) 50%, var(--panel-solid) 70%); background-size: 200% 100%; animation: sh 1.4s linear infinite; }
    @keyframes sh { to { background-position: -200% 0; } }
 
    #output { margin-top: 30px; }
 
    /* verdict: gradient-bordered hero card */
    .verdict { display: flex; align-items: center; gap: 28px; padding: 26px 30px; border-radius: 22px; position: relative; overflow: hidden;
      border: 1px solid transparent; animation: rise .7s var(--ease) both;
      background: linear-gradient(var(--panel-solid), var(--panel-solid)) padding-box, linear-gradient(135deg, var(--vc), rgba(255,255,255,.06) 55%) border-box; }
    .verdict::before { content: ""; position: absolute; inset: 0; background: radial-gradient(55% 140% at 0% 50%, var(--vc), transparent 70%); opacity: .14; pointer-events: none; }
    .verdict.pass { --vc: var(--ok); } .verdict.fail { --vc: var(--bad); }
    .ring { width: 124px; height: 124px; flex: none; position: relative; }
    .ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
    .ring .tr { stroke: rgba(255,255,255,.07); }
    .ring .fg { stroke: var(--vc); stroke-linecap: round; stroke-dasharray: 326.7; stroke-dashoffset: 326.7; transition: stroke-dashoffset 1.6s var(--ease); filter: drop-shadow(0 0 8px var(--vc)); }
    .ring .pct { position: absolute; inset: 0; display: grid; place-items: center; text-align: center; font-weight: 700; font-size: 26px; letter-spacing: -.02em; }
    .ring .pct small { display: block; font-weight: 500; font-size: 10px; color: var(--mute); letter-spacing: 0; margin-top: -3px; }
    .vtxt { min-width: 0; flex: 1; position: relative; }
    .verdict h2 { margin: 0 0 6px; font-size: 24px; letter-spacing: -.02em; }
    .verdict p { margin: 0; color: var(--mute); font-size: 14px; line-height: 1.55; }
    .vact { position: relative; display: flex; gap: 8px; flex: none; }
    .ghost { border: 1px solid var(--line-2); background: rgba(255,255,255,.04); color: var(--text); border-radius: 11px; padding: 10px 16px; cursor: pointer;
      font: 500 13px var(--sans); transition: background .2s, border-color .2s, transform .15s; }
    .ghost:hover { background: rgba(255,255,255,.09); border-color: rgba(255,255,255,.26); }
    .ghost:active { transform: scale(.97); }
 
    /* stats */
    .summary { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 14px; margin: 16px 0 0; }
    .stat { padding: 18px 20px; border-radius: 18px; background: var(--panel); border: 1px solid var(--line); position: relative; overflow: hidden;
      backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); animation: rise .7s var(--ease) both; transition: border-color .25s, transform .25s var(--ease); }
    .stat:nth-child(1) { animation-delay: .08s } .stat:nth-child(2) { animation-delay: .16s } .stat:nth-child(3) { animation-delay: .24s } .stat:nth-child(4) { animation-delay: .32s }
    .stat::before { content: ""; position: absolute; left: 20px; right: 20px; top: 0; height: 2px; border-radius: 0 0 4px 4px; background: var(--c); box-shadow: 0 0 18px var(--c); }
    .stat.click { cursor: pointer; } .stat.click:hover { transform: translateY(-3px); border-color: var(--line-2); }
    .stat-num { font-size: 38px; font-weight: 700; letter-spacing: -.04em; color: var(--c); font-variant-numeric: tabular-nums; line-height: 1.1; }
    .stat-label { font-size: 12px; color: var(--mute); margin-top: 4px; }
    @keyframes rise { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: none; } }
 
    /* tabs */
    .tabs { display: inline-flex; gap: 4px; padding: 5px; margin: 34px 0 18px; border-radius: 14px; background: var(--panel); border: 1px solid var(--line); max-width: 100%; overflow-x: auto; }
    .tab { border: 0; background: transparent; color: var(--mute); border-radius: 10px; padding: 9px 16px; cursor: pointer; white-space: nowrap;
      font: 500 13px var(--sans); display: flex; align-items: center; gap: 8px; transition: color .2s, background .25s; }
    .tab:hover { color: var(--text); }
    .tab.on { color: var(--text); background: var(--panel-2); box-shadow: inset 0 0 0 1px var(--line-2); }
    .tab .n { font: 600 11px var(--mono); padding: 2px 8px; border-radius: 20px; background: rgba(255,255,255,.07); color: var(--mute); }
    .tab.t-bad .n { background: rgba(255,93,115,.16); color: var(--bad); }
    .tab.t-warn .n { background: rgba(255,180,84,.16); color: var(--warn); }
    .panel { display: none; } .panel.on { display: block; animation: fade .35s var(--ease) both; }
    @keyframes fade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
 
    /* issue cards */
    .issue { display: flex; gap: 14px; padding: 16px 18px; margin-bottom: 10px; border-radius: 16px; background: var(--panel); border: 1px solid var(--line);
      position: relative; overflow: hidden; transition: transform .25s var(--ease), border-color .25s, background .25s; }
    .issue::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--rc); box-shadow: 0 0 16px var(--rc); }
    .issue:hover { transform: translateX(4px); border-color: var(--line-2); background: rgba(26,32,54,.8); }
    .issue.block { --rc: var(--bad); } .issue.warn { --rc: var(--warn); }
    .ico { width: 34px; height: 34px; flex: none; display: grid; place-items: center; border-radius: 10px; background: color-mix(in srgb, var(--rc) 16%, transparent); color: var(--rc); }
    .ico svg { width: 18px; height: 18px; }
    .ibody { min-width: 0; flex: 1; }
    .iname { font: 600 14px var(--mono); overflow-wrap: anywhere; }
    .iname em { font-style: normal; color: var(--mute); font-weight: 400; }
    .reason { color: var(--mute); font-size: 13px; margin-top: 6px; line-height: 1.55; overflow-wrap: anywhere; }
    .tag { flex: none; align-self: flex-start; font: 600 10px var(--mono); padding: 4px 9px; border-radius: 6px; letter-spacing: .04em; }
    .block .tag { background: rgba(255,93,115,.15); color: var(--bad); } .warn .tag { background: rgba(255,180,84,.15); color: var(--warn); }
 
    /* dependency table */
    .tools { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }
    .search { flex: 1; min-width: 200px; position: relative; }
    .search svg { position: absolute; left: 13px; top: 50%; transform: translateY(-50%); width: 16px; height: 16px; color: var(--dim); }
    .search input { width: 100%; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; color: var(--text); font: 400 13px var(--mono); padding: 11px 14px 11px 38px; outline: 0; transition: border-color .2s, box-shadow .2s; }
    .search input:focus { border-color: rgba(139,123,255,.7); box-shadow: 0 0 0 3px rgba(139,123,255,.14); }
    .seg { display: inline-flex; padding: 4px; gap: 2px; border-radius: 12px; background: var(--panel); border: 1px solid var(--line); }
    .chip { border: 0; background: transparent; color: var(--mute); border-radius: 9px; padding: 8px 14px; font: 500 12px var(--sans); cursor: pointer; transition: all .2s; }
    .chip:hover { color: var(--text); }
    .chip.on { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #070910; font-weight: 600; }
    .table { border-radius: 16px; border: 1px solid var(--line); background: var(--panel); overflow: hidden; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
    .trow { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,260px) 104px; gap: 16px; align-items: center; padding: 12px 20px; border-top: 1px solid var(--line); transition: background .2s; }
    .trow:first-child { border-top: 0; }
    .thead { font: 500 11px var(--sans); color: var(--dim); padding: 12px 20px; background: rgba(255,255,255,.025); }
    .trow:not(.thead):hover { background: rgba(255,255,255,.035); }
    .pk { font: 500 13px var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .vr { font: 400 12px var(--mono); color: var(--mute); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .pill { justify-self: end; font: 600 11px var(--mono); padding: 3px 10px; border-radius: 20px; }
    .p-direct { background: rgba(139,123,255,.18); color: #b4a9ff; } .p-trans { background: rgba(255,255,255,.06); color: var(--mute); }
    .more { display: block; margin: 16px auto 0; }
    .empty { color: var(--mute); font-size: 13px; padding: 28px 20px; text-align: center; }
    .clean { text-align: center; padding: 44px 20px; color: var(--mute); font-size: 14px; border: 1px dashed var(--line-2); border-radius: 16px; }
    .clean b { display: block; color: var(--ok); font-size: 16px; margin-bottom: 6px; }
 
    .foot { margin-top: 40px; color: var(--dim); font: 400 12px var(--mono); display: flex; flex-wrap: wrap; gap: 6px 14px; }
    a { color: var(--accent-2); text-decoration: none; } a:hover { text-decoration: underline; }
    .error { color: var(--bad); background: rgba(255,93,115,.08); border: 1px solid rgba(255,93,115,.3); padding: 16px 18px; border-radius: 14px; font-size: 14px; }
    pre.raw { color: var(--mute); font: 12px var(--mono); overflow: auto; }
 
    @media (max-width: 760px) {
      .wrap { padding: 36px 16px 70px; }
      .summary { grid-template-columns: repeat(2, minmax(0,1fr)); }
      .verdict { flex-direction: column; text-align: center; align-items: center; }
      .scanbar { flex-wrap: wrap; } .scanbar input { flex-basis: 70%; } .btn { padding: 12px 22px; width: 100%; }
      .trow { grid-template-columns: minmax(0,1fr) 90px; } .trow .vr { display: none; } .thead .vr { display: none; }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
  </style>
</head>
<body>
  <div class="bg"><i></i><i></i></div>
  <div class="wrap">
    <header>
      <svg class="logo" viewBox="0 0 48 48" fill="none" aria-hidden="true">
        <defs><linearGradient id="g" x1="0" y1="0" x2="48" y2="48"><stop stop-color="#8b7bff"/><stop offset="1" stop-color="#38d0f5"/></linearGradient></defs>
        <path d="M24 4l16 6v12c0 10-7 18-16 22C15 40 8 32 8 22V10l16-6z" stroke="url(#g)" stroke-width="2.5" stroke-linejoin="round" fill="rgba(139,123,255,.08)"/>
        <circle cx="23" cy="23" r="6" stroke="url(#g)" stroke-width="2.5"/>
        <path d="M27.5 27.5L33 33" stroke="url(#g)" stroke-width="2.5" stroke-linecap="round"/>
      </svg>
      <h1>DepScan</h1>
    </header>
    <p class="tagline">Dependency vulnerability scanner powered by OSV.dev</p>
 
    <div class="scanbar">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>
      <input id="path" placeholder="repo path, e.g. ./testdata" autocomplete="off" spellcheck="false" />
      <button class="btn" id="runBtn" onclick="runScan()">Run Scan</button>
    </div>
 
    <div class="spinner" id="spinner">
      <div class="txt">Scanning dependencies. This may take a few seconds.</div>
      <div class="track"></div>
      <div class="skel"><div></div><div></div><div></div></div>
    </div>
    <div id="output"></div>
  </div>
 
  <script>
    var DEPS = [], DATA = null;
    var depFilter = 'all', depShown = 50, PAGE = 50;
 
    function esc(s) {
      return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
      });
    }
 
    document.getElementById('path').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') runScan();
    });
 
    async function runScan() {
      const path = document.getElementById('path').value.trim();
      if (!path) return;
 
      const btn = document.getElementById('runBtn');
      btn.disabled = true;
      document.getElementById('spinner').style.display = 'block';
      document.getElementById('output').innerHTML = '';
 
      try {
        const res = await fetch('/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path })
        });
        const data = await res.json();
        document.getElementById('spinner').style.display = 'none';
        btn.disabled = false;
        if (data.error) {
          document.getElementById('output').innerHTML =
            '<p class="error">Server error: ' + esc(data.error) + '</p>';
          return;
        }
        if (!data.result) {
          document.getElementById('output').innerHTML =
            '<pre class="raw">' + esc(JSON.stringify(data, null, 2)) + '</pre>';
          return;
        }
        render(data);
      } catch (err) {
        document.getElementById('spinner').style.display = 'none';
        btn.disabled = false;
        document.getElementById('output').innerHTML =
          '<p class="error">Error: ' + esc(err.message) + '</p>';
      }
    }
 
    function sev(s) {
      const map = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'moderate', MEDIUM: 'moderate' };
      return map[s] || '';
    }
 
    var ICON_BAD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>';
    var ICON_WARN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/></svg>';
    var ICON_SEARCH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></svg>';
 
    function stat(num, label, color, tab) {
      return '<div class="stat' + (tab ? ' click' : '') + '" style="--c:' + color + '"' + (tab ? ' onclick="switchTab(\'' + tab + '\')"' : '') + '>' +
        '<div class="stat-num" data-count="' + num + '">0</div>' +
        '<div class="stat-label">' + label + '</div></div>';
    }
 
    function issueRows(list, cls, label, icon) {
      let h = '';
      for (const v of list) {
        h += '<div class="issue ' + cls + '"><div class="ico">' + icon + '</div>' +
          '<div class="ibody"><div class="iname">' + esc(v.Dep.Name) + '<em>@' + esc(v.Dep.Version) + '</em></div>' +
          '<div class="reason">' + esc(v.Reason) + '</div></div>' +
          '<span class="tag">' + label + '</span></div>';
      }
      return h;
    }
 
    function render(data) {
      DATA = data;
      const r = data.result;
      const deps = r.Deps || [], findings = r.Findings || [];
      const viol = r.Violations || [], warns = r.Warnings || [];
      const passed = viol.length === 0;
      DEPS = deps; depFilter = 'all'; depShown = PAGE;
 
      // share of dependencies with no violation or warning
      const flagged = {};
      viol.concat(warns).forEach(function (x) { flagged[x.Dep.Name + '@' + x.Dep.Version] = 1; });
      const total = deps.length;
      const clean = total ? Math.round(((total - Object.keys(flagged).length) / total) * 100) : 100;
 
      let html = '';
 
      // Verdict
      html += '<div class="verdict ' + (passed ? 'pass' : 'fail') + '">' +
        '<div class="ring"><svg viewBox="0 0 120 120">' +
        '<circle class="tr" cx="60" cy="60" r="52" fill="none" stroke-width="9"/>' +
        '<circle class="fg" cx="60" cy="60" r="52" fill="none" stroke-width="9" data-pct="' + clean + '"/></svg>' +
        '<div class="pct"><div>' + clean + '%<small>clean</small></div></div></div>' +
        '<div class="vtxt"><h2>' + (passed ? 'Scan passed' : 'Scan failed') + '</h2><p>' +
        (passed ? 'No policy violations found.' : viol.length + ' violation(s) found. This build would be blocked.') +
        '</p></div>' +
        '<div class="vact"><button class="ghost" onclick="exportJSON()">Export JSON</button></div></div>';
 
      // Summary stats
      html += '<div class="summary">';
      html += stat(deps.length, 'Dependencies', '#8b7bff', 'deps');
      html += stat(findings.length, 'Findings', '#38d0f5');
      html += stat(viol.length, 'Violations', viol.length > 0 ? '#ff5d73' : '#3ddc97', 'viol');
      html += stat(warns.length, 'Warnings', warns.length > 0 ? '#ffb454' : '#3ddc97', 'warn');
      html += '</div>';
 
      // Tabs
      html += '<div class="tabs" role="tablist">' +
        '<button class="tab t-bad" data-t="viol" onclick="switchTab(\'viol\')">Violations <span class="n">' + viol.length + '</span></button>' +
        '<button class="tab t-warn" data-t="warn" onclick="switchTab(\'warn\')">Warnings <span class="n">' + warns.length + '</span></button>' +
        '<button class="tab" data-t="deps" onclick="switchTab(\'deps\')">Dependencies <span class="n">' + deps.length + '</span></button></div>';
 
      // Panels
      html += '<div class="panel" data-p="viol">' +
        (viol.length ? issueRows(viol, 'block', 'BLOCK', ICON_BAD) : '<div class="clean"><b>No violations</b>Every dependency meets your policy.</div>') + '</div>';
      html += '<div class="panel" data-p="warn">' +
        (warns.length ? issueRows(warns, 'warn', 'WARN', ICON_WARN) : '<div class="clean"><b>No warnings</b>Nothing to review.</div>') + '</div>';
      html += '<div class="panel" data-p="deps">' +
        '<div class="tools"><div class="search">' + ICON_SEARCH + '<input id="depSearch" placeholder="Filter packages" oninput="depShown=PAGE;renderDeps()" /></div>' +
        '<div class="seg"><button class="chip on" data-f="all" onclick="setFilter(this)">All</button>' +
        '<button class="chip" data-f="direct" onclick="setFilter(this)">Direct</button>' +
        '<button class="chip" data-f="trans" onclick="setFilter(this)">Transitive</button></div></div>' +
        '<div class="table" id="depList"></div><button class="ghost more" id="moreBtn" onclick="depShown+=PAGE;renderDeps()" style="display:none"></button></div>';
 
      // Scan ID
      html += '<div class="foot"><span>Scan ID: <a href="/scans/' + esc(data.id) + '">' + esc(data.id) + '</a></span><span>' +
        esc(new Date(data.scanned_at).toLocaleString()) + '</span></div>';
 
      document.getElementById('output').innerHTML = html;
      switchTab(viol.length ? 'viol' : (warns.length ? 'warn' : 'deps'));
      renderDeps();
      animate();
    }
 
    function switchTab(t) {
      document.querySelectorAll('.tab').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-t') === t); });
      document.querySelectorAll('.panel').forEach(function (p) { p.classList.toggle('on', p.getAttribute('data-p') === t); });
    }
 
    function setFilter(btn) {
      depFilter = btn.getAttribute('data-f'); depShown = PAGE;
      document.querySelectorAll('.chip').forEach(function (c) { c.classList.remove('on'); });
      btn.classList.add('on');
      renderDeps();
    }
 
    function renderDeps() {
      const q = (document.getElementById('depSearch').value || '').toLowerCase();
      const list = DEPS.filter(function (d) {
        if (depFilter === 'direct' && !d.Direct) return false;
        if (depFilter === 'trans' && d.Direct) return false;
        return !q || String(d.Name).toLowerCase().indexOf(q) !== -1;
      });
      let h = '<div class="trow thead"><span>Package</span><span class="vr">Version</span><span style="justify-self:end">Type</span></div>';
      list.slice(0, depShown).forEach(function (d) {
        h += '<div class="trow"><span class="pk" title="' + esc(d.Name) + '">' + esc(d.Name) + '</span>' +
          '<span class="vr" title="' + esc(d.Version) + '">' + esc(d.Version) + '</span>' +
          '<span class="pill ' + (d.Direct ? 'p-direct">direct' : 'p-trans">transitive') + '</span></div>';
      });
      if (!list.length) h += '<div class="empty">No packages match this filter.</div>';
      document.getElementById('depList').innerHTML = h;
      const more = document.getElementById('moreBtn');
      const left = list.length - depShown;
      more.style.display = left > 0 ? 'block' : 'none';
      more.textContent = 'Show ' + Math.min(left, PAGE) + ' more (' + left + ' remaining)';
    }
 
    function exportJSON() {
      const blob = new Blob([JSON.stringify(DATA, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'depscan-' + (DATA.id || 'report') + '.json';
      a.click();
      URL.revokeObjectURL(a.href);
    }
 
    // count-up numbers + ring fill
    function animate() {
      document.querySelectorAll('[data-count]').forEach(function (el) {
        const target = parseInt(el.getAttribute('data-count'), 10) || 0;
        const start = performance.now(), dur = 900;
        function tick(now) {
          const t = Math.min((now - start) / dur, 1);
          el.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
          if (t < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
      });
      const fg = document.querySelector('.ring .fg');
      if (fg) {
        const pct = parseInt(fg.getAttribute('data-pct'), 10) || 0;
        requestAnimationFrame(function () {
          requestAnimationFrame(function () { fg.style.strokeDashoffset = 326.7 * (1 - pct / 100); });
        });
      }
    }
  </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}
