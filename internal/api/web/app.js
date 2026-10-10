/* DepScan dashboard: the Scan pane, the dependency skyline, and the router
   that switches between Scan and How it works. */
'use strict';
const ROOT = String(window.DEPSCAN_ROOT || '');
const SEP = ROOT.indexOf('\\') !== -1 ? '\\' : '/';
const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];
const SEV = {
  CRITICAL: { label: 'Critical', c: 'var(--critical)', t: 'var(--critical-t)' },
  HIGH:     { label: 'High',     c: 'var(--high)',     t: 'var(--high-t)' },
  MEDIUM:   { label: 'Medium',   c: 'var(--medium)',   t: 'var(--medium-t)' },
  LOW:      { label: 'Low',      c: 'var(--low)',      t: 'var(--low-t)' },
  UNKNOWN:  { label: 'Unrated',  c: 'var(--unknown)',  t: 'var(--unknown-t)' },
  NONE:     { label: 'No known issues', c: 'var(--clean)', t: 'var(--clean-t)' }
};
const STATUS = { block: 'Blocks the build', warn: 'Warning', allowed: 'Allowed by policy' };
const PAGE = 40;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sevOf = (s) => { s = String(s || '').toUpperCase(); if (s === 'MODERATE') return 'MEDIUM'; return SEV[s] ? s : 'UNKNOWN'; };
const rank = (s) => SEVS.indexOf(s);
const plural = (n, one, many) => n + ' ' + (n === 1 ? one : (many || one + 's'));
const words = (s) => String(s).split(' ').map((w, i) => '<span class="w"><span style="--i:' + i + '">' + esc(w) + '</span></span>').join(' ');
const nv = (v) => String(v).replace(/^v/, '');

let ui = { model: null, record: null, tab: 'fixes', q: '', showAllowed: false, shown: PAGE, depFilter: 'all', depQ: '', depShown: 60, open: new Set() };
let controller = null, timer = null;

/* ---------- storage (optional; the page works without it) ---------- */
function loadRecent() { try { return JSON.parse(localStorage.getItem('depscan.recent') || '[]'); } catch (e) { return []; } }
function saveRecent(p) {
  const list = [p].concat(loadRecent().filter((x) => x !== p)).slice(0, 6);
  try { localStorage.setItem('depscan.recent', JSON.stringify(list)); } catch (e) {}
  renderRecent();
}
function renderRecent() {
  const list = loadRecent();
  $('recent').innerHTML = list.length ? '<span>Recent</span>' + list.map((p) => '<button class="chip" type="button" title="' + esc(p) + '" data-path="' + esc(p) + '">' + esc(shortPath(p)) + '</button>').join('') : '';
}
function shortPath(p) {
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length > 2 ? '…' + SEP + parts.slice(-2).join(SEP) : p;
}

/* ---------- model ---------- */
function depKey(d) { return d.Ecosystem + '|' + d.Name + '@' + d.Version; }
function cmpVer(a, b) {
  const pa = String(a).split(/[.+-]/), pb = String(b).split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || '0', y = pb[i] || '0';
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    const c = nx && ny ? (parseInt(x, 10) - parseInt(y, 10)) : x.localeCompare(y);
    if (c) return c;
  }
  return 0;
}
function upgradeCmd(dep, v) {
  if (dep.Ecosystem === 'npm') return 'npm install ' + dep.Name + '@' + v;
  if (dep.Ecosystem === 'Go') return 'go get ' + dep.Name + '@v' + v.replace(/^v/, '');
  return dep.Name + '@' + v;
}

function buildModel(record) {
  const r = record.result || {};
  const deps = r.Deps || [], findings = r.Findings || [];
  const viol = r.Violations || [], warns = r.Warnings || [];
  const tag = (list) => new Set(list.filter((v) => v.Kind === 'vulnerability').map((v) => depKey(v.Dep) + '#' + String(v.Reason).split(' ')[0]));
  const blockSet = tag(viol), warnSet = tag(warns);

  const groups = new Map();
  for (const d of deps) groups.set(depKey(d), { dep: d, advs: [] });
  for (const f of findings) {
    const k = depKey(f.Dep);
    if (!groups.has(k)) groups.set(k, { dep: f.Dep, advs: [] });
    const id = k + '#' + f.VulnID;
    groups.get(k).advs.push({
      id: f.VulnID, aliases: f.Aliases || [], sev: sevOf(f.Severity), summary: f.Summary, fixed: f.FixedVersion,
      status: blockSet.has(id) ? 'block' : warnSet.has(id) ? 'warn' : 'allowed'
    });
  }

  const list = [];
  for (const [k, g] of groups) {
    g.key = k;
    g.advs.sort((a, b) => ['block', 'warn', 'allowed'].indexOf(a.status) - ['block', 'warn', 'allowed'].indexOf(b.status) || rank(a.sev) - rank(b.sev));
    g.worst = g.advs.reduce((w, a) => rank(a.sev) < rank(w) ? a.sev : w, 'NONE');
    g.status = g.advs.some((a) => a.status === 'block') ? 'block' : g.advs.some((a) => a.status === 'warn') ? 'warn' : g.advs.length ? 'allowed' : 'clean';
    const active = g.advs.filter((a) => a.status !== 'allowed');
    const pool = active.length ? active : g.advs;
    const fixes = pool.map((a) => a.fixed).filter(Boolean);
    g.fixTo = fixes.length ? fixes.sort(cmpVer)[fixes.length - 1] : '';
    g.unfixed = pool.filter((a) => !a.fixed).length;
    list.push(g);
  }
  const licenses = viol.filter((v) => v.Kind === 'license').map((v) => ({ dep: v.Dep, reason: v.Reason, status: 'block' }))
    .concat(warns.filter((v) => v.Kind === 'license').map((v) => ({ dep: v.Dep, reason: v.Reason, status: 'warn' })));

  return {
    deps, findings, groups: list, licenses,
    blockPkgs: list.filter((g) => g.status === 'block').length,
    warnPkgs: list.filter((g) => g.status === 'warn').length,
    vulnPkgs: list.filter((g) => g.advs.length).length,
    blocked: viol.length > 0
  };
}

/* ---------- scanning ---------- */
async function runScan(path) {
  path = (path || $('path').value).trim();
  if (!path) { $('path').focus(); return; }
  $('path').value = path;
  if (controller) controller.abort();
  controller = new AbortController();

  $('intro').hidden = true; $('result').hidden = true; $('error').innerHTML = '';
  $('loading').hidden = false; $('loadingPath').textContent = shortPath(path);
  $('runBtn').disabled = true;
  const t0 = performance.now();
  timer = setInterval(() => { $('elapsed').textContent = ((performance.now() - t0) / 1000).toFixed(1) + 's'; }, 100);

  try {
    const res = await fetch('/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path }), signal: controller.signal });
    let data;
    try { data = await res.json(); } catch (e) { throw new Error('The server answered with ' + res.status + ' and no JSON body.'); }
    if (data.error) { showError(data.error, path); return; }
    data._ms = performance.now() - t0;
    saveRecent(path);
    render(data);
  } catch (e) {
    if (e.name === 'AbortError') { $('intro').hidden = false; toast('Scan cancelled'); }
    else showError(e.message, path);
  } finally {
    clearInterval(timer); $('elapsed').textContent = '';
    $('loading').hidden = true; $('runBtn').disabled = false; controller = null;
  }
}

function showError(msg, path) {
  let title = 'The scan did not finish', body = esc(msg);
  if (/scan root/.test(msg)) {
    title = 'That folder is outside the scan root';
    body = 'DepScan only scans folders inside <code>' + esc(ROOT) + '</code>. Pick a project in there, or restart the server with <code>-scan-root</code> pointing at a parent folder.';
  } else if (/no such file|cannot find|not find|does not exist/i.test(msg)) {
    title = 'Folder not found';
    body = 'Nothing exists at <code>' + esc(path) + '</code>. Check the spelling, or paste the full path.';
  } else if (/OSV|querybatch|dial|timeout/i.test(msg)) {
    title = 'Could not reach OSV.dev';
    body = 'The vulnerability database did not respond. Check your connection and scan again.<br><code>' + esc(msg) + '</code>';
  }
  $('error').innerHTML = '<div class="alert appear" role="alert"><b>' + title + '</b><p>' + body + '</p></div>';
}

/* ---------- rendering ---------- */
function render(record) {
  if (sky) sky.destroy();
  ui.skyModeSet = false;
  ui.record = record; ui.model = buildModel(record); ui.sky = null;
  $('intro').hidden = true; $('error').innerHTML = '';
  ui.q = ''; ui.shown = PAGE; ui.depQ = ''; ui.depShown = 60; ui.depFilter = 'all'; ui.open = new Set();
  const m = ui.model;
  ui.tab = m.blockPkgs || m.warnPkgs ? 'fixes' : m.licenses.length ? 'licenses' : 'deps';

  let state, color, headline, sub;
  if (!m.deps.length) {
    state = 'Nothing to scan'; color = 'var(--unknown-t)';
    headline = 'No lockfiles found in this folder';
    sub = 'DepScan looks for <code>go.mod</code> and <code>package-lock.json</code> (npm 7 or newer). Other lockfiles are skipped.';
  } else if (m.blocked) {
    state = 'Blocked'; color = 'var(--critical-t)';
    headline = 'This build would be blocked';
    sub = plural(m.blockPkgs, 'package') + ' ' + (m.blockPkgs === 1 ? 'has' : 'have') + ' vulnerabilities your policy does not allow' + (m.licenses.some((l) => l.status === 'block') ? ', and some licenses are denied' : '') + '. Upgrade them to pass.';
  } else if (m.warnPkgs || m.licenses.length) {
    state = 'Passes with warnings'; color = 'var(--medium-t)';
    headline = 'Passes, with ' + plural(m.warnPkgs || m.licenses.length, 'package') + ' to review';
    sub = 'Nothing breaks your policy, but these are worth upgrading before they become blocking.';
  } else {
    state = 'Passes'; color = 'var(--clean-t)';
    headline = m.vulnPkgs ? 'Passes your policy' : 'No known vulnerabilities';
    sub = m.vulnPkgs ? plural(m.vulnPkgs, 'package') + ' ' + (m.vulnPkgs === 1 ? 'has' : 'have') + ' advisories below your policy threshold.' : 'Every dependency was checked against OSV.dev.';
  }

  const direct = m.deps.filter((d) => d.Direct).length;
  const secs = record._ms ? (record._ms / 1000).toFixed(1) + 's' : '—';
  const html =
    '<div class="verdict appear">' +
      '<div><div class="state fade" style="--sc:' + color + '">' + state + '</div><h2 class="words">' + words(headline) + '</h2>' +
      '<p class="sub fade" style="--d:380ms">' + sub + ' <span class="mono" style="font-size:13px">' + esc(record.path) + '</span></p></div>' +
      '<div class="actions fade" style="--d:450ms"><button class="ghost" type="button" id="exportBtn">Export JSON</button></div>' +
    '</div>' +
    (m.deps.length ? skyHTML(m) : '') +
    '<dl class="facts">' +
      fact('Dependencies', m.deps.length, false, 'dependency') + fact('Direct', direct, false, 'transitive') + fact('With advisories', m.vulnPkgs, false, 'advisory') +
      fact('Blocking', m.blockPkgs, m.blockPkgs > 0) + fact('Scan time', secs) +
    '</dl>' +
    '<div class="tabs" role="tablist" id="tabs">' +
      tabBtn('fixes', 'Fixes', m.blockPkgs + m.warnPkgs) +
      (m.licenses.length ? tabBtn('licenses', 'Licenses', m.licenses.length) : '') +
      tabBtn('deps', 'All dependencies', m.deps.length) +
      tabBtn('history', 'History', '') +
      '<span class="bar" id="tabBar"></span>' +
    '</div>' +
    '<div id="panel"></div>';

  const res = $('result');
  res.innerHTML = html; res.hidden = false;
  $('exportBtn').onclick = exportJSON;
  $('tabs').onclick = (e) => { const b = e.target.closest('.tab'); if (b) setTab(b.dataset.tab); };
  startSky();
  countUp();
  setTab(ui.tab);
  res.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

const fact = (k, v, hot, topic) => '<div><dt>' + (topic ? '<button class="learn-term" type="button" data-learn="' + topic + '">' + k + '</button>' : k) + '</dt><dd' + (hot ? ' class="hot"' : '') + (typeof v === 'number' ? ' data-n="' + v + '"' : '') + '>' + v + '</dd></div>';

// The headline numbers count up once, quickly, so the eye lands on them.
function countUp() {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const els = document.querySelectorAll('.facts dd[data-n]'), t0 = performance.now();
  const step = (now) => {
    const k = easeOut((now - t0) / 900);
    els.forEach((el) => { el.textContent = Math.round(+el.dataset.n * k); });
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const tabBtn = (id, label, n) => '<button class="tab" role="tab" type="button" data-tab="' + id + '" aria-selected="false">' + label + (n !== '' ? '<span class="n">' + n + '</span>' : '') + '</button>';

/* ---------- dependency skyline ----------
   Every dependency is a block on a grid. Seen from straight above it is a flat
   map; seen from the corner it is a skyline. Height is risk (critical 10, high 6,
   medium 3, low 1), colour is the worst severity. One camera swings between the
   two views while the blocks rise in a wave, so the map visibly becomes the city. */
const SKY_WEIGHT = { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, UNKNOWN: 1, NONE: 0 };
const YAW_3D = Math.PI / 4, ELEV_3D = 34 * Math.PI / 180;
const YAW_RANGE = [8 * Math.PI / 180, 82 * Math.PI / 180], ELEV_RANGE = [18 * Math.PI / 180, 62 * Math.PI / 180];
const clamp01 = (v) => v > 0 ? (v < 1 ? v : 1) : 0;
const lerp = (a, b, t) => a + (b - a) * t;
const easeInOut = (x) => { const t = clamp01(x); return t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
const easeOut = (x) => 1 - Math.pow(1 - clamp01(x), 3);
function camera(e, dYaw, dElev) {
  const yaw = Math.min(YAW_RANGE[1], Math.max(0, lerp(0, YAW_3D + dYaw, e)));
  const elev = lerp(Math.PI / 2, Math.min(ELEV_RANGE[1], Math.max(ELEV_RANGE[0], ELEV_3D + dElev)), e);
  return { cs: Math.cos(yaw), sn: Math.sin(yaw), se: Math.sin(elev), ce: Math.cos(elev) };
}
let probe = null;
function toRGB(color, fb) {
  if (!probe) { const c = document.createElement('canvas'); c.width = c.height = 1; probe = c.getContext('2d', { willReadFrequently: true }); }
  probe.clearRect(0, 0, 1, 1); probe.fillStyle = 'rgba(0,0,0,0)'; probe.fillStyle = color; probe.fillRect(0, 0, 1, 1);
  const d = probe.getImageData(0, 0, 1, 1).data;
  return d[3] < 8 ? fb : [d[0], d[1], d[2]];
}
const rgb = (r, g, b) => 'rgb(' + (r | 0) + ',' + (g | 0) + ',' + (b | 0) + ')';
function inQuad(p, o, x, y) {
  let sign = 0;
  for (let k = 0; k < 4; k++) {
    const ax = p[o + k * 2], ay = p[o + k * 2 + 1], bx = p[o + ((k + 1) % 4) * 2], by = p[o + ((k + 1) % 4) * 2 + 1];
    const cr = (bx - ax) * (y - ay) - (by - ay) * (x - ax);
    if (Math.abs(cr) < 1e-9) continue;
    const s = cr > 0 ? 1 : -1;
    if (!sign) sign = s; else if (s !== sign) return false;
  }
  return sign !== 0;
}
function quad(ctx, p, o, r) {
  if (r < .3) { ctx.moveTo(p[o], p[o + 1]); ctx.lineTo(p[o + 2], p[o + 3]); ctx.lineTo(p[o + 4], p[o + 5]); ctx.lineTo(p[o + 6], p[o + 7]); ctx.closePath(); return; }
  ctx.moveTo((p[o + 6] + p[o]) / 2, (p[o + 7] + p[o + 1]) / 2);
  for (let k = 0; k < 4; k++) { const b = (k + 1) % 4; ctx.arcTo(p[o + k * 2], p[o + k * 2 + 1], p[o + b * 2], p[o + b * 2 + 1], r); }
  ctx.closePath();
}

let sky = null;

// A view with mostly clean packages wastes the stage on flat tiles and
// shrinks the towers that matter. "Risky" lays out only packages with
// advisories and turns every clean one into the platform they stand on.
function skyHTML(m) {
  const items = m.groups.slice().map((g) => { g.score = g.advs.reduce((s, a) => s + SKY_WEIGHT[a.sev], 0); return g; })
    .sort((a, b) => b.score - a.score || rank(a.worst) - rank(b.worst) || a.dep.Name.localeCompare(b.dep.Name));
  ui.sky = items;
  const risky = items.filter((g) => g.score > 0).length;
  const clean = items.length - risky;
  // Default to Risky when clean packages dominate; All when there is nothing to focus on.
  if (!ui.skyModeSet) ui.skyMode = risky > 0 && clean > risky ? 'risk' : 'all';
  const canFocus = risky > 0 && clean > 0;

  const counts = {};
  items.forEach((g) => { counts[g.worst] = (counts[g.worst] || 0) + 1; });
  const legend = SEVS.filter((s) => counts[s]).map((s) =>
    '<button type="button" class="key" data-l="' + rank(s) + '" style="--c:' + (s === 'NONE' ? 'var(--flat)' : SEV[s].c) + '" aria-pressed="false" title="Highlight ' + SEV[s].label.toLowerCase() + '"><b>' + counts[s] + '</b> ' + SEV[s].label.toLowerCase() + '</button>').join('');
  const top = items[0];
  const towers = top && top.score
    ? '<div class="corner bl"><span class="lbl">Tallest tower</span><span class="big">' + esc(top.dep.Name) + '</span><span class="lbl">' + plural(top.advs.length, 'advisory', 'advisories') + ', risk score ' + top.score + '</span></div>' : '';
  const modes = canFocus
    ? '<div class="seg sky-mode" id="skyMode" role="group" aria-label="Packages shown">' +
        '<button type="button" data-m="risk" aria-pressed="' + (ui.skyMode === 'risk') + '">Risky <b>' + risky + '</b></button>' +
        '<button type="button" data-m="all" aria-pressed="' + (ui.skyMode === 'all') + '">All <b>' + items.length + '</b></button>' +
      '</div>' : '';
  return '<section class="sky is3d" id="sky">' +
    '<div class="sky-top"><p class="sky-title" id="skyTitle"></p>' +
      '<div class="sky-ctl">' + modes +
      '<div class="view" id="viewToggle" data-v="3d" role="group" aria-label="Chart view"><span class="knob" aria-hidden="true"></span>' +
        '<button type="button" data-v="2d" aria-pressed="false" title="Flat map" aria-label="Flat map"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1" fill="currentColor"/><rect x="9" y="1.5" width="5.5" height="5.5" rx="1" fill="currentColor"/><rect x="1.5" y="9" width="5.5" height="5.5" rx="1" fill="currentColor"/><rect x="9" y="9" width="5.5" height="5.5" rx="1" fill="currentColor"/></svg></button>' +
        '<button type="button" data-v="3d" aria-pressed="true" title="3D skyline" aria-label="3D skyline"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M8 1.2 14.2 4.6v6.8L8 14.8 1.8 11.4V4.6Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M1.8 4.6 8 8l6.2-3.4M8 8v6.8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg></button>' +
      '</div></div></div>' +
    '<div class="stage" id="stage"><canvas id="skyCanvas" tabindex="0" role="img"></canvas>' +
      '<div class="corner tr"><span class="lbl">Blocking the build</span><span class="big" style="color:' + (m.blockPkgs ? 'var(--critical-t)' : 'var(--clean-t)') + '">' + m.blockPkgs + '</span><span class="lbl">' + (m.blockPkgs === 1 ? 'package' : 'packages') + ' your policy rejects</span></div>' +
      towers + '</div>' +
    '<div class="sky-foot"><span class="hint" id="skyHint"></span><div class="keys" id="skyKeys">' + legend + '</div></div>' +
    '<p class="sr" aria-live="polite" id="skyLive"></p>' +
  '</section>';
}

function startSky(opts) {
  opts = opts || {};
  const prev = sky ? sky.state() : null;
  if (sky) sky.destroy();
  const all = ui.sky, root = $('sky'), stage = $('stage'), canvas = $('skyCanvas'), tip = $('tip');
  if (!all || !root) return;
  const ctx = canvas.getContext('2d');
  const ac = new AbortController(), on = (el, ev, fn) => el.addEventListener(ev, fn, { signal: ac.signal });
  const rmq = matchMedia('(prefers-reduced-motion: reduce)');
  let reduced = rmq.matches;

  const riskyAll = all.filter((g) => g.score > 0);
  const focus = ui.skyMode === 'risk' && riskyAll.length > 0 && riskyAll.length < all.length;
  const items = focus ? riskyAll : all;
  const cleanCount = all.length - riskyAll.length;
  const plate = focus && cleanCount > 0; // the clean packages, as one platform

  const n = items.length;
  // A near-square block (slightly wide in All mode) fills the stage far
  // better than a long strip. Cells are handed out by diagonal from the back
  // corner, so the riskiest, tallest towers stand behind the shorter ones.
  const C = Math.max(1, Math.ceil(Math.sqrt(n * (focus ? 1.2 : 1.7))));
  const R = Math.max(1, Math.ceil(n / C));
  const cells = [];
  for (let x = 0; x < C; x++) for (let y = 0; y < R; y++) cells.push([x, y]);
  cells.sort((a, b) => (a[0] + a[1]) - (b[0] + b[1]) || Math.abs(a[0] - a[1]) - Math.abs(b[0] - b[1]) || a[0] - b[0]);

  const wk = new Float32Array(n), dy = new Float32Array(n), lv = new Uint8Array(n), hgt = new Float32Array(n), zs = new Float32Array(n);
  const hover = new Float32Array(n), dim = new Float32Array(n), polys = new Float32Array(n * 24), faces = new Uint8Array(n);
  const order = Array.from({ length: n }, (_, i) => i);
  const at = new Map();
  const maxScore = Math.max(1, ...items.map((g) => g.score));
  items.forEach((g, i) => {
    wk[i] = cells[i][0]; dy[i] = cells[i][1]; lv[i] = rank(g.worst);
    hgt[i] = g.score > 0 ? .5 + Math.pow(g.score / maxScore, .8) * 6.4 : .18;
    at.set(wk[i] + ',' + dy[i], i);
  });
  const diag = Math.max(1, C + R - 2);
  const PLATE = -2, PAD = .45, PLATE_H = .16;
  const platePoly = new Float32Array(24);

  // Titles and hints follow the mode, so the copy always matches the picture.
  $('skyTitle').innerHTML = focus
    ? '<b>' + n + '</b> risky ' + (n === 1 ? 'package' : 'packages') + ' standing on <b>' + cleanCount + '</b> clean ones'
    : '<b>' + all.length + '</b> ' + (all.length === 1 ? 'dependency' : 'dependencies') + ', tower height is risk';
  canvas.setAttribute('aria-label', n + ' packages drawn as towers. Taller and redder means riskier. Use the arrow keys to read each package.');

  let t = prev ? prev.t : 0, target = prev ? prev.target : 1, yaw = 0, elev = 0, yawGoal = 0, elevGoal = 0, entered = !!prev;
  if (prev && prev.target === 1 && !reduced) t = .35; // replay the rise when switching modes
  let W = 0, H2 = 0, H3 = 0, Hmax = 0, dpr = 1, lastH = -1, raf = 0, last = 0;
  let col = [], fg = [20, 26, 36], bg = [255, 255, 255], plateCol = [0, 0, 0];
  let hovered = -1, pinned = -1, active = -1, legendLevel = -1, legendSticky = -1;

  const retheme = () => {
    const cs = getComputedStyle(root);
    fg = toRGB(cs.getPropertyValue('--text').trim(), fg);
    bg = toRGB(cs.getPropertyValue('--surface').trim(), bg);
    const dark = (0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]) / 255 < .45;
    const flat = [0, 1, 2].map((k) => bg[k] + (fg[k] - bg[k]) * (dark ? .16 : .1));
    const cleanRGB = toRGB(cs.getPropertyValue('--clean').trim(), fg);
    plateCol = [0, 1, 2].map((k) => flat[k] + (cleanRGB[k] - flat[k]) * (dark ? .22 : .28));
    root.style.setProperty('--flat', rgb(flat[0], flat[1], flat[2]));
    // In Risky mode clean packages are the platform, so the legend uses its colour.
    const cleanKey = root.querySelector('.key[data-l="' + rank('NONE') + '"]');
    if (cleanKey) cleanKey.style.setProperty('--c', plate ? rgb(plateCol[0], plateCol[1], plateCol[2]) : 'var(--flat)');
    col = ['--critical', '--high', '--medium', '--low', '--unknown'].map((v) => toRGB(cs.getPropertyValue(v).trim(), fg)).concat([flat]);
    if (entered) kick(); else draw();
  };

  const width = (e) => lerp(.78, .86, e);
  const extent = (cam, e, full) => {
    const w = width(e), off = (1 - w) / 2;
    let a = Infinity, b = -Infinity, c = Infinity, d = -Infinity;
    const add = (x, y, z) => { const px = x * cam.cs - y * cam.sn, py = (x * cam.sn + y * cam.cs) * cam.se - z * cam.ce; if (px < a) a = px; if (px > b) b = px; if (py < c) c = py; if (py > d) d = py; };
    for (let i = 0; i < n; i++) {
      const x0 = wk[i] + off, y0 = dy[i] + off, z = full ? hgt[i] * e : zs[i];
      add(x0, y0, z); add(x0 + w, y0, z); add(x0, y0 + w, z); add(x0 + w, y0 + w, 0); add(x0, y0 + w, 0); add(x0 + w, y0, 0);
    }
    if (plate) { add(-PAD, -PAD, 0); add(C + PAD, -PAD, 0); add(-PAD, R + PAD, 0); add(C + PAD, R + PAD, 0); }
    return { minx: a, maxx: b, miny: c, maxy: d };
  };

  // Bigger cells when there are few packages, so a small risky set fills the stage.
  const cap2 = n < 40 ? 64 : 44, cap3 = n < 40 ? 104 : 72;
  const relayout = () => {
    const w = Math.round(stage.clientWidth);
    if (!w) return;
    W = w; dpr = Math.min(2, devicePixelRatio || 1);
    const b2 = extent(camera(0, 0, 0), 0, true), bw2 = b2.maxx - b2.minx, bh2 = b2.maxy - b2.miny;
    H2 = Math.max(80, Math.min(bh2 * Math.min((W - 8) / bw2, cap2) + 8, 460));
    const b3 = extent(camera(1, 0, 0), 1, true), bw3 = b3.maxx - b3.minx, bh3 = b3.maxy - b3.miny;
    H3 = Math.max(Math.min(bh3 * Math.min((W - 40) / bw3, cap3) + 40, W * .66, 560), Math.min(260, W * .75));
    Hmax = Math.ceil(Math.max(H2, H3));
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(Hmax * dpr);
    canvas.style.width = W + 'px'; canvas.style.height = Hmax + 'px';
    lastH = -1; draw();
  };

  const rise = (i) => easeOut((t - ((wk[i] + dy[i]) / diag) * .4) / .58);

  const face = (p, o, r, fill) => { ctx.beginPath(); quad(ctx, p, o, r); ctx.fillStyle = fill; ctx.fill(); };

  const draw = () => {
    if (!W || !col.length) return;
    const e = easeInOut(t), cam = camera(e, yaw, elev), Hc = lerp(H2, H3, e);
    if (Math.abs(Hc - lastH) > .2) { stage.style.height = Hc.toFixed(1) + 'px'; lastH = Hc; }
    for (let i = 0; i < n; i++) zs[i] = rise(i) * hgt[i];
    const b = extent(cam, e, false), pad = lerp(6, 24, e);
    const aw = W - 2 * pad, ah = Hc - 2 * pad, bw = Math.max(1e-6, b.maxx - b.minx), bh = Math.max(1e-6, b.maxy - b.miny);
    const s = Math.min(aw / bw, ah / bh, lerp(cap2, cap3, e));
    const ox = pad + (aw - bw * s) / 2 - b.minx * s, oy = pad + (ah - bh * s) / 2 - b.miny * s;
    const { cs, sn, se, ce } = cam;
    const px = (x, y) => ox + (x * cs - y * sn) * s, py = (x, y, z) => oy + ((x * sn + y * cs) * se - z * ce) * s;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, Hmax);

    // The platform goes first: everything stands on it.
    if (plate) {
      const x0 = -PAD, y0 = -PAD, x1 = C + PAD, y1 = R + PAD, z = PLATE_H * e, p = platePoly;
      p[0] = px(x0, y0); p[1] = py(x0, y0, z); p[2] = px(x1, y0); p[3] = py(x1, y0, z);
      p[4] = px(x1, y1); p[5] = py(x1, y1, z); p[6] = px(x0, y1); p[7] = py(x0, y1, z);
      p[8] = px(x0, y1); p[9] = py(x0, y1, 0); p[10] = px(x1, y1); p[11] = py(x1, y1, 0); p[12] = p[4]; p[13] = p[5]; p[14] = p[6]; p[15] = p[7];
      p[16] = px(x1, y0); p[17] = py(x1, y0, 0); p[18] = p[10]; p[19] = p[11]; p[20] = p[4]; p[21] = p[5]; p[22] = p[2]; p[23] = p[3];
      const [r, g, bl] = plateCol, hl = active === PLATE ? .12 : 0;
      const mix = (c, k) => c + (fg[k === 0 ? 0 : k === 1 ? 1 : 2] - c) * hl;
      if (z * ce * s > .5) {
        face(p, 8, 0, rgb(mix(r, 0) * .82, mix(g, 1) * .82, mix(bl, 2) * .82));
        face(p, 16, 0, rgb(mix(r, 0) * .64, mix(g, 1) * .64, mix(bl, 2) * .64));
      }
      ctx.beginPath(); quad(ctx, p, 0, lerp(.35, .12, e) * s); ctx.fillStyle = rgb(mix(r, 0), mix(g, 1), mix(bl, 2)); ctx.fill();
      ctx.strokeStyle = 'rgba(' + fg[0] + ',' + fg[1] + ',' + fg[2] + ',' + (active === PLATE ? .7 : .08) + ')'; ctx.lineWidth = active === PLATE ? 1.5 : 1; ctx.stroke();
    }

    order.sort((a, c) => (wk[a] + .5) * sn + (dy[a] + .5) * cs - ((wk[c] + .5) * sn + (dy[c] + .5) * cs));
    const w = width(e), off = (1 - w) / 2, radius = lerp(.17, .03, e) * s, outline = (1 - e) * .06, lift = .7 * e;
    const base = plate ? PLATE_H * e : 0;
    const glow = n <= 150 && e > .5;
    const flat = col[5];
    for (let k = 0; k < n; k++) {
      const i = order[k], x0 = wk[i] + off, y0 = dy[i] + off, x1 = x0 + w, y1 = y0 + w, z = base + zs[i] + hover[i] * lift, o = i * 24;
      polys[o] = px(x0, y0); polys[o + 1] = py(x0, y0, z); polys[o + 2] = px(x1, y0); polys[o + 3] = py(x1, y0, z);
      polys[o + 4] = px(x1, y1); polys[o + 5] = py(x1, y1, z); polys[o + 6] = px(x0, y1); polys[o + 7] = py(x0, y1, z);
      polys[o + 8] = px(x0, y1); polys[o + 9] = py(x0, y1, base); polys[o + 10] = px(x1, y1); polys[o + 11] = py(x1, y1, base);
      polys[o + 12] = polys[o + 4]; polys[o + 13] = polys[o + 5]; polys[o + 14] = polys[o + 6]; polys[o + 15] = polys[o + 7];
      polys[o + 16] = px(x1, y0); polys[o + 17] = py(x1, y0, base); polys[o + 18] = polys[o + 10]; polys[o + 19] = polys[o + 11];
      polys[o + 20] = polys[o + 4]; polys[o + 21] = polys[o + 5]; polys[o + 22] = polys[o + 2]; polys[o + 23] = polys[o + 3];
      const tall = (z - base) * ce * s;
      let f = 0; if (tall > .35 && w * cs * s > .35) f |= 1; if (tall > .35 && w * sn * s > .35) f |= 2; faces[i] = f;
      const c = col[lv[i]];
      let r = c[0], g = c[1], bl = c[2];
      const d = dim[i];
      if (d > .002) { r += (flat[0] - r) * .78 * d; g += (flat[1] - g) * .78 * d; bl += (flat[2] - bl) * .78 * d; }
      const hv = hover[i];
      if (hv > .002) { const m2 = .18 * hv; r += (fg[0] - r) * m2; g += (fg[1] - g) * m2; bl += (fg[2] - bl) * m2; }
      if (f & 1) face(polys, o + 8, 0, rgb(r * .84, g * .84, bl * .84));
      if (f & 2) face(polys, o + 16, 0, rgb(r * .66, g * .66, bl * .66));
      // Critical and high towers glow like signs at night.
      if (glow && lv[i] <= 1 && d < .5) { ctx.shadowColor = rgb(c[0], c[1], c[2]); ctx.shadowBlur = 18 * e * (1 - d); }
      ctx.beginPath(); quad(ctx, polys, o, radius); ctx.fillStyle = rgb(r, g, bl); ctx.fill();
      ctx.shadowBlur = 0;
      if (outline > .004) { ctx.strokeStyle = 'rgba(' + fg[0] + ',' + fg[1] + ',' + fg[2] + ',' + outline.toFixed(3) + ')'; ctx.lineWidth = 1; ctx.stroke(); }
      if (hv > .02) { ctx.strokeStyle = 'rgba(' + fg[0] + ',' + fg[1] + ',' + fg[2] + ',' + (.85 * hv).toFixed(3) + ')'; ctx.lineWidth = 1.5; ctx.stroke(); }
    }
    if (active >= 0) {
      const i = active, z = base + zs[i] + hover[i] * lift, rc = canvas.getBoundingClientRect();
      const tx = px(wk[i] + .5, dy[i] + .5), ty = Math.min(py(wk[i] + off, dy[i] + off, z), py(wk[i] + off + w, dy[i] + off, z), py(wk[i] + off, dy[i] + off + w, z));
      tip.style.left = Math.min(Math.max(rc.left + tx, 130), innerWidth - 130) + 'px';
      tip.style.top = (rc.top + ty) + 'px';
    } else if (active === PLATE) {
      const rc = canvas.getBoundingClientRect();
      // Anchor to the platform's front corner, below the towers.
      tip.style.left = Math.min(Math.max(rc.left + platePoly[10], 150), innerWidth - 150) + 'px';
      tip.style.top = (rc.top + platePoly[11] + 58) + 'px';
    }
  };

  const tick = (now) => {
    raf = 0;
    const dt = Math.min(.05, Math.max(0, (now - last) / 1000)); last = now;
    let moving = false;
    if (t !== target) { const st = reduced ? 1 : dt * 1000 / 1300; t = target > t ? Math.min(target, t + st) : Math.max(target, t - st); moving = true; }
    const ko = reduced ? 1 : 1 - Math.exp(-dt * 12);
    yaw += (yawGoal - yaw) * ko; elev += (elevGoal - elev) * ko;
    if (Math.abs(yawGoal - yaw) > 1e-4 || Math.abs(elevGoal - elev) > 1e-4) moving = true; else { yaw = yawGoal; elev = elevGoal; }
    const kh = reduced ? 1 : 1 - Math.exp(-dt * 16), kd = reduced ? 1 : 1 - Math.exp(-dt * 10);
    const leg = legendSticky >= 0 ? legendSticky : legendLevel;
    for (let i = 0; i < n; i++) {
      const hg = i === active ? 1 : 0, dg = leg >= 0 && lv[i] !== leg ? 1 : 0;
      if (hover[i] !== hg) { hover[i] = Math.abs(hg - hover[i]) < .003 ? hg : hover[i] + (hg - hover[i]) * kh; moving = true; }
      if (dim[i] !== dg) { dim[i] = Math.abs(dg - dim[i]) < .003 ? dg : dim[i] + (dg - dim[i]) * kd; moving = true; }
    }
    draw();
    if (moving) raf = requestAnimationFrame(tick);
  };
  const kick = () => { if (raf) return; last = performance.now(); raf = requestAnimationFrame(tick); };

  const describe = (i) => {
    const g = items[i];
    return g.dep.Name + '@' + g.dep.Version + ': ' + (g.advs.length ? plural(g.advs.length, 'advisory', 'advisories') + ', worst ' + SEV[g.worst].label.toLowerCase() + (g.fixTo ? ', upgrade to ' + g.fixTo : '') : 'no known issues');
  };
  const showTip = () => {
    if (active === -1) { tip.classList.remove('on'); return; }
    if (active === PLATE) {
      tip.innerHTML = '<b>' + cleanCount + '</b> ' + (cleanCount === 1 ? 'package' : 'packages') + ' with no known issues<br><span style="opacity:.7">Click to show every package</span>';
    } else {
      const g = items[active];
      tip.innerHTML = '<span class="mono">' + esc(g.dep.Name) + '<span style="opacity:.6">@' + esc(g.dep.Version) + '</span></span><br>' +
        (g.advs.length ? plural(g.advs.length, 'advisory', 'advisories') + ', worst ' + SEV[g.worst].label.toLowerCase() + (g.fixTo ? '. Upgrade to ' + esc(g.fixTo) : '') : 'No known issues');
    }
    tip.classList.add('on'); draw();
  };
  const refresh = () => { const next = hovered !== -1 ? hovered : pinned; if (next === active) return; active = next; showTip(); kick(); };
  const hit = (x, y) => {
    for (let k = n - 1; k >= 0; k--) { const i = order[k], o = i * 24; if (inQuad(polys, o, x, y) || (faces[i] & 1 && inQuad(polys, o + 8, x, y)) || (faces[i] & 2 && inQuad(polys, o + 16, x, y))) return i; }
    if (plate && (inQuad(platePoly, 0, x, y) || inQuad(platePoly, 8, x, y) || inQuad(platePoly, 16, x, y))) return PLATE;
    return -1;
  };
  const local = (ev) => { const r = canvas.getBoundingClientRect(); return [ev.clientX - r.left, ev.clientY - r.top]; };
  const setMode = (m) => { if (ui.skyMode === m) return; ui.skyMode = m; ui.skyModeSet = true; tip.classList.remove('on'); syncModeButtons(); startSky(); };
  const goTo = (i) => {
    if (i === PLATE) { setMode('all'); return; }
    const g = items[i]; tip.classList.remove('on');
    if (g.status === 'clean') { ui.depQ = g.dep.Name; setTab('deps'); }
    else { if (g.status === 'allowed') ui.showAllowed = true; ui.q = g.dep.Name; ui.open = new Set([g.key]); setTab('fixes'); }
    $('tabs').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
  };

  let drag = null;
  on(canvas, 'pointerdown', (ev) => {
    if (ev.button !== 0) return;
    const can = target === 1;
    drag = { id: ev.pointerId, x: ev.clientX, y: ev.clientY, yaw: yawGoal, elev: elevGoal, moved: false, orbit: can, mouse: ev.pointerType === 'mouse' };
    if (can) try { canvas.setPointerCapture(ev.pointerId); } catch (e) {}
  });
  on(canvas, 'pointermove', (ev) => {
    if (drag && drag.orbit && ev.pointerId === drag.id) {
      const dx = ev.clientX - drag.x, dyy = ev.clientY - drag.y;
      if (drag.moved || Math.hypot(dx, dyy) > 4) {
        drag.moved = true;
        yawGoal = Math.min(YAW_RANGE[1] - YAW_3D, Math.max(YAW_RANGE[0] - YAW_3D, drag.yaw + dx * .006));
        if (drag.mouse) elevGoal = Math.min(ELEV_RANGE[1] - ELEV_3D, Math.max(ELEV_RANGE[0] - ELEV_3D, drag.elev + dyy * .004));
        canvas.style.cursor = 'grabbing'; hovered = -1; refresh(); kick(); return;
      }
    }
    if (ev.pointerType !== 'mouse') return;
    const [x, y] = local(ev), i = hit(x, y);
    if (i !== hovered) { hovered = i; refresh(); }
    canvas.style.cursor = i !== -1 ? 'pointer' : target === 1 ? 'grab' : 'default';
  });
  on(canvas, 'pointerup', (ev) => {
    if (!drag || ev.pointerId !== drag.id) return;
    const moved = drag.moved; drag = null;
    if (canvas.hasPointerCapture(ev.pointerId)) canvas.releasePointerCapture(ev.pointerId);
    canvas.style.cursor = target === 1 ? 'grab' : 'default';
    if (moved) return;
    const [x, y] = local(ev), i = hit(x, y);
    if (i === -1) { pinned = -1; refresh(); return; }
    if (ev.pointerType === 'mouse' || pinned === i) goTo(i);
    else { pinned = i; hovered = -1; refresh(); }
  });
  on(canvas, 'pointercancel', () => { drag = null; });
  on(canvas, 'pointerleave', () => { if (!drag) { hovered = -1; refresh(); } });
  on(canvas, 'dblclick', () => { yawGoal = 0; elevGoal = 0; kick(); });
  // Arrow keys move by grid position, not list order, because the layout is diagonal.
  on(canvas, 'keydown', (ev) => {
    const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End', 'Escape', 'Enter', ' '];
    if (!keys.includes(ev.key) || !n) return;
    ev.preventDefault();
    if (ev.key === 'Escape') { pinned = hovered = -1; refresh(); return; }
    if (ev.key === 'Enter' || ev.key === ' ') { if (active >= 0) goTo(active); return; }
    let i = active >= 0 ? active : 0;
    if (active >= 0) {
      let x = wk[i], y = dy[i];
      if (ev.key === 'ArrowLeft') x--; if (ev.key === 'ArrowRight') x++;
      if (ev.key === 'ArrowUp') y--; if (ev.key === 'ArrowDown') y++;
      if (ev.key === 'Home') i = 0; else if (ev.key === 'End') i = n - 1;
      else if (at.has(x + ',' + y)) i = at.get(x + ',' + y);
    }
    pinned = i; hovered = -1; refresh();
    $('skyLive').textContent = describe(pinned);
  });
  on(canvas, 'blur', () => { pinned = -1; refresh(); });
  on(window, 'scroll', () => { if (active !== -1) { hovered = -1; pinned = -1; refresh(); } }, { passive: true });

  const toggle = $('viewToggle');
  const setView = (v) => {
    target = v === '3d' ? 1 : 0;
    if (!target) { yawGoal = 0; elevGoal = 0; }
    toggle.dataset.v = v; root.classList.toggle('is3d', !!target);
    toggle.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === v)));
    $('skyHint').textContent = target ? 'Hover a tower for details. Drag to orbit, double-click to reset.' : 'Hover a block for details. Arrow keys walk the map.';
    canvas.style.cursor = target ? 'grab' : 'default';
    kick();
  };
  on(toggle, 'click', (e) => { const b = e.target.closest('button'); if (b) setView(b.dataset.v); });
  const modeBox = $('skyMode');
  const syncModeButtons = () => { if (modeBox) modeBox.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.m === ui.skyMode))); };
  if (modeBox) on(modeBox, 'click', (e) => { const b = e.target.closest('button'); if (b) setMode(b.dataset.m); });

  const keys = $('skyKeys');
  on(keys, 'mouseover', (e) => { const b = e.target.closest('.key'); if (b) { legendLevel = +b.dataset.l; kick(); } });
  on(keys, 'mouseleave', () => { legendLevel = -1; kick(); });
  on(keys, 'click', (e) => {
    const b = e.target.closest('.key'); if (!b) return;
    // The clean colour lives on the platform in Risky mode; show every package to highlight it.
    if (+b.dataset.l === rank('NONE') && focus) { setMode('all'); return; }
    legendSticky = legendSticky === +b.dataset.l ? -1 : +b.dataset.l;
    keys.querySelectorAll('.key').forEach((k) => k.setAttribute('aria-pressed', String(+k.dataset.l === legendSticky)));
    kick();
  });

  on(rmq, 'change', () => { reduced = rmq.matches; kick(); });
  on(matchMedia('(prefers-color-scheme: dark)'), 'change', retheme);
  const ro = new ResizeObserver(() => { if (Math.round(stage.clientWidth) !== W) relayout(); });
  ro.observe(stage);
  const io = new IntersectionObserver((en) => {
    if (en.some((x) => x.isIntersecting) && !entered) { entered = true; if (reduced) t = 1; kick(); io.disconnect(); }
  }, { threshold: .3 });
  const keepTarget = target;
  target = 0; retheme(); relayout(); target = keepTarget;
  setView(target ? '3d' : '2d');
  if (entered) kick(); else io.observe(stage);

  sky = {
    state() { return { t, target }; },
    destroy() { if (raf) cancelAnimationFrame(raf); ac.abort(); ro.disconnect(); io.disconnect(); tip.classList.remove('on'); sky = null; }
  };
}

function setTab(id) {
  ui.tab = id;
  document.querySelectorAll('.tab').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === id)));
  const active = document.querySelector('.tab[data-tab="' + id + '"]');
  const bar = $('tabBar');
  if (active && bar) { bar.style.width = active.offsetWidth + 'px'; bar.style.transform = 'translateX(' + active.offsetLeft + 'px)'; }
  if (id === 'fixes') renderFixes();
  else if (id === 'licenses') renderLicenses();
  else if (id === 'deps') renderDeps();
  else renderHistory();
}

const searchBox = (id, value, ph) => '<label class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/></svg><span class="sr">' + ph + '</span><input id="' + id + '" value="' + esc(value) + '" placeholder="' + ph + '"></label>';

function renderFixes() {
  const m = ui.model;
  const q = ui.q.toLowerCase();
  const list = m.groups
    .filter((g) => g.status === 'block' || g.status === 'warn' || (ui.showAllowed && g.status === 'allowed'))
    .filter((g) => !q || g.dep.Name.toLowerCase().includes(q) || g.advs.some((a) => (a.id + ' ' + a.aliases.join(' ') + ' ' + a.summary).toLowerCase().includes(q)))
    .sort((a, b) => ['block', 'warn', 'allowed'].indexOf(a.status) - ['block', 'warn', 'allowed'].indexOf(b.status) || rank(a.worst) - rank(b.worst) || b.advs.length - a.advs.length || a.dep.Name.localeCompare(b.dep.Name));

  const allowedCount = m.groups.filter((g) => g.status === 'allowed').length;
  let h = '<div class="toolbar">' + searchBox('fixQ', ui.q, 'Filter by package, CVE or GHSA') +
    (allowedCount ? '<label class="check"><input type="checkbox" id="showAllowed"' + (ui.showAllowed ? ' checked' : '') + '> Include ' + plural(allowedCount, 'package') + ' below the policy threshold</label>' : '') +
    '</div>';

  if (!list.length) {
    h += '<div class="list"><div class="empty"><b>' + (q ? 'No packages match “' + esc(ui.q) + '”' : 'Nothing to fix') + '</b>' +
      (q ? 'Try a package name, CVE or GHSA ID.' : 'No package breaks or approaches your policy.') + '</div></div>';
  } else {
    h += '<div class="list">' + list.slice(0, ui.shown).map(pkgHTML).join('') + '</div>';
    if (list.length > ui.shown) h += '<button class="ghost more" type="button" id="moreFix">Show ' + Math.min(PAGE, list.length - ui.shown) + ' more of ' + (list.length - ui.shown) + '</button>';
  }
  $('panel').innerHTML = h;

  const input = $('fixQ');
  input.oninput = () => { ui.q = input.value; ui.shown = PAGE; const pos = input.selectionStart; renderFixes(); const n = $('fixQ'); n.focus(); n.setSelectionRange(pos, pos); };
  const sa = $('showAllowed'); if (sa) sa.onchange = () => { ui.showAllowed = sa.checked; renderFixes(); };
  const more = $('moreFix'); if (more) more.onclick = () => { ui.shown += PAGE; renderFixes(); };
  $('panel').onclick = onPanelClick;
}

function pkgHTML(g) {
  const counts = {};
  g.advs.forEach((a) => { counts[a.sev] = (counts[a.sev] || 0) + 1; });
  const pills = SEVS.filter((s) => counts[s]).map((s) => '<span class="pill" style="--c:' + SEV[s].c + ';--t:' + SEV[s].t + '">' + counts[s] + ' ' + SEV[s].label.toLowerCase() + '</span>').join('');
  const fix = g.fixTo
    ? '<div class="fix"><span class="to">Upgrade to <b>' + esc(g.fixTo) + '</b></span><button class="copy" type="button" data-cmd="' + esc(upgradeCmd(g.dep, g.fixTo)) + '">Copy command</button></div>'
    : '<div class="fix"><span class="nofix">No fixed version published</span></div>';
  const open = ui.open.has(g.key);
  const meta = (g.dep.Ecosystem || '') + ', ' + (g.dep.Direct ? 'direct' : 'transitive') + ', ' + STATUS[g.status === 'clean' ? 'allowed' : g.status].toLowerCase() +
    (g.unfixed && g.fixTo ? ', ' + plural(g.unfixed, 'advisory', 'advisories') + ' without a fix' : '');
  return '<div class="pkg' + (open ? ' open' : '') + '" data-key="' + esc(g.key) + '">' +
    '<div class="pkg-head">' +
      '<span class="sev" style="--c:' + SEV[g.worst].c + '"></span>' +
      '<button class="toggle who" type="button" aria-expanded="' + open + '"><span class="name">' + esc(g.dep.Name) + '<em>@' + esc(g.dep.Version) + '</em></span><span class="meta" style="display:block">' + esc(meta) + '</span></button>' +
      '<span class="counts">' + pills + '</span>' + fix +
      '<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg>' +
    '</div>' +
    '<div class="pkg-body"><div><div class="advs">' + (open ? advsHTML(g) : '') + '</div></div></div>' +
  '</div>';
}

// Upgrade path: installed version, then every version that closes advisories,
// with the dot coloured by whatever risk is still left at that point.
function pathHTML(g) {
  const fixed = [...new Set(g.advs.map((a) => a.fixed).filter(Boolean))].sort((a, b) => cmpVer(nv(a), nv(b)));
  if (!fixed.length) return '';
  const left = (v) => g.advs.filter((a) => !a.fixed || cmpVer(nv(a.fixed), nv(v)) > 0);
  const worstOf = (list) => list.reduce((w, a) => rank(a.sev) < rank(w) ? a.sev : w, 'NONE');
  const color = (list) => list.length ? SEV[worstOf(list)].c : 'var(--clean)';
  const stops = [{ v: g.dep.Version, c: color(g.advs), label: 'Installed', note: plural(g.advs.length, 'advisory', 'advisories') }];
  // Only stop where the remaining risk visibly changes, plus the recommended
  // target. Releases in between are folded into the next stop's count.
  let prev = g.dep.Version, lastWorst = worstOf(g.advs);
  fixed.forEach((v, i) => {
    const rest = left(v), w = rest.length ? worstOf(rest) : 'CLEAR';
    if (w === lastWorst && v !== g.fixTo && i !== fixed.length - 1) return;
    const closed = g.advs.filter((a) => a.fixed && cmpVer(nv(a.fixed), nv(v)) <= 0 && cmpVer(nv(a.fixed), nv(prev)) > 0).length;
    stops.push({ v, c: color(rest), note: 'Closes ' + closed + (rest.length ? ', ' + rest.length + ' left' : ''), rec: v === g.fixTo, rest: rest.length });
    prev = v; lastWorst = w;
  });
  return '<div class="path"><p class="path-h">Upgrade path</p><div class="track"><ol>' + stops.map((s, i) => {
    const next = stops[i + 1];
    return '<li class="stop' + (s.rec ? ' rec' : '') + '" style="--i:' + i + ';--a:' + s.c + ';--b:' + (next ? next.c : s.c) + '">' +
      (next ? '<span class="link" aria-hidden="true"></span>' : '') + '<span class="dot" aria-hidden="true"></span>' +
      '<span class="mask"><b>' + esc(s.v) + '</b></span>' +
      '<span class="mask"><small>' + (s.label ? s.label + ', ' + s.note.toLowerCase() : esc(s.note)) + '</small></span>' +
      (s.rec ? '<span class="mask"><span><span class="tag' + (s.rest ? ' part' : '') + '">' + (s.rest ? 'Recommended' : 'Recommended, clears all') + '</span></span></span>' : '') +
    '</li>';
  }).join('') + '</ol></div></div>';
}

function advsHTML(g) {
  return pathHTML(g) + g.advs.map((a, i) => {
    const s = SEV[a.sev];
    const cve = a.aliases.filter((x) => /^CVE-/.test(x))[0];
    return '<div class="adv" style="--i:' + i + '"><span class="sevt" style="--t:' + s.t + '">' + s.label + '<small>' + STATUS[a.status] + '</small></span>' +
      '<span class="what">' + esc(a.summary || 'No summary published') + '<br><a href="https://osv.dev/vulnerability/' + encodeURIComponent(a.id) + '" target="_blank" rel="noopener noreferrer">' + esc(a.id) + '</a>' +
      (cve && cve !== a.id ? ' <a href="https://osv.dev/vulnerability/' + encodeURIComponent(cve) + '" target="_blank" rel="noopener noreferrer">' + esc(cve) + '</a>' : '') + '</span>' +
      '<span class="in">' + (a.fixed ? 'Fixed in <b>' + esc(a.fixed) + '</b>' : 'No fix yet') + '</span></div>';
  }).join('');
}

function onPanelClick(e) {
  const copy = e.target.closest('.copy');
  if (copy) { e.stopPropagation(); copyText(copy.dataset.cmd); return; }
  const toggle = e.target.closest('.toggle');
  if (!toggle) return;
  const el = toggle.closest('.pkg'), key = el.dataset.key;
  const g = ui.model.groups.find((x) => x.key === key);
  const advs = el.querySelector('.advs');
  if (!advs.innerHTML) advs.innerHTML = advsHTML(g);
  const open = !el.classList.contains('open');
  el.classList.toggle('open', open);
  toggle.setAttribute('aria-expanded', String(open));
  if (open) ui.open.add(key); else ui.open.delete(key);
}

function renderLicenses() {
  const l = ui.model.licenses;
  $('panel').innerHTML = '<div class="toolbar"></div><div class="list">' + l.map((x) =>
    '<div class="pkg"><div class="pkg-head" style="grid-template-columns:4px minmax(0,1fr) auto"><span class="sev" style="--c:' + (x.status === 'block' ? 'var(--critical)' : 'var(--medium)') + '"></span>' +
    '<span class="who"><span class="name">' + esc(x.dep.Name) + '<em>@' + esc(x.dep.Version) + '</em></span><span class="meta" style="display:block">' + esc(x.reason) + '</span></span>' +
    '<span class="pill" style="--c:' + (x.status === 'block' ? 'var(--critical)' : 'var(--medium)') + ';--t:' + (x.status === 'block' ? 'var(--critical-t)' : 'var(--medium-t)') + '">' + (x.status === 'block' ? 'Denied' : 'Review') + '</span></div></div>'
  ).join('') + '</div>';
}

function renderDeps() {
  const m = ui.model, q = ui.depQ.toLowerCase();
  const byKey = new Map(m.groups.map((g) => [g.key, g]));
  const list = m.deps.filter((d) => (ui.depFilter === 'all' || (ui.depFilter === 'direct') === !!d.Direct) && (!q || d.Name.toLowerCase().includes(q)))
    .sort((a, b) => a.Name.localeCompare(b.Name));
  const segBtn = (v, label) => '<button type="button" data-f="' + v + '" aria-pressed="' + (ui.depFilter === v) + '">' + label + '</button>';
  let h = '<div class="toolbar">' + searchBox('depQ', ui.depQ, 'Filter packages') +
    '<div class="seg" id="depSeg">' + segBtn('all', 'All') + segBtn('direct', 'Direct') + segBtn('trans', 'Transitive') + '</div></div>';
  h += '<div class="list"><div class="row head"><span>Package</span><span>Version</span><span>Type</span><span>Ecosystem</span><span>Status</span></div>';
  if (!list.length) h += '<div class="empty"><b>No packages match</b>Clear the filter to see every dependency.</div>';
  h += list.slice(0, ui.depShown).map((d) => {
    const g = byKey.get(depKey(d)) || { worst: 'NONE' };
    return '<div class="row"><span class="mono" title="' + esc(d.Name) + '">' + esc(d.Name) + '</span><span class="mono v" title="' + esc(d.Version) + '">' + esc(d.Version) + '</span>' +
      '<span style="color:var(--muted);font-size:13px">' + (d.Direct ? 'Direct' : 'Transitive') + '</span><span style="color:var(--muted);font-size:13px">' + esc(d.Ecosystem) + '</span>' +
      '<span class="dot" style="--c:' + SEV[g.worst].c + '">' + (g.worst === 'NONE' ? 'Clean' : SEV[g.worst].label) + '</span></div>';
  }).join('') + '</div>';
  if (list.length > ui.depShown) h += '<button class="ghost more" type="button" id="moreDeps">Show 60 more of ' + (list.length - ui.depShown) + '</button>';
  $('panel').innerHTML = h;

  const input = $('depQ');
  input.oninput = () => { ui.depQ = input.value; ui.depShown = 60; const pos = input.selectionStart; renderDeps(); const n = $('depQ'); n.focus(); n.setSelectionRange(pos, pos); };
  $('depSeg').onclick = (e) => { const b = e.target.closest('button'); if (b) { ui.depFilter = b.dataset.f; ui.depShown = 60; renderDeps(); } };
  const more = $('moreDeps'); if (more) more.onclick = () => { ui.depShown += 60; renderDeps(); };
  $('panel').onclick = null;
}

async function renderHistory() {
  $('panel').innerHTML = '<div class="toolbar"></div><div class="list"><div class="empty">Loading history…</div></div>';
  let recs = [];
  try { recs = await (await fetch('/scans')).json(); } catch (e) {}
  if (ui.tab !== 'history') return;
  recs.sort((a, b) => new Date(b.scanned_at) - new Date(a.scanned_at));
  let h = '<div class="toolbar"><span style="color:var(--muted);font-size:13.5px">Scans from this server session. They are kept in memory until the server restarts.</span></div><div class="list">';
  h += '<div class="row head hist" style="cursor:default"><span>Folder</span><span>Result</span><span>When</span></div>';
  h += recs.map((r) => {
    const v = (r.result && r.result.Violations || []).length, w = (r.result && r.result.Warnings || []).length;
    const c = v ? 'var(--critical)' : w ? 'var(--medium)' : 'var(--clean)';
    return '<button type="button" class="row hist" data-id="' + esc(r.id) + '"><span class="mono" title="' + esc(r.path) + '">' + esc(r.path) + '</span>' +
      '<span class="dot" style="--c:' + c + '">' + (v ? 'Blocked' : w ? 'Warnings' : 'Passed') + '</span><span style="color:var(--muted);font-size:13px">' + esc(ago(r.scanned_at)) + '</span></button>';
  }).join('') + (recs.length ? '' : '<div class="empty"><b>No scans yet</b>Scan a folder and it shows up here.</div>') + '</div>';
  $('panel').innerHTML = h;
  $('panel').onclick = (e) => { const b = e.target.closest('.hist[data-id]'); if (!b) return; const r = recs.find((x) => x.id === b.dataset.id); if (r) { $('path').value = r.path; render(r); } };
}

function ago(t) {
  const s = (Date.now() - new Date(t)) / 1000;
  if (s < 60) return 'Just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return new Date(t).toLocaleString();
}

/* ---------- small helpers ---------- */
function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.add('on');
  clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove('on'), 1800);
}
async function copyText(s) {
  try { await navigator.clipboard.writeText(s); toast('Copied: ' + s); }
  catch (e) { prompt('Copy this command', s); }
}
function exportJSON() {
  const r = Object.assign({}, ui.record); delete r._ms;
  const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'depscan-' + (r.id || 'report') + '.json';
  a.click(); URL.revokeObjectURL(a.href);
  toast('Exported report');
}

/* ---------- panes: Scan and How it works ---------- */
const PANES = { scan: $('paneScan'), how: $('paneHow') };
const paneScroll = { scan: 0, how: 0 };
function moveNavInd(instant) {
  const a = document.querySelector('.nav a[aria-current="page"]'), ind = $('navInd');
  if (!a || !ind) return;
  if (instant) ind.style.transition = 'none';
  ind.style.width = a.offsetWidth + 'px';
  ind.style.transform = 'translateX(' + (a.offsetLeft - 4) + 'px)';
  if (instant) { void ind.offsetWidth; ind.style.transition = ''; }
}
function route(first) {
  const name = location.hash === '#how' ? 'how' : 'scan';
  if (name === ui.pane) return;
  const prev = ui.pane;
  if (prev) paneScroll[prev] = scrollY;
  ui.pane = name;
  for (const k in PANES) PANES[k].hidden = k !== name;
  document.querySelectorAll('.nav a').forEach((a) => { if (a.dataset.pane === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  moveNavInd(first === true);
  document.title = name === 'how' ? 'How a scan works · DepScan' : 'DepScan';
  if (first !== true) {
    const el = PANES[name];
    el.classList.remove('enter'); void el.offsetWidth; el.classList.add('enter');
    scrollTo({ top: paneScroll[name] || 0, behavior: 'instant' });
  }
  const demo = window.DepscanDemo;
  if (demo) { if (name === 'how') demo.enter(); else demo.leave(); }
  if (name === 'scan' && sky) dispatchEvent(new Event('resize'));
}
function go(name) {
  const h = name === 'how' ? '#how' : '#scan';
  if (location.hash !== h) history.pushState(null, '', h);
  route();
}
addEventListener('hashchange', route);
addEventListener('popstate', route);
document.addEventListener('click', (e) => {
  const a = e.target.closest('a[href="#how"], a[href="#scan"]');
  if (!a || e.metaKey || e.ctrlKey || e.shiftKey) return;
  e.preventDefault(); go(a.getAttribute('href') === '#how' ? 'how' : 'scan');
});
// "See it in the walkthrough" from the Learn panel.
document.addEventListener('depscan:watch', (e) => {
  go('how');
  if (window.DepscanDemo) window.DepscanDemo.goChapter(e.detail.chapter, true);
});
// The walkthrough's last screen sends people back here.
document.addEventListener('depscan:try', () => {
  go('scan');
  setTimeout(() => { $('path').focus({ preventScroll: true }); $('scanForm').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' }); }, 80);
});

/* ---------- wiring ---------- */
$('rootLabel').textContent = ROOT;
$('rootLabel').title = ROOT;
$('path').placeholder = ROOT + SEP + 'your-project';
$('skel').innerHTML = Array.from({ length: 48 }, (_, i) => '<i style="--i:' + i + '"></i>').join('');
$('ask').innerHTML = words($('ask').textContent);
$('scanForm').onsubmit = (e) => { e.preventDefault(); runScan(); };
$('cancelBtn').onclick = () => controller && controller.abort();
$('recent').onclick = (e) => { const b = e.target.closest('.chip'); if (b) runScan(b.dataset.path); };
addEventListener('keydown', (e) => {
  if (ui.pane !== 'scan') return;
  if (e.key === '/' && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); $('path').focus(); $('path').select(); }
  if (e.key === 'Escape' && controller) controller.abort();
});
addEventListener('resize', () => {
  moveNavInd(true);
  if (ui.model) { const a = document.querySelector('.tab[aria-selected="true"]'), bar = $('tabBar'); if (a && bar) { bar.style.width = a.offsetWidth + 'px'; bar.style.transform = 'translateX(' + a.offsetLeft + 'px)'; } }
});
if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => moveNavInd(true));
renderRecent();
route(true);
