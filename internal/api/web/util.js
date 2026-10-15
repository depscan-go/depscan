/* Shared helpers for the depscan dashboard: DOM, formatting, severities,
   versions, licenses, links and commands. Everything hangs off window.DS. */
(function () {
  'use strict';
  const DS = (window.DS = window.DS || {});

  /* ---------- DOM ---------- */
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const plural = (n, one, many) => fmtN(n) + ' ' + (n === 1 ? one : (many || one + 's'));
  const fmtN = (n) => Number(n).toLocaleString('en-US');
  const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function fmtMs(ms) {
    if (ms == null || !isFinite(ms)) return '';
    if (ms < 1000) return Math.round(ms) + ' ms';
    if (ms < 60000) return (ms / 1000).toFixed(1) + ' s';
    const s = Math.round(ms / 1000);
    return Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
  }
  function ago(t) {
    const d = new Date(t), s = (Date.now() - d) / 1000;
    if (!isFinite(s)) return '';
    if (s < 45) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    if (s < 86400 * 7) { const n = Math.round(s / 86400); return n === 1 ? 'yesterday' : n + ' days ago'; }
    return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: d.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' });
  }
  function when(t) {
    const d = new Date(t);
    return d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  /* ---------- toast, copy, download ---------- */
  // A short message at the bottom. It stays longer when there is more to read,
  // and a hairline under it runs down for as long as it stays.
  function toast(msg, kind) {
    const t = $('toast'); if (!t) return;
    const life = Math.min(5200, Math.max(2200, 1200 + String(msg).length * 38));
    t.innerHTML = '<span class="ti">' + (kind === 'bad' ? TOAST_BAD : TOAST_OK) + '</span><span>' + esc(msg) + '</span><i class="tl" aria-hidden="true"></i>';
    t.dataset.kind = kind || '';
    t.style.setProperty('--life', life + 'ms');
    t.classList.remove('on'); void t.offsetWidth; t.classList.add('on');
    clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove('on'), life);
  }
  const TOAST_OK = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3.5 8.5 3 3 6-7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const TOAST_BAD = '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 4.8v3.8M8 11.1v.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>';
  async function copy(text, label) {
    try { await navigator.clipboard.writeText(text); toast(label || 'Copied'); return true; }
    catch (e) {
      // http://127.0.0.1 is a secure context, but fall back for older browsers.
      const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
      ta.remove(); toast(ok ? (label || 'Copied') : 'Copy failed: select the text and copy it yourself', ok ? '' : 'bad');
      return ok;
    }
  }
  function download(name, text, type) {
    const blob = text instanceof Blob ? text : new Blob([text], { type: type || 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }
  const slug = (s) => String(s || 'scan').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'scan';

  /* ---------- severities ----------
     OSV records carry GitHub's database severity: CRITICAL, HIGH, MODERATE,
     LOW. Records without one (most GO- entries) come through as UNKNOWN. */
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const SEV = {
    CRITICAL: { label: 'Critical', v: 'critical', w: 10 },
    HIGH: { label: 'High', v: 'high', w: 6 },
    MEDIUM: { label: 'Moderate', v: 'medium', w: 3 },
    LOW: { label: 'Low', v: 'low', w: 1 },
    UNKNOWN: { label: 'Unrated', v: 'unknown', w: 1 },
    NONE: { label: 'No known issues', v: 'clean', w: 0 }
  };
  const sevOf = (s) => { s = String(s || '').toUpperCase(); if (s === 'MODERATE') return 'MEDIUM'; return SEV[s] && s !== 'NONE' ? s : 'UNKNOWN'; };
  const sevRank = (s) => (s === 'NONE' ? 9 : SEVS.indexOf(s));
  const sevColor = (s, text) => 'var(--' + SEV[s].v + (text ? '-t' : '') + ')';

  /* ---------- versions ---------- */
  const nv = (v) => String(v || '').replace(/^v/, '');
  function cmpVer(a, b) {
    const split = (v) => { const m = nv(v).split('+')[0]; const i = m.indexOf('-'); return [i < 0 ? m : m.slice(0, i), i < 0 ? '' : m.slice(i + 1)]; };
    const [ca, pa] = split(a), [cb, pb] = split(b);
    const xa = ca.split('.'), xb = cb.split('.');
    for (let i = 0; i < Math.max(xa.length, xb.length); i++) {
      const x = xa[i] || '0', y = xb[i] || '0';
      const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
      const c = nx && ny ? (parseInt(x, 10) - parseInt(y, 10)) : x.localeCompare(y);
      if (c) return c;
    }
    if (pa === pb) return 0;
    if (!pa) return 1; // 1.0.0 > 1.0.0-rc.1
    if (!pb) return -1;
    return pa.localeCompare(pb, undefined, { numeric: true });
  }
  const maxVer = (list) => list.filter(Boolean).sort(cmpVer).pop() || '';

  /* ---------- licenses ----------
     A faithful port of internal/license (Unknown, Check, normalizeID), so
     the page can evaluate a license someone types in during a review. */
  const licUnknown = (expr) => { const e = String(expr || '').trim(); return e === '' || /^noassertion$/i.test(e) || /^non-standard$/i.test(e); };
  const normID = (id) => (id.endsWith('+') ? id.slice(0, -1) + '-or-later' : id);
  function licIds(expr) {
    const tokens = String(expr).replace(/[()]/g, ' ').split(/\s+/).filter(Boolean);
    const ids = []; let hasOr = false, hasAnd = false;
    for (let i = 0; i < tokens.length; i++) {
      const u = tokens[i].toUpperCase();
      if (u === 'OR') hasOr = true;
      else if (u === 'AND') hasAnd = true;
      else if (u === 'WITH') i++;
      else ids.push(normID(tokens[i]));
    }
    return { ids, hasOr, hasAnd };
  }
  // Same rules as license.Check(expr, DenySet(denied), true).
  function licCheck(expr, denied) {
    if (licUnknown(expr)) return { ok: true, unknown: true, denied: [] };
    const deny = new Set((denied || []).map((d) => normID(String(d).trim()).toLowerCase()));
    const { ids, hasOr, hasAnd } = licIds(expr);
    const bad = ids.filter((id) => deny.has(id.toLowerCase()));
    if (hasOr && !hasAnd) return { ok: bad.length < ids.length, denied: bad, choice: true };
    return { ok: bad.length === 0, denied: bad };
  }

  // License families, from least to most restrictive.
  const FAM = {
    pd: { label: 'Public domain', v: 'fam-pd', rank: 0, about: 'No conditions at all.' },
    perm: { label: 'Permissive', v: 'fam-perm', rank: 1, about: 'Use freely; keep the copyright notice.' },
    weak: { label: 'Weak copyleft', v: 'fam-weak', rank: 2, about: 'Changes to these files must be shared; your own code stays yours.' },
    other: { label: 'Other', v: 'fam-other', rank: 2.5, about: 'An SPDX license outside the common families. Read it.' },
    strong: { label: 'Strong copyleft', v: 'fam-strong', rank: 3, about: 'Shipping it can require releasing your source under the same license.' },
    restr: { label: 'Restricted', v: 'fam-restr', rank: 4, about: 'Source-available or non-commercial terms. Often not allowed in products.' },
    unknown: { label: 'Unknown', v: 'fam-unknown', rank: 5, about: 'deps.dev had no SPDX license for this version.' }
  };
  const FAM_IDS = {
    pd: ['CC0-1.0', 'Unlicense', '0BSD', 'MIT-0', 'WTFPL', 'CC-PDDC', 'PDDL-1.0'],
    perm: ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear', 'Apache-2.0', 'Zlib', 'BSL-1.0', 'Python-2.0', 'PSF-2.0', 'X11', 'BlueOak-1.0.0', 'Unicode-DFS-2016', 'Unicode-3.0', 'CC-BY-3.0', 'CC-BY-4.0', 'OFL-1.1', 'PostgreSQL', 'NCSA', 'Artistic-2.0', 'MIT-CMU', 'ISC-Veillard', 'BSD-1-Clause', 'Apache-1.1', 'AFL-3.0', 'curl', 'libpng-2.0', 'JSON', 'Ruby'],
    weak: ['MPL-1.1', 'MPL-2.0', 'MPL-2.0-no-copyleft-exception', 'LGPL-2.0', 'LGPL-2.0-only', 'LGPL-2.0-or-later', 'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0', 'CDDL-1.1', 'MS-RL', 'CPL-1.0', 'CC-BY-SA-4.0'],
    strong: ['GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later', 'AGPL-1.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'EUPL-1.1', 'EUPL-1.2', 'OSL-3.0', 'RPL-1.5', 'SSPL-1.0-like'],
    restr: ['SSPL-1.0', 'BUSL-1.1', 'Elastic-2.0', 'CC-BY-NC-4.0', 'CC-BY-NC-SA-4.0', 'CC-BY-NC-ND-4.0', 'CC-BY-NC-3.0', 'CC-BY-ND-4.0', 'Commons-Clause', 'PolyForm-Noncommercial-1.0.0', 'PolyForm-Small-Business-1.0.0']
  };
  const famOfId = new Map();
  Object.keys(FAM_IDS).forEach((f) => FAM_IDS[f].forEach((id) => famOfId.set(id.toLowerCase(), f)));
  function licFamily(expr) {
    if (licUnknown(expr)) return 'unknown';
    const { ids, hasOr, hasAnd } = licIds(expr);
    const fams = ids.map((id) => famOfId.get(id.toLowerCase()) || (/^LicenseRef-/i.test(id) ? 'other' : 'other'));
    if (!fams.length) return 'unknown';
    const byRank = fams.slice().sort((a, b) => FAM[a].rank - FAM[b].rank);
    // "A OR B": you may pick the easier one. "A AND B": you must meet both.
    return hasOr && !hasAnd ? byRank[0] : byRank[byRank.length - 1];
  }
  const SPDX_COMMON = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC', 'MPL-2.0', 'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'EPL-2.0', 'CDDL-1.0', 'Unlicense', 'CC0-1.0', '0BSD', 'MIT-0', 'Zlib', 'BSL-1.0', 'Python-2.0', 'BlueOak-1.0.0', 'Artistic-2.0', 'Unicode-3.0', 'OFL-1.1', 'CC-BY-4.0', 'EUPL-1.2', 'BUSL-1.1', 'SSPL-1.0', 'Elastic-2.0', 'CC-BY-NC-4.0', 'MIT OR Apache-2.0'];

  /* ---------- identities, links and commands ---------- */
  const depKey = (d) => d.Ecosystem + '|' + d.Name + '@' + d.Version;
  const goV = (v) => 'v' + nv(v);
  const verOf = (d, v) => (d.Ecosystem === 'Go' ? goV(v == null ? d.Version : v) : (v == null ? d.Version : v));
  function purl(d) {
    if (d.Ecosystem === 'Go') return 'pkg:golang/' + d.Name + '@' + goV(d.Version);
    if (d.Ecosystem === 'npm') { const n = d.Name.startsWith('@') ? '%40' + d.Name.slice(1) : d.Name; return 'pkg:npm/' + n + '@' + d.Version; }
    return 'pkg:generic/' + d.Name + '@' + d.Version;
  }
  const enc = encodeURIComponent;
  const links = {
    pkg(d) {
      if (d.Ecosystem === 'Go') return 'https://pkg.go.dev/' + d.Name + '@' + goV(d.Version);
      if (d.Ecosystem === 'npm') return 'https://www.npmjs.com/package/' + d.Name + '/v/' + enc(d.Version);
      return '';
    },
    license(d) {
      if (d.Ecosystem === 'Go') return 'https://pkg.go.dev/' + d.Name + '@' + goV(d.Version) + '?tab=licenses';
      if (d.Ecosystem === 'npm') return 'https://www.npmjs.com/package/' + d.Name + '/v/' + enc(d.Version);
      return '';
    },
    depsdev(d) {
      if (d.Ecosystem === 'Go') return 'https://deps.dev/go/' + enc(d.Name) + '/' + goV(d.Version);
      if (d.Ecosystem === 'npm') return 'https://deps.dev/npm/' + enc(d.Name) + '/' + enc(d.Version);
      return '';
    },
    // Best effort: the source repository for common Go module hosts.
    repo(d) {
      if (d.Ecosystem !== 'Go') return '';
      const n = d.Name, p = n.split('/');
      if (/^(github\.com|gitlab\.com|bitbucket\.org)$/.test(p[0]) && p.length >= 3) return 'https://' + p.slice(0, 3).join('/');
      if (p[0] === 'golang.org' && p[1] === 'x' && p[2]) return 'https://github.com/golang/' + p[2];
      if (p[0] === 'k8s.io' && p[1]) return 'https://github.com/kubernetes/' + p[1];
      if (p[0] === 'sigs.k8s.io' && p[1]) return 'https://github.com/kubernetes-sigs/' + p[1];
      if (n.startsWith('google.golang.org/grpc')) return 'https://github.com/grpc/grpc-go';
      if (n.startsWith('google.golang.org/protobuf')) return 'https://github.com/protocolbuffers/protobuf-go';
      if (p[0] === 'gopkg.in' && p[1]) { const m = p[1].match(/^([^.]+)\.v\d+$/); if (m) return 'https://github.com/go-' + m[1] + '/' + m[1]; }
      if (p[0] === 'go.opentelemetry.io') return 'https://github.com/open-telemetry/opentelemetry-go';
      return '';
    },
    advisory(id) {
      if (/^GHSA-/i.test(id)) return 'https://github.com/advisories/' + id;
      if (/^CVE-/i.test(id)) return 'https://nvd.nist.gov/vuln/detail/' + id;
      if (/^GO-/i.test(id)) return 'https://pkg.go.dev/vuln/' + id;
      return 'https://osv.dev/vulnerability/' + enc(id);
    },
    osv: (id) => 'https://osv.dev/vulnerability/' + enc(id)
  };
  const cmd = {
    upgrade(d, v) {
      if (d.Ecosystem === 'Go') return 'go get ' + d.Name + '@' + goV(v);
      if (d.Ecosystem === 'npm') return 'npm install ' + d.Name + '@' + v;
      return '';
    },
    why(d) {
      if (d.Ecosystem === 'Go') return 'go mod why -m ' + d.Name;
      if (d.Ecosystem === 'npm') return 'npm explain ' + d.Name;
      return '';
    },
    override(d, v) {
      return '"overrides": {\n  "' + d.Name + '": "' + v + '"\n}';
    }
  };

  /* ---------- small rendering helpers ---------- */
  const icon = {
    folder: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M2.5 6a1.5 1.5 0 0 1 1.5-1.5h3.6l1.6 1.6H16A1.5 1.5 0 0 1 17.5 7.6v7A1.5 1.5 0 0 1 16 16.1H4A1.5 1.5 0 0 1 2.5 14.6z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>',
    path: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M4 15.5h12M5.5 12.5 9 4.5h2l3.5 8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M7 9.5h6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    pr: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="5.5" cy="4.8" r="1.8" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="5.5" cy="15.2" r="1.8" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="14.5" cy="15.2" r="1.8" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5.5 6.6v6.8M14.5 13.4V8.5a2.5 2.5 0 0 0-2.5-2.5H9.5m0 0 2-2m-2 2 2 2" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    copy: '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="5" y="5" width="8.5" height="8.5" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M10.5 3.6V3A1.5 1.5 0 0 0 9 1.5H3A1.5 1.5 0 0 0 1.5 3v6A1.5 1.5 0 0 0 3 10.5h.6" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>',
    ext: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M9.5 2.5h4v4M13.5 2.5 7.5 8.5M11.5 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    chev: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m6 3.5 4.5 4.5L6 12.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    check: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3.5 8.5 3 3 6-7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    search: '<svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="9" cy="9" r="5.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m13.2 13.2 3.6 3.6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    download: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2v8m0 0-3-3m3 3 3-3M2.5 11.5v1a1.5 1.5 0 0 0 1.5 1.5h8a1.5 1.5 0 0 0 1.5-1.5v-1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    trash: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 4.5h10M6.5 4.5V3a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v1.5M4.5 4.5l.6 8.6a1 1 0 0 0 1 .9h3.8a1 1 0 0 0 1-.9l.6-8.6" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    redo: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M13 3.5v3.5H9.5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M12.6 7A5 5 0 1 0 13 10" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
  };
  const ext = (href, label, cls) => href ? '<a class="' + (cls || 'xlink') + '" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + label + icon.ext + '</a>' : '';
  const codeBlock = (text, label) => '<div class="code"><pre>' + esc(text) + '</pre><button class="code-copy" type="button" data-copy="' + esc(text) + '" aria-label="Copy ' + esc(label || 'command') + '">' + icon.copy + '<span>Copy</span></button></div>';

  // Splits a heading into words for the reveal; the full sentence stays the accessible name.
  function splitWords(el) {
    if (!el || el.dataset.split === 'done') return;
    const text = el.textContent.trim();
    el.setAttribute('aria-label', text);
    el.innerHTML = text.split(/\s+/).map((w, i) => '<span class="w" aria-hidden="true"><span style="--i:' + i + '">' + esc(w) + '</span></span>').join(' ');
    el.dataset.split = 'done';
  }

  // Counts numbers up once, quickly, so the eye lands on them.
  function countUp(root) {
    const els = root.querySelectorAll('[data-n]');
    if (reduced()) { els.forEach((el) => { el.textContent = fmtN(+el.dataset.n); }); return; }
    const t0 = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - t0) / 900), e = 1 - Math.pow(1 - k, 3);
      els.forEach((el) => { el.textContent = fmtN(Math.round(+el.dataset.n * e)); });
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // A focus-trapping side sheet used for package details and license reviews.
  const sheet = (() => {
    let lastFocus = null, onClose = null, closing = 0;
    const el = () => $('sheet');
    function open(o) {
      const s = el();
      // Opening again while the last one is still sliding out: keep the sheet, drop the pending hide.
      if (closing) { clearTimeout(closing); closing = 0; }
      $('sheetKicker').innerHTML = o.kicker || '';
      $('sheetTitle').innerHTML = o.title || '';
      $('sheetBody').innerHTML = o.body || '';
      $('sheetBody').scrollTop = 0;
      onClose = o.onClose || null;
      if (s.hidden || !s.classList.contains('on')) {
        if (s.hidden) lastFocus = document.activeElement;
        s.hidden = false; void s.offsetWidth; s.classList.add('on');
        document.documentElement.classList.add('sheet-open');
      }
      if (o.wire) o.wire($('sheetBody'));
      $('sheetBody').scrollTop = 0;
      requestAnimationFrame(() => { $('sheetBody').scrollTop = 0; });
      setTimeout(() => s.querySelector('.sheet-panel').focus({ preventScroll: true }), 30);
    }
    function close() {
      const s = el(); if (s.hidden || !s.classList.contains('on')) return;
      s.classList.remove('on');
      document.documentElement.classList.remove('sheet-open');
      const done = () => { closing = 0; s.hidden = true; $('sheetBody').innerHTML = ''; };
      // Hide only after the panel has slid all the way out (.5s in app.css).
      if (reduced()) done(); else closing = setTimeout(done, 520);
      if (onClose) { const f = onClose; onClose = null; f(); }
      if (lastFocus && document.contains(lastFocus)) lastFocus.focus({ preventScroll: true });
    }
    document.addEventListener('click', (e) => { if (e.target.closest('#sheet [data-close]')) close(); });
    document.addEventListener('keydown', (e) => {
      const s = el(); if (!s || s.hidden || !s.classList.contains('on')) return;
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); return; }
      if (e.key === 'Tab') {
        const f = Array.from(s.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), textarea, select, [tabindex]:not([tabindex="-1"])')).filter((x) => x.offsetParent !== null);
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    }, true);
    return { open, close, get isOpen() { const s = el(); return !!s && !s.hidden && s.classList.contains('on'); } };
  })();

  // Any [data-copy] button copies its text.
  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-copy]');
    if (!b) return;
    e.preventDefault(); e.stopPropagation();
    copy(b.dataset.copy, b.dataset.copyLabel || 'Copied to the clipboard').then((ok) => {
      if (!ok) return;
      // The button itself says it worked: a tick and "Copied", at the same width, then back.
      if (!b.classList.contains('done')) {
        b._was = b.innerHTML;
        b.style.minWidth = b.offsetWidth + 'px';
        const label = b.querySelector('span') || b.textContent.trim() ? '<span>Copied</span>' : '';
        b.innerHTML = icon.check + label;
      }
      b.classList.add('done');
      clearTimeout(b._done);
      b._done = setTimeout(() => { b.classList.remove('done'); if (b._was != null) { b.innerHTML = b._was; b._was = null; } b.style.minWidth = ''; }, 1600);
    });
  });

  // Parts of a page settle in as they scroll into view, once. The classes come
  // off when the motion is over, so hover and other transitions work as before.
  const revealIO = 'IntersectionObserver' in window ? new IntersectionObserver((en) => {
    en.forEach((x) => {
      if (!x.isIntersecting) return;
      const el = x.target, d = +el.style.getPropertyValue('--d') || 0;
      revealIO.unobserve(el);
      el.classList.add('in');
      setTimeout(() => { el.classList.remove('rv', 'rv-line', 'in'); el.style.removeProperty('--d'); }, 2200 + d * 75);
    });
  }, { rootMargin: '0px 0px -6% 0px', threshold: 0.06 }) : null;
  // reveal(elements, { line: true } for a survey line along the top hairline, { rise: false } to keep it in place)
  function reveal(items, o) {
    o = o || {};
    if (!revealIO || reduced()) return;
    Array.from(items || []).forEach((el, i) => {
      if (!el || el.classList.contains('rv') || el.classList.contains('rv-line')) return;
      if (o.rise !== false) el.classList.add('rv');
      if (o.line) el.classList.add('rv-line');
      el.style.setProperty('--d', String(o.stagger === false ? 0 : Math.min(i, 8) + (o.offset || 0)));
      revealIO.observe(el);
    });
  }

  // Rows that scroll sideways (tabs, filters, chapters) fade at the edge that has more.
  const EDGE_SEL = '.tabs, .toolbar .seg, .chapters';
  function syncEdge(el) {
    const max = el.scrollWidth - el.clientWidth;
    el.classList.toggle('edge-l', max > 2 && el.scrollLeft > 2);
    el.classList.toggle('edge-r', max > 2 && el.scrollLeft < max - 2);
  }
  function edges(root) { (root || document).querySelectorAll(EDGE_SEL).forEach(syncEdge); }
  document.addEventListener('scroll', (e) => { const el = e.target; if (el && el.matches && el.matches(EDGE_SEL)) syncEdge(el); }, { capture: true, passive: true });
  addEventListener('resize', () => edges());
  // Watch a part of the page that redraws itself (filters, tabs) and keep its edges right.
  function watchEdges(el) {
    if (!el || !('MutationObserver' in window)) return;
    let raf = 0;
    new MutationObserver(() => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; edges(el); }); }).observe(el, { childList: true, subtree: true });
  }

  Object.assign(DS, {
    reveal, edges, watchEdges,
    $, esc, reduced, plural, fmtN, clamp, fmtBytes, fmtMs, ago, when, toast, copy, download, slug,
    SEVS, SEV, sevOf, sevRank, sevColor, nv, cmpVer, maxVer,
    licUnknown, licCheck, licFamily, licIds, FAM, SPDX_COMMON,
    depKey, purl, verOf, links, cmd, icon, ext, codeBlock, splitWords, countUp, sheet,
    ROOT: String(window.DEPSCAN_ROOT || '')
  });
})();
