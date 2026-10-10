/* How it works: a frame-exact walkthrough of one scan.
   Every frame is a pure function of the playhead, so pausing, scrubbing,
   changing speed or jumping to a step always lands on the same picture.
   The stage has two layouts: wide (960 x 560) and narrow (480 x 720). */
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const pane = $('paneHow'), canvas = $('demoCanvas');
  if (!pane || !canvas) return;
  const ctx = canvas.getContext('2d');
  const Hash = window.DepscanHash;

  /* ======================= sample project ======================= */
  // A made-up project built from real OSV.dev records (checked October 2026),
  // trimmed so the walkthrough stays short.
  const PKGS = [
    { id: 'gin', eco: 'Go', name: 'github.com/gin-gonic/gin', s: 'gin', v: 'v1.9.0', direct: true, lic: 'MIT' },
    { id: 'jwt', eco: 'Go', name: 'github.com/golang-jwt/jwt/v4', s: 'jwt/v4', v: 'v4.5.0', direct: true, lic: 'MIT' },
    { id: 'crypto', eco: 'Go', name: 'golang.org/x/crypto', s: 'x/crypto', v: 'v0.14.0', direct: true, lic: 'BSD-3-Clause' },
    { id: 'net', eco: 'Go', name: 'golang.org/x/net', s: 'x/net', v: 'v0.10.0', direct: false, lic: 'BSD-3-Clause', up: ['gin'] },
    { id: 'sys', eco: 'Go', name: 'golang.org/x/sys', s: 'x/sys', v: 'v0.8.0', direct: false, lic: 'BSD-3-Clause', up: ['net', 'crypto', 'isatty'] },
    { id: 'text', eco: 'Go', name: 'golang.org/x/text', s: 'x/text', v: 'v0.9.0', direct: false, lic: 'BSD-3-Clause', up: ['net'] },
    { id: 'validator', eco: 'Go', name: 'github.com/go-playground/validator/v10', s: 'validator', v: 'v10.14.0', direct: false, lic: 'MIT', up: ['gin'] },
    { id: 'jsoniter', eco: 'Go', name: 'github.com/json-iterator/go', s: 'json-iter', v: 'v1.1.12', direct: false, lic: 'MIT', up: ['gin'] },
    { id: 'isatty', eco: 'Go', name: 'github.com/mattn/go-isatty', s: 'go-isatty', v: 'v0.0.19', direct: false, lic: 'MIT', up: ['gin'] },
    { id: 'sonic', eco: 'Go', name: 'github.com/bytedance/sonic', s: 'sonic', v: 'v1.9.1', direct: false, lic: 'Apache-2.0', up: ['gin'] },
    { id: 'codec', eco: 'Go', name: 'github.com/ugorji/go/codec', s: 'codec', v: 'v1.2.11', direct: false, lic: 'MIT', up: ['gin'] },
    { id: 'axios', eco: 'npm', name: 'axios', s: 'axios', v: '0.21.1', direct: true, lic: 'MIT' },
    { id: 'ffmpeg', eco: 'npm', name: 'ffmpeg-static', s: 'ffmpeg-static', v: '5.2.0', direct: true, lic: 'GPL-3.0-or-later' },
    { id: 'uikit', eco: 'npm', name: '@shop/ui-kit', s: '@shop/ui-kit', v: '2.3.0', direct: true, lic: '' },
    { id: 'follow', eco: 'npm', name: 'follow-redirects', s: 'follow-redirects', v: '1.14.0', direct: false, lic: 'MIT', up: ['axios'] },
    { id: 'httpbasic', eco: 'npm', name: '@derhuerst/http-basic', s: 'http-basic', v: '8.2.4', direct: false, lic: 'MIT', up: ['ffmpeg'] },
    { id: 'hpa', eco: 'npm', name: 'https-proxy-agent', s: 'https-proxy-agent', v: '5.0.1', direct: false, lic: 'MIT', up: ['ffmpeg'] },
    { id: 'agentbase', eco: 'npm', name: 'agent-base', s: 'agent-base', v: '6.0.2', direct: false, lic: 'MIT', up: ['hpa'] },
    { id: 'debug', eco: 'npm', name: 'debug', s: 'debug', v: '4.3.4', direct: false, lic: 'MIT', up: ['hpa', 'agentbase'] },
    { id: 'ms', eco: 'npm', name: 'ms', s: 'ms', v: '2.1.2', direct: false, lic: 'MIT', up: ['debug'] },
    { id: 'envpaths', eco: 'npm', name: 'env-paths', s: 'env-paths', v: '2.2.1', direct: false, lic: 'MIT', up: ['ffmpeg'] },
    { id: 'progress', eco: 'npm', name: 'progress', s: 'progress', v: '2.0.3', direct: false, lic: 'MIT', up: ['ffmpeg'] }
  ];
  const PK = Object.fromEntries(PKGS.map((p) => [p.id, p]));
  const GO = PKGS.filter((p) => p.eco === 'Go'), NPM = PKGS.filter((p) => p.eco === 'npm');

  // The 15 records OSV.dev returns, before duplicates are merged. g = alias group.
  const RAW = [
    { id: 'GHSA-2c4m-59x9-fr2g', pkg: 'gin', sev: 'MODERATE', g: 'A', cve: 'CVE-2023-29401' },
    { id: 'GO-2023-1737', pkg: 'gin', sev: null, g: 'A', cve: 'CVE-2023-29401' },
    { id: 'GHSA-mh63-6h87-95cp', pkg: 'jwt', sev: 'HIGH', g: 'B', cve: 'CVE-2025-30204' },
    { id: 'GO-2025-3553', pkg: 'jwt', sev: null, g: 'B', cve: 'CVE-2025-30204' },
    { id: 'GHSA-v778-237x-gjrc', pkg: 'crypto', sev: 'CRITICAL', g: 'C', cve: 'CVE-2024-45337' },
    { id: 'GO-2024-3321', pkg: 'crypto', sev: null, g: 'C', cve: 'CVE-2024-45337' },
    { id: 'GHSA-hcg3-q754-cr77', pkg: 'crypto', sev: 'HIGH', g: 'D', cve: 'CVE-2025-22869' },
    { id: 'GO-2025-3487', pkg: 'crypto', sev: null, g: 'D', cve: 'CVE-2025-22869' },
    { id: 'GHSA-45x7-px36-x8w8', pkg: 'crypto', sev: 'MODERATE', g: 'E', cve: 'CVE-2023-48795' },
    { id: 'GO-2023-2402', pkg: 'crypto', sev: null, g: 'E', cve: 'CVE-2023-48795' },
    { id: 'GHSA-4374-p667-p6c8', pkg: 'net', sev: 'HIGH', g: 'F', cve: 'CVE-2023-39325' },
    { id: 'GO-2023-2102', pkg: 'net', sev: null, g: 'F', cve: 'CVE-2023-39325' },
    { id: 'GHSA-cph5-m8f7-6c5x', pkg: 'axios', sev: 'HIGH', g: 'G', cve: 'CVE-2021-3749' },
    { id: 'GHSA-wf5p-g6vw-rhxx', pkg: 'axios', sev: 'MODERATE', g: 'H', cve: 'CVE-2023-45857' },
    { id: 'GHSA-74fj-2j2h-c42q', pkg: 'follow', sev: 'HIGH', g: 'I', cve: 'CVE-2022-0155' }
  ];
  // After merging: one record per flaw, with the policy outcome.
  const ADV = [
    { id: 'GHSA-v778-237x-gjrc', pkg: 'crypto', sev: 'CRITICAL', fix: 'v0.31.0', out: 'block', why: 'Authorization bypass via PublicKeyCallback' },
    { id: 'GHSA-hcg3-q754-cr77', pkg: 'crypto', sev: 'HIGH', fix: 'v0.35.0', out: 'block', why: 'Denial of service in SSH key exchange' },
    { id: 'GHSA-mh63-6h87-95cp', pkg: 'jwt', sev: 'HIGH', fix: 'v4.5.2', out: 'block', why: 'Excessive memory use parsing headers' },
    { id: 'GHSA-4374-p667-p6c8', pkg: 'net', sev: 'HIGH', fix: 'v0.17.0', out: 'block', why: 'HTTP/2 rapid reset', trans: true },
    { id: 'GHSA-cph5-m8f7-6c5x', pkg: 'axios', sev: 'HIGH', fix: '0.21.2', out: 'block', why: 'Regular expression denial of service' },
    { id: 'GHSA-74fj-2j2h-c42q', pkg: 'follow', sev: 'HIGH', fix: '1.14.7', out: 'block', why: 'Leaks cookies across redirects', trans: true },
    { id: 'GHSA-45x7-px36-x8w8', pkg: 'crypto', sev: 'MODERATE', fix: 'v0.17.0', out: 'warn', why: 'Terrapin SSH prefix truncation' },
    { id: 'GHSA-wf5p-g6vw-rhxx', pkg: 'axios', sev: 'MODERATE', fix: '0.28.0', out: 'warn', why: 'Leaks the XSRF token to other hosts' },
    { id: 'GHSA-2c4m-59x9-fr2g', pkg: 'gin', sev: 'MODERATE', fix: 'v1.9.1', out: 'allow', why: 'Unsanitized FileAttachment filename' }
  ];

  const POLICY_TEXT = [
    'block_severities: [CRITICAL, HIGH]',
    'warn_severities:  [MODERATE, MEDIUM]',
    'check_transitive: true',
    'denied_licenses:',
    '  - GPL-3.0-or-later',
    '  - AGPL-3.0-only',
    'block_unknown_license: false',
    'exceptions:',
    '  - id: GHSA-2c4m-59x9-fr2g',
    '    reason: FileAttachment is not used',
    '    expires: 2026-12-31'
  ];
  const POLICY_SHA = Hash.sha256(POLICY_TEXT.join('\n') + '\n');

  // The report shown in step 9. Its digests are computed from exactly this text.
  const REPORT = (result) => [
    '{',
    '  "bomFormat": "CycloneDX",',
    '  "specVersion": "1.5",',
    '  "version": 1,',
    '  "metadata": {',
    '    "timestamp": "2026-10-10T04:00:15Z",',
    '    "component": { "type": "application", "name": "shop-api" },',
    '    "properties": [',
    '      { "name": "depscan:policy:sha256", "value": "' + POLICY_SHA.slice(0, 12) + '…" },',
    '      { "name": "depscan:result", "value": "' + result + '" },',
    '      { "name": "depscan:violations", "value": "7" },',
    '      { "name": "depscan:warnings", "value": "3" }',
    '    ]',
    '  },',
    '  "components": [',
    '    { "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.0" },',
    '    { "purl": "pkg:golang/golang.org/x/crypto@v0.14.0" },',
    '    … 20 more, sorted by purl',
    '  ],',
    '  "vulnerabilities": [',
    '    { "id": "GHSA-v778-237x-gjrc", "ratings": [ … ] },',
    '    … 8 more, sorted by id',
    '  ]',
    '}'
  ];
  const REPORT_FAIL = REPORT('fail'), REPORT_PASS = REPORT('pass');
  const TRACE = [];
  const DIGEST = Hash.sha256(REPORT_FAIL.join('\n') + '\n', TRACE);
  const DIGEST2 = Hash.sha256(REPORT_PASS.join('\n') + '\n');
  const DIFF = Array.from(DIGEST2, (c, i) => c !== DIGEST[i]);
  const DIFFN = DIFF.filter(Boolean).length;

  const HOOK_BODY = '{"action":"opened","number":42,"pull_request":{"head":{"sha":"9c1e2f7a4d"}},"repository":{"full_name":"you/shop-api"}}';
  const HOOK_SIG = Hash.hmac('demo-webhook-secret', HOOK_BODY);
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const TXID = Array.from({ length: 88 }, (_, i) => B58[parseInt(DIGEST.slice((i * 2) % 62, (i * 2) % 62 + 2), 16) % 58]).join('');

  /* ======================= palette and type ======================= */
  // The stage is always night, whatever the page theme: it reads like a screen.
  const P = {
    bg0: '#070B22', bg1: '#0E1640', panel: '#121B4A', panel2: '#19245A', panel3: '#22306E',
    line: '#2A3A7C', line2: '#3B4E99', text: '#EEF2FF', muted: '#AAB5E0', faint: '#7280B6',
    act: '#8270FF', act2: '#B3A8FF', crit: '#FF3D6E', high: '#FF8A1F', med: '#FFC83D', low: '#38BDF8',
    ok: '#2EE6A6', unk: '#8B93C9', white: '#FFFFFF'
  };
  const SEVC = { CRITICAL: P.crit, HIGH: P.high, MODERATE: P.med, MEDIUM: P.med, LOW: P.low };
  const sevc = (s) => SEVC[s] || P.unk;
  const SEVL = { CRITICAL: 'Critical', HIGH: 'High', MODERATE: 'Moderate' };
  const FONT = { s: '"IBM Plex Sans", system-ui, sans-serif', m: '"IBM Plex Mono", ui-monospace, monospace', d: '"Bricolage Grotesque", "IBM Plex Sans", sans-serif' };

  /* ======================= math ======================= */
  const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);
  const c01 = (v) => clamp(v, 0, 1);
  const k = (t, a, b) => c01((t - a) / (b - a));
  const mix = (a, b, t) => a + (b - a) * t;
  const E = {
    out: (t) => 1 - Math.pow(1 - c01(t), 3),
    out5: (t) => 1 - Math.pow(1 - c01(t), 5),
    in: (t) => Math.pow(c01(t), 3),
    io: (t) => { t = c01(t); return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; },
    back: (t) => { t = c01(t); const c1 = 1.70158, c3 = c1 + 1; return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2); },
    spring: (t) => { t = c01(t); return t === 0 ? 0 : t === 1 ? 1 : Math.pow(2, -9 * t) * Math.sin((t * 10 - 0.75) * (2 * Math.PI / 3.2)) + 1; }
  };
  const typed = (s, p) => s.slice(0, Math.floor(s.length * c01(p) + 1e-6));
  function seeded(seed) { return () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  const qpt = (a, c, b, t) => { const u = 1 - t; return [u * u * a[0] + 2 * u * t * c[0] + t * t * b[0], u * u * a[1] + 2 * u * t * c[1] + t * t * b[1]]; };
  const arcMid = (a, b, lift) => [(a[0] + b[0]) / 2, Math.min(a[1], b[1]) - (lift == null ? 60 : lift)];

  /* ======================= drawing kit ======================= */
  let BA = 1;               // base alpha, multiplied through nested fades
  let NOW = 0;              // local time of the scene being drawn (for idle wobble)
  const A = (a) => { ctx.globalAlpha = BA * (a == null ? 1 : a); };
  function fade(a, fn) { if (a <= 0.002) return; const p = BA; BA *= a; fn(); BA = p; }
  const rgbaCache = new Map();
  function rgba(hex, a) {
    let rgb = rgbaCache.get(hex);
    if (!rgb) { const n = parseInt(hex.slice(1), 16); rgb = [(n >> 16) & 255, (n >> 8) & 255, n & 255]; rgbaCache.set(hex, rgb); }
    return 'rgba(' + rgb[0] + ',' + rgb[1] + ',' + rgb[2] + ',' + a + ')';
  }
  function rr(x, y, w, h, r) {
    ctx.beginPath();
    if (ctx.roundRect) { ctx.roundRect(x, y, w, h, Math.max(0, Math.min(r, w / 2, h / 2))); return; }
    r = Math.max(0, Math.min(r, w / 2, h / 2));
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  // box(x, y, w, h, { r, fill, stroke, lw, dash, a, glow, shadow })
  function box(x, y, w, h, o) {
    o = o || {};
    rr(x, y, w, h, o.r == null ? 12 : o.r);
    if (o.shadow) { A(o.a); ctx.shadowColor = o.shadow; ctx.shadowBlur = o.blur || 28; ctx.shadowOffsetY = o.oy == null ? 10 : o.oy; ctx.fillStyle = o.fill || P.panel; ctx.fill(); ctx.shadowColor = 'transparent'; ctx.shadowBlur = 0; ctx.shadowOffsetY = 0; }
    if (o.glow) { A((o.a == null ? 1 : o.a) * (o.ga == null ? 1 : o.ga)); ctx.shadowColor = o.glow; ctx.shadowBlur = o.gb || 22; ctx.fillStyle = o.fill || P.panel; ctx.fill(); ctx.shadowColor = 'transparent'; ctx.shadowBlur = 0; }
    if (o.fill && !o.shadow && !o.glow) { A(o.a); ctx.fillStyle = o.fill; ctx.fill(); }
    if (o.stroke) { A((o.a == null ? 1 : o.a) * (o.sa == null ? 1 : o.sa)); ctx.lineWidth = o.lw || 1; ctx.strokeStyle = o.stroke; if (o.dash) { ctx.setLineDash(o.dash); ctx.lineDashOffset = o.off || 0; } ctx.stroke(); if (o.dash) ctx.setLineDash([]); }
  }
  const font = (o) => (o.w || 400) + ' ' + (o.size || 14) + 'px ' + FONT[o.f || 's'];
  function fit(s, max) {
    if (ctx.measureText(s).width <= max) return s;
    while (s.length > 1 && ctx.measureText(s + '…').width > max) s = s.slice(0, -1);
    return s + '…';
  }
  // T(text, x, y, { size, w, f, c, al, bl, a, max })
  function T(s, x, y, o) {
    o = o || {};
    ctx.font = font(o); ctx.textAlign = o.al || 'left'; ctx.textBaseline = o.bl || 'middle';
    A(o.a); ctx.fillStyle = o.c || P.text;
    if (o.max) s = fit(s, o.max);
    ctx.fillText(s, x, y);
  }
  const TW = (s, o) => { ctx.font = font(o || {}); return ctx.measureText(s).width; };
  // Text made of differently coloured runs: [[text, color], ...]
  function runs(parts, x, y, o) {
    o = o || {}; ctx.font = font(o); ctx.textAlign = 'left'; ctx.textBaseline = o.bl || 'middle';
    let cx = x;
    for (const [s, c, a] of parts) { A((o.a == null ? 1 : o.a) * (a == null ? 1 : a)); ctx.fillStyle = c || P.text; ctx.fillText(s, cx, y); cx += ctx.measureText(s).width; }
    return cx - x;
  }
  // pill(x, y, label, { c, h, size, f, w, fill, stroke, tc, a, al, icon }) -> width; y is the vertical centre
  function pill(x, y, label, o) {
    o = o || {};
    const h = o.h || 24, size = o.size || 12, pad = o.pad == null ? 10 : o.pad;
    const w = o.width || TW(label, { size, f: o.f || 'm', w: o.w || 500 }) + pad * 2 + (o.dot ? 12 : 0);
    const x0 = o.al === 'center' ? x - w / 2 : o.al === 'right' ? x - w : x;
    const c = o.c || P.act;
    box(x0, y - h / 2, w, h, { r: o.r == null ? h / 2 : o.r, fill: o.fill || rgba(c, 0.16), stroke: o.stroke || null, lw: o.lw || 1, dash: o.dash, a: o.a, glow: o.glow, gb: o.gb });
    if (o.dot) { A(o.a); ctx.fillStyle = c; ctx.beginPath(); ctx.arc(x0 + pad + 3, y, 3.5, 0, 7); ctx.fill(); }
    T(o.width ? fitTo(label, w - pad * 2 - (o.dot ? 12 : 0), { size, f: o.f || 'm', w: o.w || 500 }) : label, x0 + pad + (o.dot ? 12 : 0), y + 0.5, { size, f: o.f || 'm', w: o.w || 500, c: o.tc || c, a: o.a });
    return w;
  }
  function fitTo(s, max, o) { ctx.font = font(o); return fit(s, max); }
  function line(x1, y1, x2, y2, o) {
    o = o || {}; A(o.a); ctx.strokeStyle = o.c || P.line2; ctx.lineWidth = o.lw || 1.5; ctx.lineCap = 'round';
    if (o.dash) { ctx.setLineDash(o.dash); ctx.lineDashOffset = o.off || 0; }
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x1 + (x2 - x1) * (o.p == null ? 1 : o.p), y1 + (y2 - y1) * (o.p == null ? 1 : o.p)); ctx.stroke();
    if (o.dash) ctx.setLineDash([]);
  }
  // Quadratic curve drawn from 0 to p (exact sub-curve by de Casteljau).
  function curve(a, c, b, o) {
    o = o || {}; const p = o.p == null ? 1 : c01(o.p); if (p <= 0) return;
    const c1 = [mix(a[0], c[0], p), mix(a[1], c[1], p)], c2 = [mix(c[0], b[0], p), mix(c[1], b[1], p)], e = [mix(c1[0], c2[0], p), mix(c1[1], c2[1], p)];
    A(o.a); ctx.strokeStyle = o.c || P.line2; ctx.lineWidth = o.lw || 1.5; ctx.lineCap = 'round';
    if (o.dash) { ctx.setLineDash(o.dash); ctx.lineDashOffset = o.off || 0; }
    if (o.glow) { ctx.shadowColor = o.glow; ctx.shadowBlur = o.gb || 10; }
    ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.quadraticCurveTo(c1[0], c1[1], e[0], e[1]); ctx.stroke();
    ctx.shadowColor = 'transparent'; ctx.shadowBlur = 0;
    if (o.dash) ctx.setLineDash([]);
  }
  // Cubic curve drawn from 0 to p.
  function curve3(a, c1, c2, b, o) {
    o = o || {}; const p = o.p == null ? 1 : c01(o.p); if (p <= 0) return;
    const l = (u, v) => [mix(u[0], v[0], p), mix(u[1], v[1], p)];
    const ab = l(a, c1), bc = l(c1, c2), cd = l(c2, b), abc = l(ab, bc), bcd = l(bc, cd), e = l(abc, bcd);
    A(o.a); ctx.strokeStyle = o.c || P.line2; ctx.lineWidth = o.lw || 1.5; ctx.lineCap = 'round';
    if (o.glow) { ctx.shadowColor = o.glow; ctx.shadowBlur = o.gb || 10; }
    ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.bezierCurveTo(ab[0], ab[1], abc[0], abc[1], e[0], e[1]); ctx.stroke();
    ctx.shadowColor = 'transparent'; ctx.shadowBlur = 0;
  }
  function dot(x, y, r, c, a) { A(a); ctx.fillStyle = c; ctx.beginPath(); ctx.arc(x, y, Math.max(0, r), 0, Math.PI * 2); ctx.fill(); }
  function ring(x, y, r, c, a, lw) { A(a); ctx.strokeStyle = c; ctx.lineWidth = lw || 1.5; ctx.beginPath(); ctx.arc(x, y, Math.max(0, r), 0, Math.PI * 2); ctx.stroke(); }
  function glow(x, y, r, c, a) {
    if (r <= 0) return;
    const g = ctx.createRadialGradient(x, y, 0, x, y, r);
    g.addColorStop(0, rgba(c, 0.55)); g.addColorStop(1, rgba(c, 0));
    A(a); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
  }
  // A packet travelling along a curve, with a short fading trail.
  function packet(a, c, b, p, col, o) {
    o = o || {};
    if (p <= 0 || p >= 1) return null;
    for (let i = 5; i >= 1; i--) { const q = qpt(a, c, b, c01(p - i * 0.025)); dot(q[0], q[1], (o.r || 4) * (1 - i * 0.14), col, (o.a == null ? 1 : o.a) * (0.5 - i * 0.08)); }
    const q = qpt(a, c, b, p);
    glow(q[0], q[1], (o.r || 4) * 4, col, (o.a == null ? 1 : o.a) * 0.7);
    dot(q[0], q[1], o.r || 4, col, o.a);
    return q;
  }
  function ripple(x, y, p, c, max) { if (p <= 0 || p >= 1) return; ring(x, y, (max || 30) * E.out(p), c, (1 - p) * 0.9, 2); }
  function spinner(x, y, r, t, c, a) {
    A(a); ctx.strokeStyle = c; ctx.lineWidth = 2.2; ctx.lineCap = 'round';
    ctx.beginPath(); ctx.arc(x, y, r, t * 6, t * 6 + Math.PI * 1.4); ctx.stroke();
  }
  function tick(x, y, s, c, p, a) {
    if (p <= 0) return; A(a); ctx.strokeStyle = c; ctx.lineWidth = Math.max(1.8, s * 0.16); ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    const pts = [[x - s * 0.36, y + s * 0.02], [x - s * 0.1, y + s * 0.28], [x + s * 0.38, y - s * 0.26]];
    const l1 = Math.hypot(pts[1][0] - pts[0][0], pts[1][1] - pts[0][1]), l2 = Math.hypot(pts[2][0] - pts[1][0], pts[2][1] - pts[1][1]), L = (l1 + l2) * c01(p);
    ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]);
    if (L <= l1) ctx.lineTo(mix(pts[0][0], pts[1][0], L / l1), mix(pts[0][1], pts[1][1], L / l1));
    else { ctx.lineTo(pts[1][0], pts[1][1]); ctx.lineTo(mix(pts[1][0], pts[2][0], (L - l1) / l2), mix(pts[1][1], pts[2][1], (L - l1) / l2)); }
    ctx.stroke();
  }
  function cross(x, y, s, c, p, a) {
    if (p <= 0) return; A(a); ctx.strokeStyle = c; ctx.lineWidth = Math.max(1.8, s * 0.16); ctx.lineCap = 'round';
    const d = s * 0.3, p1 = c01(p * 2), p2 = c01(p * 2 - 1);
    ctx.beginPath(); ctx.moveTo(x - d, y - d); ctx.lineTo(x - d + 2 * d * p1, y - d + 2 * d * p1);
    if (p2 > 0) { ctx.moveTo(x + d, y - d); ctx.lineTo(x + d - 2 * d * p2, y - d + 2 * d * p2); }
    ctx.stroke();
  }
  function badge(x, y, r, c, kind, p, a) {
    const s = E.back(p); if (s <= 0) return;
    dot(x, y, r * s, c, a);
    if (kind === 'ok') tick(x, y, r * 1.5 * s, P.bg0, k(p, 0.3, 1), a);
    else if (kind === 'no') cross(x, y, r * 1.6 * s, P.bg0, k(p, 0.3, 1), a);
    else T(kind, x, y + 0.5, { size: r * 1.2 * s, w: 700, c: P.bg0, al: 'center', a });
  }
  // The pointer arrow, pressed when p > 0.
  function pointer(x, y, press, a) {
    ctx.save(); ctx.translate(x, y); const s = 1 - 0.12 * press; ctx.scale(s, s);
    A(a); ctx.shadowColor = 'rgba(0,0,0,.5)'; ctx.shadowBlur = 6; ctx.shadowOffsetY = 2;
    ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(0, 19); ctx.lineTo(4.6, 14.8); ctx.lineTo(7.8, 21.6); ctx.lineTo(10.6, 20.4); ctx.lineTo(7.5, 13.8); ctx.lineTo(13.6, 13.6); ctx.closePath();
    ctx.fillStyle = '#fff'; ctx.fill(); ctx.shadowColor = 'transparent'; ctx.lineWidth = 1.2; ctx.strokeStyle = '#0E1734'; ctx.stroke();
    ctx.restore();
  }
  function caret(x, y, h, c, t) { if (Math.floor(t * 2.2) % 2 === 0) { A(); ctx.fillStyle = c || P.act2; ctx.fillRect(x, y - h / 2, 2, h); } }

  /* ---------- icons (24-unit paths, stroked) ---------- */
  const ICON = {
    folder: (c) => { c.moveTo(3, 7); c.lineTo(3, 18); c.quadraticCurveTo(3, 20, 5, 20); c.lineTo(19, 20); c.quadraticCurveTo(21, 20, 21, 18); c.lineTo(21, 9); c.quadraticCurveTo(21, 7, 19, 7); c.lineTo(11, 7); c.lineTo(9, 5); c.lineTo(5, 5); c.quadraticCurveTo(3, 5, 3, 7); },
    file: (c) => { c.moveTo(6, 3); c.lineTo(14, 3); c.lineTo(19, 8); c.lineTo(19, 21); c.lineTo(6, 21); c.closePath(); c.moveTo(14, 3); c.lineTo(14, 8); c.lineTo(19, 8); },
    server: (c) => { c.rect(4, 4, 16, 7); c.rect(4, 13, 16, 7); c.moveTo(7.5, 7.5); c.lineTo(8, 7.5); c.moveTo(7.5, 16.5); c.lineTo(8, 16.5); },
    db: (c) => { c.ellipse(12, 6, 7.5, 2.8, 0, 0, Math.PI * 2); c.moveTo(4.5, 6); c.lineTo(4.5, 18); c.ellipse(12, 18, 7.5, 2.8, 0, Math.PI, 0, true); c.lineTo(19.5, 6); c.moveTo(4.5, 12); c.ellipse(12, 12, 7.5, 2.8, 0, Math.PI, 0, true); },
    globe: (c) => { c.arc(12, 12, 8.5, 0, Math.PI * 2); c.moveTo(3.5, 12); c.lineTo(20.5, 12); c.moveTo(12, 3.5); c.bezierCurveTo(7.5, 8, 7.5, 16, 12, 20.5); c.moveTo(12, 3.5); c.bezierCurveTo(16.5, 8, 16.5, 16, 12, 20.5); },
    lock: (c) => { c.rect(5, 11, 14, 9.5); c.moveTo(8, 11); c.lineTo(8, 8); c.arc(12, 8, 4, Math.PI, 0); c.lineTo(16, 11); },
    unlock: (c) => { c.rect(5, 11, 14, 9.5); c.moveTo(8, 11); c.lineTo(8, 8); c.arc(12, 8, 4, Math.PI, -0.2); },
    gear: (c) => { for (let i = 0; i < 8; i++) { const a = i * Math.PI / 4; c.moveTo(12 + Math.cos(a) * 6.5, 12 + Math.sin(a) * 6.5); c.lineTo(12 + Math.cos(a) * 9, 12 + Math.sin(a) * 9); } c.moveTo(18.5, 12); c.arc(12, 12, 6.5, 0, Math.PI * 2); c.moveTo(14.5, 12); c.arc(12, 12, 2.5, 0, Math.PI * 2); },
    branch: (c) => { c.arc(6, 5, 2, 0, Math.PI * 2); c.moveTo(8, 19); c.arc(6, 19, 2, 0, Math.PI * 2); c.moveTo(20, 12); c.arc(18, 12, 2, 0, Math.PI * 2); c.moveTo(6, 7); c.lineTo(6, 17); c.moveTo(6, 7); c.bezierCurveTo(6, 11, 10, 12, 16, 12); },
    shield: (c) => { c.moveTo(12, 3); c.lineTo(19.5, 6); c.lineTo(19.5, 11.5); c.bezierCurveTo(19.5, 16, 16.4, 19.6, 12, 21); c.bezierCurveTo(7.6, 19.6, 4.5, 16, 4.5, 11.5); c.lineTo(4.5, 6); c.closePath(); },
    hash: (c) => { c.moveTo(9.5, 3.5); c.lineTo(7.5, 20.5); c.moveTo(16.5, 3.5); c.lineTo(14.5, 20.5); c.moveTo(4, 9); c.lineTo(20.5, 9); c.moveTo(3.5, 15); c.lineTo(20, 15); },
    clock: (c) => { c.arc(12, 12, 8.5, 0, Math.PI * 2); c.moveTo(12, 7.5); c.lineTo(12, 12); c.lineTo(15, 14); },
    doc: (c) => { c.moveTo(6, 3); c.lineTo(14, 3); c.lineTo(19, 8); c.lineTo(19, 21); c.lineTo(6, 21); c.closePath(); c.moveTo(9, 12); c.lineTo(16, 12); c.moveTo(9, 15.5); c.lineTo(16, 15.5); },
    queue: (c) => { c.rect(3, 6, 4, 12); c.rect(10, 6, 4, 12); c.rect(17, 6, 4, 12); },
    hook: (c) => { c.moveTo(18, 16.5); c.arc(14, 16.5, 4, 0, Math.PI * 1.35); c.moveTo(8.5, 7.5); c.arc(12.5, 7.5, 4, Math.PI, Math.PI * 2.35); c.moveTo(6, 16.5); c.arc(6, 12.5, 4, Math.PI / 2, Math.PI * 1.9); },
    chain: (c) => { c.rect(2.5, 8, 6, 8); c.rect(9, 8, 6, 8); c.rect(15.5, 8, 6, 8); }
  };
  function icon(name, x, y, s, c, a, lw) {
    ctx.save(); ctx.translate(x - s / 2, y - s / 2); ctx.scale(s / 24, s / 24);
    A(a); ctx.strokeStyle = c; ctx.lineWidth = (lw || 1.8) * 24 / s; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    ctx.beginPath(); ICON[name](ctx); ctx.stroke();
    ctx.restore();
  }
  // A window-like card with a title row. Returns the content top.
  function card(x, y, w, h, o) {
    o = o || {};
    box(x, y, w, h, { r: o.r || 14, fill: o.fill || P.panel, stroke: o.stroke || P.line, a: o.a, shadow: o.shadow === false ? null : 'rgba(0,0,0,.45)', blur: 30, oy: 12 });
    if (o.glow) box(x, y, w, h, { r: o.r || 14, stroke: o.glow, lw: 1.5, a: (o.a == null ? 1 : o.a) * (o.ga == null ? 1 : o.ga) });
    if (o.title) {
      let tx = x + 16;
      if (o.icon) { icon(o.icon, x + 25, y + 22, 18, o.ic || P.act2, o.a); tx = x + 42; }
      T(o.title, tx, y + 22, { size: o.ts || 13.5, w: 600, c: P.text, a: o.a, f: o.tf || 's', max: w - (tx - x) - 16 - (o.tag ? TW(o.tag, { size: 11, f: 'm', w: 500 }) + 26 : 0) });
      if (o.tag) pill(x + w - 12, y + 22, o.tag, { al: 'right', h: 20, size: 11, c: o.tagc || P.faint, a: o.a });
      box(x + 1, y + 42, w - 2, 1, { r: 0, fill: P.line, a: (o.a == null ? 1 : o.a) * 0.8 });
      return y + 44;
    }
    return y;
  }
  // Wraps text into lines that fit max width.
  function wrap(s, max, o) {
    ctx.font = font(o); const words = s.split(' '), out = []; let cur = '';
    for (const w of words) { const t = cur ? cur + ' ' + w : w; if (ctx.measureText(t).width > max && cur) { out.push(cur); cur = w; } else cur = t; }
    if (cur) out.push(cur); return out;
  }
  // Mono code line with light syntax colouring for YAML/JSON/Go.
  function codeLine(s, x, y, o) {
    o = o || {};
    const parts = [];
    const re = /("(?:[^"\\]|\\.)*")|(\/\/.*$|#.*$)|((?<![\w.-])\d[\d.]*(?![\w-]))|([A-Za-z_][\w./-]*:)(?=\s)|([{}[\],])/g;
    let last = 0, m;
    while ((m = re.exec(s))) {
      if (m.index > last) parts.push([s.slice(last, m.index), o.c || P.text]);
      parts.push([m[0], m[1] ? (o.str || P.ok) : m[2] ? P.faint : m[3] ? P.med : m[4] ? P.act2 : P.muted]);
      last = m.index + m[0].length;
    }
    if (last < s.length) parts.push([s.slice(last), o.c || P.text]);
    return runs(parts, x, y, { size: o.size || 12, f: 'm', a: o.a });
  }

  /* ======================= layout state ======================= */
  let WIDE = true;            // wide: 960 x 560 world, narrow: 480 x 720
  const SW = () => (WIDE ? 960 : 480), SH = () => (WIDE ? 560 : 720);
  // Fade in while rising a few units; p is 0..1.
  function rise(p, fn, dy) {
    if (p <= 0.002) return;
    const e = E.out(p);
    fade(c01(p * 1.4), () => { ctx.save(); ctx.translate(0, (1 - e) * (dy == null ? 14 : dy)); fn(); ctx.restore(); });
  }
  function pop(p, x, y, fn) {
    if (p <= 0.002) return;
    const s = E.back(p);
    fade(c01(p * 2), () => { ctx.save(); ctx.translate(x, y); ctx.scale(s, s); ctx.translate(-x, -y); fn(); ctx.restore(); });
  }
  const shake = (t, a, b, amp) => (t > a && t < b ? Math.sin((t - a) * 60) * amp * (1 - (t - a) / (b - a)) : 0);

  // Token pill used for packages from step 2 on.
  function token(p, x, y, w, o) {
    o = o || {};
    const h = o.h || (WIDE ? 30 : 30), a = o.a == null ? 1 : o.a;
    if (p.direct) {
      box(x, y - h / 2, w, h, { r: 9, fill: P.panel3, stroke: rgba(P.act2, 0.55), a, glow: o.glow ? P.act : null, gb: 18, ga: o.glow || 0 });
      box(x + 1, y - h / 2 + 6, 3, h - 12, { r: 2, fill: P.act, a });
    } else {
      box(x, y - h / 2, w, h, { r: 9, fill: rgba(P.panel2, 0.7), stroke: P.line2, dash: [4, 3], a });
    }
    // Stored as DepScan stores it: Go versions without the leading v, which is what OSV.dev expects.
    const v = p.eco === 'Go' ? p.v.slice(1) : p.v, vw = TW(v, { size: 11, f: 'm' });
    T(p.s, x + 12, y + 0.5, { size: 12.5, f: 'm', w: 500, c: P.text, a, max: w - vw - 30 });
    T(v, x + w - 10, y + 0.5, { size: 11, f: 'm', c: P.faint, al: 'right', a });
  }

  /* ======================= 1. point at a folder ======================= */
  const TREE = [
    ['shop-api', 0, 'dir'], ['.git', 1, 'skip'], ['cmd', 1, 'dir'], ['go.mod', 1, 'lock'], ['go.sum', 1, 'file'],
    ['policy.yaml', 1, 'file'], ['web', 1, 'dir'], ['node_modules', 2, 'skip'], ['src', 2, 'dir'], ['package.json', 2, 'file'], ['package-lock.json', 2, 'lock']
  ];
  const PATH = 'C:\\Users\\you\\code\\shop-api', ROOTP = 'C:\\Users\\you\\code';
  function sc1(t) {
    const L = WIDE
      ? { app: [40, 50, 430, 124], srv: [90, 292, 340, 128], root: [520, 40, 410, 480], row0: 110, rowH: 34 }
      : { app: [16, 20, 448, 124], srv: [16, 168, 448, 124], root: [16, 340, 448, 364], row0: 404, rowH: 26 };
    const [ax, ay, aw, ah] = L.app, [sx, sy, sw, sh] = L.srv, [rx, ry, rw, rh] = L.root;
    const btn = [ax + aw - 16 - 84, ay + 58, 84, 46], fld = [ax + 16, ay + 58, aw - 32 - 96, 46];

    // app window
    rise(k(t, 0, 0.6), () => {
      card(ax, ay, aw, ah, { title: 'DepScan', icon: 'globe', tag: '127.0.0.1:8080' });
      const typing = k(t, 0.5, 2.3), focus = t > 0.4 && t < 3.2;
      box(fld[0], fld[1], fld[2], fld[3], { r: 10, fill: P.bg0, stroke: focus ? P.act : P.line2, lw: focus ? 1.5 : 1 });
      icon('folder', fld[0] + 20, fld[1] + 23, 16, P.faint);
      const s = typed(PATH, typing);
      T(s, fld[0] + 36, fld[1] + 23.5, { size: WIDE ? 13 : 13.5, f: 'm', c: P.text, max: fld[2] - 44 });
      if (focus) caret(fld[0] + 37 + Math.min(TW(s, { size: WIDE ? 13 : 13.5, f: 'm' }), fld[2] - 44), fld[1] + 23, 18, P.act2, t);
      const press = t > 2.95 && t < 3.2 ? Math.sin(k(t, 2.95, 3.2) * Math.PI) : 0;
      ctx.save(); ctx.translate(btn[0] + btn[2] / 2, btn[1] + btn[3] / 2); ctx.scale(1 - press * 0.06, 1 - press * 0.06); ctx.translate(-(btn[0] + btn[2] / 2), -(btn[1] + btn[3] / 2));
      box(btn[0], btn[1], btn[2], btn[3], { r: 10, fill: t > 3.0 && t < 4.4 ? '#6B5BEE' : P.act, glow: P.act, gb: 20, ga: 0.6 });
      if (t > 3.05 && t < 4.4) spinner(btn[0] + btn[2] / 2, btn[1] + btn[3] / 2, 8, t, '#fff');
      else T('Scan', btn[0] + btn[2] / 2, btn[1] + btn[3] / 2 + 0.5, { size: 14, w: 600, c: '#fff', al: 'center' });
      ctx.restore();
      ripple(btn[0] + btn[2] / 2, btn[1] + btn[3] / 2, k(t, 3.0, 3.7), P.act2, 60);
    });

    // server
    rise(k(t, 2.6, 3.2), () => {
      const top = card(sx, sy, sw, sh, { title: 'DepScan server', icon: 'server', tag: 'internal/api' });
      const req = k(t, 4.1, 4.4);
      fade(req, () => {
        runs([['POST ', P.act2], ['/scans', P.text]], sx + 16, top + 22, { size: 12.5, f: 'm', w: 500 });
        T('{"path": "…\\shop-api"}', sx + 16 + TW('POST /scans  ', { size: 12.5, f: 'm', w: 500 }), top + 22, { size: 12, f: 'm', c: P.ok, max: sw - 150 });
      });
      const y2 = top + 52;
      if (t > 4.3 && t < 5.1) { spinner(sx + 24, y2, 7, t, P.act2); T('resolveScanPath(): checking the path', sx + 40, y2, { size: 12.5, f: 'm', c: P.muted, max: sw - 56 }); }
      if (t >= 5.1) {
        badge(sx + 24, y2, 8, P.ok, 'ok', k(t, 5.1, 5.5));
        T(t < 6.0 ? 'inside the scan root: OK' : 'inside the scan root: walking files', sx + 40, y2, { size: 12.5, f: 'm', c: P.ok, max: sw - 56, a: k(t, 5.1, 5.4) });
      }
    });

    // scan root boundary
    rise(k(t, 3.5, 4.2), () => {
      const ants = t > 4.2 && t < 5.4 ? -(t - 4.2) * 30 : 0;
      box(rx, ry, rw, rh, { r: 18, fill: rgba(P.act, 0.05), stroke: P.act2, sa: 0.55, dash: [7, 6], off: ants, lw: 1.5 });
      icon('lock', rx + 26, ry + 26, 16, P.act2);
      T('Scan root', rx + 42, ry + 26, { size: 13, w: 600 });
      T(ROOTP, rx + 42 + TW('Scan root', { size: 13, w: 600 }) + 10, ry + 26, { size: 12, f: 'm', c: P.faint, max: rw - 140 });
    }, 0);

    // the path resolves to a folder inside the root
    const src = WIDE ? [sx + sw, sy + 60] : [sx + sw * 0.7, sy + sh], dst = [rx + 22, L.row0];
    const ctl = WIDE ? [mix(src[0], dst[0], 0.5), Math.min(src[1], dst[1]) + 10] : [rx + 40, (src[1] + dst[1]) / 2];
    curve(src, ctl, dst, { p: E.io(k(t, 4.3, 5.0)), c: t > 5.0 ? P.ok : P.act2, lw: 2, dash: [5, 5], off: -t * 24, a: 1 - k(t, 6.8, 7.4) * 0.6 });
    packet(src, ctl, dst, E.io(k(t, 4.3, 5.0)), P.act2, { r: 4 });

    // request travels from the page to the server
    const ra = [btn[0] + btn[2] / 2, btn[1] + btn[3]], rb = [sx + sw / 2, sy], rc = WIDE ? [ra[0] - 20, (ra[1] + rb[1]) / 2 + 10] : [ra[0] - 60, (ra[1] + rb[1]) / 2];
    const rp = E.io(k(t, 3.15, 4.15));
    const q = packet(ra, rc, rb, rp, P.act2, { r: 5 });
    if (q) pill(q[0] + 14, q[1], 'POST /scans', { h: 22, size: 11.5, c: P.act2, fill: rgba(P.bg0, 0.9), stroke: rgba(P.act2, 0.6) });

    // a path that climbs out of the root is rejected
    if (t > 5.4 && t < 7.6) {
      const from = WIDE ? [sx + sw - 10, sy + sh - 18] : [sx + sw - 40, sy + sh - 10];
      const hit = WIDE ? [rx - 4, ry + rh * 0.78] : [rx + rw * 0.62, ry - 4];
      const go = E.in(k(t, 5.4, 6.0)), back = E.out(k(t, 6.0, 6.7));
      const bx = WIDE ? hit[0] - 56 : hit[0] - 40, by = WIDE ? hit[1] + 10 : hit[1] - 26;
      let x = mix(from[0], hit[0], go), y = mix(from[1], hit[1], go);
      if (t > 6.0) { x = mix(hit[0], bx, back) + shake(t, 6.0, 6.5, 5); y = mix(hit[1], by, back); }
      const a = 1 - k(t, 7.0, 7.6);
      const lbl = '..\\..\\Windows';
      const w = TW(lbl, { size: 12, f: 'm', w: 500 }) + 20;
      pill(x - w, y, lbl, { h: 24, c: P.crit, fill: rgba(P.crit, 0.16), stroke: rgba(P.crit, 0.6), a });
      if (t > 6.0) {
        ripple(hit[0], hit[1], k(t, 6.0, 6.6), P.crit, 40);
        badge(hit[0], hit[1], 10, P.crit, 'no', k(t, 6.0, 6.4), a);
        const ly = WIDE ? hit[1] + 46 : hit[1] - 22;
        T(WIDE ? '400: path must be inside the scan root' : '400: outside the root', WIDE ? hit[0] - 6 : hit[0] + 18, ly, { size: 12, f: 'm', c: P.crit, al: WIDE ? 'right' : 'left', a: a * k(t, 6.05, 6.3) });
      }
    }

    // file tree, then the walker
    const walk = (t - 7.0) / 0.27;
    TREE.forEach(([name, depth, kind], i) => {
      const y = L.row0 + i * L.rowH, x = rx + 24 + depth * 22;
      const ap = k(t, 5.0 + i * 0.1, 5.4 + i * 0.1);
      if (ap <= 0) return;
      const passed = walk > i + 0.6, at = walk > i - 0.4 && walk < i + 0.6;
      fade(ap, () => {
        ctx.save(); ctx.translate((1 - E.out(ap)) * 16, 0);
        let alpha = 1;
        if (passed && kind === 'file') alpha = 0.5;
        if (passed && kind === 'dir') alpha = 0.7;
        if (at) box(rx + 12, y - L.rowH / 2 + 2, rw - 24, L.rowH - 4, { r: 8, fill: rgba(P.act, 0.18), stroke: rgba(P.act2, 0.5) });
        if (kind === 'lock' && walk > i - 0.2) {
          const g = k(walk, i - 0.2, i + 0.4);
          box(rx + 12, y - L.rowH / 2 + 2, rw - 24, L.rowH - 4, { r: 8, fill: rgba(P.act, 0.22 * g), stroke: P.act2, sa: g, glow: P.act, gb: 16, ga: g * 0.5 });
        }
        const isDir = kind === 'dir' || kind === 'skip';
        icon(isDir ? 'folder' : 'file', x + 8, y, 15, kind === 'lock' ? P.act2 : kind === 'skip' && passed ? P.faint : P.muted, alpha);
        T(name + (isDir ? '/' : ''), x + 24, y + 0.5, { size: WIDE ? 13 : 13.5, f: 'm', w: kind === 'lock' ? 600 : 400, c: kind === 'lock' && walk > i - 0.2 ? P.text : P.muted, a: alpha });
        const nameW = TW(name + (isDir ? '/' : ''), { size: WIDE ? 13 : 13.5, f: 'm', w: kind === 'lock' ? 600 : 400 });
        if (kind === 'skip' && walk > i - 0.2) {
          const s = k(walk, i - 0.2, i + 0.3);
          line(x + 22, y + 1, x + 26 + nameW, y + 1, { c: P.faint, lw: 1.5, p: s });
          pill(rx + rw - 22, y, 'skipped', { al: 'right', h: 20, size: 11, c: P.faint, a: s });
        }
        if (kind === 'lock' && walk > i - 0.2) pill(rx + rw - 22, y, 'lockfile', { al: 'right', h: 20, size: 11, c: P.act2, a: k(walk, i - 0.2, i + 0.3), dot: true });
        ctx.restore();
      });
    });
    if (t > 10.0) {
      const p = k(t, 10.0, 10.5);
      rise(p, () => T('Found 2 lockfiles, skipped 2 folders', rx + rw / 2, ry + rh - (WIDE ? 22 : 18), { size: 12.5, w: 600, c: P.text, al: 'center' }), 6);
    }
  }

  /* ======================= 2. read the lockfiles ======================= */
  const GOMOD = [
    'module example.com/shop-api', '', 'go 1.22', '', 'require (',
    '\tgithub.com/gin-gonic/gin v1.9.0', '\tgithub.com/golang-jwt/jwt/v4 v4.5.0', '\tgolang.org/x/crypto v0.14.0',
    '\tgolang.org/x/net v0.10.0 // indirect', '\tgolang.org/x/sys v0.8.0 // indirect', '\t… 6 more // indirect', ')'
  ];
  const LOCK = [
    '{', '  "lockfileVersion": 3,', '  "packages": {', '    "": {', '      "dependencies": { "axios": "^0.21.1", … }', '    },',
    '    "node_modules/axios": { "version": "0.21.1" },', '    "node_modules/ffmpeg-static": { "version": "5.2.0" },',
    '    "node_modules/@shop/ui-kit": { "version": "2.3.0" },', '    "node_modules/follow-redirects": { "version": "1.14.0" },', '    … 7 more'
  ];
  // When each token leaves its line, and which line it leaves from.
  const SPAWN = (() => {
    const m = {};
    [['gin', 0.9, 5], ['jwt', 1.45, 6], ['crypto', 2.0, 7], ['net', 2.55, 8], ['sys', 3.1, 9]].forEach(([id, t, l]) => { m[id] = { t, l, f: 'go' }; });
    ['text', 'validator', 'jsoniter', 'isatty', 'sonic', 'codec'].forEach((id, i) => { m[id] = { t: 3.65 + i * 0.1, l: 10, f: 'go' }; });
    [['axios', 6.5, 6], ['ffmpeg', 6.9, 7], ['uikit', 7.3, 8], ['follow', 7.7, 9]].forEach(([id, t, l]) => { m[id] = { t, l, f: 'npm' }; });
    ['httpbasic', 'hpa', 'agentbase', 'debug', 'ms', 'envpaths', 'progress'].forEach((id, i) => { m[id] = { t: 8.1 + i * 0.1, l: 10, f: 'npm' }; });
    return m;
  })();
  function sc2(t) {
    const L = WIDE
      ? { go: [24, 20, 452, 260], lock: [24, 292, 452, 248], list: [496, 20, 440, 520], lh: 17.5, fs: 11.5, step: 37, cols: 2, top: 92, leg: 26 }
      : { go: [16, 16, 448, 214], lock: [16, 16, 448, 214], list: [16, 244, 448, 460], lh: 18, fs: 12, step: 33, cols: 2, top: 84, leg: 16 };
    const narrowSwap = WIDE ? 0 : E.io(k(t, 4.7, 5.3)); // narrow: go.mod slides out, the lockfile slides in
    const goLines = WIDE ? GOMOD : GOMOD.slice(4);
    const lockLines = WIDE ? LOCK : LOCK.slice(3);
    const goOff = WIDE ? 0 : 4, lockOff = WIDE ? 0 : 3;

    // list of dependencies
    const [lx, ly, lw, lh] = L.list;
    const colW = (lw - 32 - 12) / 2;
    const slot = (id) => {
      const p = PK[id], col = p.eco === 'Go' ? 0 : 1, list = col ? NPM : GO, i = list.indexOf(p);
      return [lx + 16 + col * (colW + 12), ly + L.top + i * L.step];
    };
    rise(k(t, 0.1, 0.6), () => {
      box(lx, ly, lw, lh, { r: 16, fill: rgba(P.panel, 0.65), stroke: P.line });
      let landed = 0;
      PKGS.forEach((p) => { if (t > SPAWN[p.id].t + 0.65) landed++; });
      T('Dependencies', lx + 18, ly + 26, { size: 15, w: 600, f: 'd' });
      const n = String(landed);
      pill(lx + lw - 16, ly + 26, n + ' found', { al: 'right', h: 24, size: 12, c: landed === 22 ? P.ok : P.act2 });
      T('Go modules', lx + 16, ly + L.top - 30, { size: 12, w: 600, c: P.muted });
      T('npm packages', lx + 16 + colW + 12, ly + L.top - 30, { size: 12, w: 600, c: P.muted });
      // empty slots, so the eye sees where things will land
      PKGS.forEach((p) => {
        const [x, y] = slot(p.id);
        if (t < SPAWN[p.id].t + 0.6) box(x, y - 13, colW, 26, { r: 9, stroke: P.line, dash: [3, 4], a: 0.5 });
      });
    }, 0);

    // files
    const drawFile = (rect, title, tag, lines, off, active, hl) => {
      const [x, y, w, h] = rect;
      const top = card(x, y, w, h, { title, icon: 'file', tag, glow: P.act2, ga: active ? 0.6 : 0 });
      lines.forEach((s, i) => {
        const yy = top + 16 + i * L.lh;
        const li = i + off;
        if (hl && hl(li) > 0) box(x + 8, yy - L.lh / 2, w - 16, L.lh, { r: 5, fill: rgba(P.act, 0.22 * hl(li)) });
        ctx.save(); rr(x + 1, y + 44, w - 2, h - 46, 0); ctx.clip();
        codeLine(s.replace('\t', '    '), x + 16, yy, { size: L.fs, a: active ? 1 : 0.55 });
        ctx.restore();
      });
      return top;
    };
    const lineHL = (file) => (li) => {
      let v = 0;
      for (const id in SPAWN) { const s = SPAWN[id]; if (s.f === file && s.l === li) v = Math.max(v, k(t, s.t - 0.25, s.t) * (1 - k(t, s.t + 0.35, s.t + 0.7))); }
      if (file === 'npm' && li >= 3 && li <= 5) v = Math.max(v, k(t, 5.2, 5.5) * (1 - k(t, 6.2, 6.5)));
      return v;
    };
    ctx.save();
    if (!WIDE) ctx.translate(-narrowSwap * 520, 0);
    rise(k(t, 0, 0.5), () => drawFile(L.go, 'go.mod', 'Go', goLines, goOff, t < 5.0, lineHL('go')));
    ctx.restore();
    ctx.save();
    if (!WIDE) ctx.translate((1 - narrowSwap) * 520, 0);
    rise(WIDE ? k(t, 0.2, 0.7) : 1, () => drawFile(L.lock, 'web/package-lock.json', 'npm', lockLines, lockOff, t >= 5.0, lineHL('npm')));
    ctx.restore();
    if (t > 5.3 && t < 6.6) {
      const [x, y, w] = L.lock, p = k(t, 5.3, 5.6) * (1 - k(t, 6.3, 6.6));
      const yy = y + 44 + 16 + (WIDE ? 4 : 1) * L.lh;
      pill(x + w - 16, yy, 'direct = listed by the root entry ""', { al: 'right', h: 24, size: 11.5, c: P.act2, fill: rgba(P.bg0, 0.92), stroke: rgba(P.act2, 0.7), a: p });
    }
    if (t > 1.8 && t < 4.6) {
      const [x, y, w] = L.go, p = k(t, 1.8, 2.1) * (1 - k(t, 4.2, 4.6));
      const yy = y + 44 + 16 + (11 - goOff) * L.lh;
      pill(x + w - 14, yy, '// indirect = transitive', { al: 'right', h: 22, size: 11.5, c: P.med, fill: rgba(P.bg0, 0.92), stroke: rgba(P.med, 0.6), a: p });
    }

    // tokens fly from their line into their slot
    PKGS.forEach((p) => {
      const s = SPAWN[p.id], fp = k(t, s.t, s.t + 0.65);
      if (fp <= 0) return;
      const rect = s.f === 'go' ? L.go : L.lock, off = s.f === 'go' ? goOff : lockOff;
      let from = [rect[0] + rect[2] - 30, rect[1] + 44 + 16 + (s.l - off) * L.lh];
      if (!WIDE) from = [rect[0] + rect[2] / 2 + (s.f === 'go' ? -narrowSwap * 520 : (1 - narrowSwap) * 520), rect[1] + rect[3] - 10];
      const to = slot(p.id), e = E.io(fp);
      const c = [mix(from[0], to[0], 0.5), Math.min(from[1], to[1]) - 50];
      const q = qpt(from, c, [to[0] + colW / 2, to[1]], e);
      const w = mix(60, colW, E.out(k(fp, 0.5, 1)));
      const glowA = (1 - k(t, s.t + 0.65, s.t + 1.3)) + (t > 10.2 && p.direct ? Math.sin(k(t, 10.2, 11.8) * Math.PI) : 0);
      token(p, q[0] - w / 2, q[1], w, { glow: c01(glowA) * 0.8, h: WIDE ? 28 : 26 });
      if (fp < 1) glow(q[0], q[1], 26, P.act, 0.5 * (1 - fp));
    });

    // legend and summary
    if (t > 10.0) {
      const p = k(t, 10.0, 10.5), y = ly + lh - L.leg;
      rise(p, () => {
        box(lx + 16, y - 9, 26, 18, { r: 5, fill: P.panel3, stroke: rgba(P.act2, 0.55) });
        T('direct  6', lx + 50, y, { size: 12, w: 500, c: P.text });
        box(lx + 150, y - 9, 26, 18, { r: 5, fill: rgba(P.panel2, 0.7), stroke: P.line2, dash: [4, 3] });
        T('transitive  16', lx + 184, y, { size: 12, w: 500, c: P.text });
      }, 6);
    }
  }

  /* ======================= 3. direct and transitive ======================= */
  const GRAPH = {
    wide: {
      root: [480, 52], gin: [110, 160], jwt: [250, 160], crypto: [390, 160], axios: [580, 160], ffmpeg: [730, 160], uikit: [870, 160],
      net: [52, 286], validator: [126, 286], jsoniter: [200, 286], isatty: [274, 286], sonic: [348, 286], codec: [422, 286],
      text: [70, 400], sys: [262, 400],
      follow: [548, 286], httpbasic: [650, 286], hpa: [752, 286], envpaths: [846, 286], progress: [918, 286],
      agentbase: [700, 400], debug: [812, 400], ms: [812, 496]
    },
    narrow: {
      root: [240, 44], gin: [80, 140], jwt: [240, 140], crypto: [400, 140],
      net: [42, 236], validator: [117, 236], jsoniter: [192, 236], isatty: [267, 236], sonic: [342, 236], codec: [417, 236],
      text: [60, 320], sys: [250, 320],
      web: [240, 392], axios: [80, 454], ffmpeg: [240, 454], uikit: [400, 454],
      follow: [64, 548], httpbasic: [166, 548], hpa: [268, 548], envpaths: [362, 548], progress: [432, 548],
      agentbase: [222, 632], debug: [330, 632], ms: [330, 700]
    }
  };
  const LEVEL = { gin: 1, jwt: 1, crypto: 1, axios: 1, ffmpeg: 1, uikit: 1, net: 2, validator: 2, jsoniter: 2, isatty: 2, sonic: 2, codec: 2, follow: 2, httpbasic: 2, hpa: 2, envpaths: 2, progress: 2, text: 3, sys: 3, agentbase: 3, debug: 3, ms: 4 };
  const LEVEL_T = [0, 0.7, 2.2, 4.6, 5.9];
  const ORDER = {};
  ['gin', 'jwt', 'crypto', 'axios', 'ffmpeg', 'uikit'].forEach((id, i) => { ORDER[id] = i; });
  ['net', 'validator', 'jsoniter', 'isatty', 'sonic', 'codec', 'follow', 'httpbasic', 'hpa', 'envpaths', 'progress'].forEach((id, i) => { ORDER[id] = i; });
  ['text', 'sys', 'agentbase', 'debug'].forEach((id, i) => { ORDER[id] = i; });
  ORDER.ms = 0;
  const nodeT = (id) => LEVEL_T[LEVEL[id]] + ORDER[id] * (LEVEL[id] === 2 ? 0.16 : 0.18);
  function sc3(t) {
    const G = WIDE ? GRAPH.wide : GRAPH.narrow;
    const zone = k(t, 8.6, 9.2);
    // zone bands
    if (zone > 0) {
      const ys = WIDE ? [[160]] : [[140], [454]];
      ys.forEach(([y]) => box(12, y - 30, SW() - 24, 60, { r: 14, fill: rgba(P.act, 0.1 * zone), stroke: rgba(P.act2, 0.35 * zone), dash: [6, 6] }));
      const tb = WIDE ? [12, 236, 936, 300] : [[12, 196, 456, 160], [12, 500, 456, 216]];
      (WIDE ? [tb] : tb).forEach(([x, y, w, h]) => box(x, y, w, h, { r: 14, fill: rgba(P.med, 0.05 * zone), stroke: rgba(P.med, 0.3 * zone), dash: [6, 6] }));
      if (WIDE) {
        pill(24, 118, 'You chose these: 6', { h: 22, size: 11.5, c: P.act2, a: zone, fill: rgba(P.bg0, 0.9), stroke: rgba(P.act2, 0.6) });
        pill(24, 236, 'They came along: 16', { h: 22, size: 11.5, c: P.med, a: zone, fill: rgba(P.bg0, 0.9), stroke: rgba(P.med, 0.6) });
      }
    }
    const rad = (id) => (id === 'root' ? 20 : id === 'web' ? 12 : PK[id].direct ? 10 : 6.5);
    const edge = (a, b, p, hot) => {
      const A0 = [G[a][0], G[a][1] + rad(a)], B0 = [G[b][0], G[b][1] - rad(b)], my = (A0[1] + B0[1]) / 2;
      curve3(A0, [A0[0], my], [B0[0], my], B0, { p: E.io(p), c: hot ? P.act2 : P.line2, lw: hot ? 2.2 : 1.3, a: hot ? 1 : 0.8, glow: hot ? P.act : null, gb: 10 });
    };
    // edges
    const hot = (id) => (t > 6.8 && t < 8.6 && (id === 'sys' || id === 'debug')) ? k(t, 6.8, 7.2) * (1 - k(t, 8.2, 8.6)) : 0;
    PKGS.forEach((p) => {
      const tt = nodeT(p.id);
      const parents = p.direct ? [WIDE || p.eco === 'Go' ? 'root' : 'web'] : p.up;
      parents.forEach((par, j) => edge(par, p.id, k(t, tt - 0.25 + j * 0.15, tt + 0.25 + j * 0.15), hot(p.id) > 0.3));
    });
    if (!WIDE) {
      const p = k(t, 0.5, 1.2);
      curve(G.root, [470, 220], G.web, { p: E.io(p), c: P.line2, lw: 1.3, dash: [5, 5] });
      pop(k(t, 1.0, 1.4), G.web[0], G.web[1], () => pill(G.web[0], G.web[1], 'web/package-lock.json', { al: 'center', h: 24, size: 11.5, c: P.muted, fill: P.panel, stroke: P.line2 }));
    }
    // root card
    pop(k(t, 0, 0.5), G.root[0], G.root[1], () => {
      box(G.root[0] - 70, G.root[1] - 20, 140, 40, { r: 12, fill: P.panel3, stroke: P.act2, glow: P.act, gb: 24, ga: 0.6 });
      icon('folder', G.root[0] - 46, G.root[1], 16, P.act2);
      T('shop-api', G.root[0] - 30, G.root[1] + 0.5, { size: 14, w: 600, f: 'm' });
    });
    // nodes
    PKGS.forEach((p) => {
      const [x, y] = G[p.id], ap = k(t, nodeT(p.id), nodeT(p.id) + 0.45), h = hot(p.id);
      if (ap <= 0) return;
      const r = p.direct ? 10 : 6.5;
      pop(ap, x, y, () => {
        if (h > 0) glow(x, y, 34, P.act, h);
        if (p.direct) { dot(x, y, r + 4, rgba(P.act, 0.25)); dot(x, y, r, P.act); }
        else { dot(x, y, r, P.panel3); ring(x, y, r, h > 0.3 ? P.act2 : P.muted, 1, 1.6); }
      });
      const stag = { follow: 0, httpbasic: 1, hpa: 0, envpaths: 1, progress: 0 };
      const ly = y + (p.direct ? 24 : 19 + (stag[p.id] || 0) * 14);
      T(p.s, x, ly, { size: p.direct ? 12.5 : 11.5, f: 'm', w: p.direct ? 600 : 400, c: p.direct ? P.text : P.muted, al: 'center', a: k(ap, 0.4, 1) });
      if (p.id === 'uikit') T('private', x, ly + 15, { size: 10.5, c: P.faint, al: 'center', a: k(ap, 0.4, 1) });
    });
    // diamond callouts
    if (t > 6.8 && t < 8.7) {
      const a = k(t, 6.9, 7.3) * (1 - k(t, 8.3, 8.7));
      const sx = G.sys[0], sy = G.sys[1];
      const text = WIDE ? 'Needed by 3 packages, built once' : 'Needed by 3, built once';
      pill(sx + (WIDE ? 18 : -10), sy + (WIDE ? 40 : 36), text, { h: 24, size: 11.5, c: P.act2, fill: rgba(P.bg0, 0.92), stroke: rgba(P.act2, 0.7), a, al: WIDE ? 'left' : 'center' });
      const dx = G.debug[0], dy = G.debug[1];
      pill(dx + (WIDE ? 26 : -60), dy + (WIDE ? 0 : 26), 'Needed by 2', { h: 24, size: 11.5, c: P.act2, fill: rgba(P.bg0, 0.92), stroke: rgba(P.act2, 0.7), a, al: WIDE ? 'left' : 'center' });
    }
    // closing stat
    if (t > 9.4) {
      const p = k(t, 9.4, 9.9);
      const x = WIDE ? 480 : 464, y = WIDE ? 468 : 30, al = WIDE ? 'center' : 'right';
      rise(p, () => {
        T(Math.round(73 * E.out(k(t, 9.4, 10.4))) + '%', x, y, { size: WIDE ? 46 : 30, w: 800, f: 'd', c: P.med, al });
        T(WIDE ? 'of the packages you ship are transitive' : 'transitive', x, y + (WIDE ? 36 : 24), { size: WIDE ? 12.5 : 11.5, c: P.muted, al });
      }, 8);
    }
  }

  /* ======================= 4. licenses ======================= */
  const LIC_ROWS = ['gin', 'jwt', 'crypto', 'net', 'axios', 'ffmpeg', 'uikit', 'follow', 'debug'];
  const LIC_SEND = LIC_ROWS.map((id, i) => 1.3 + (i < 8 ? i * 0.16 : 2.3 + (i - 8) * 0.2));
  const licColor = (l) => (!l ? P.med : /GPL/.test(l) ? P.crit : P.ok);
  function sc4(t) {
    const L = WIDE
      ? { list: [24, 24, 520, 512], node: [760, 210], r: 74, ticker: [592, 336, 344, 96], rowH: 44 }
      : { list: [16, 262, 448, 446], node: [240, 92], r: 54, ticker: [16, 168, 448, 80], rowH: 40 };
    const [lx, ly, lw] = L.list, [nx, ny] = L.node;
    // deps.dev
    pop(k(t, 0.1, 0.6), nx, ny, () => {
      glow(nx, ny, L.r * 1.9, P.low, 0.25 + 0.1 * Math.sin(t * 2));
      dot(nx, ny, L.r, P.panel2);
      ring(nx, ny, L.r, P.low, 0.9, 2);
      icon('globe', nx, ny - (WIDE ? 12 : 8), WIDE ? 34 : 28, P.low, 1, 1.8);
      T('deps.dev', nx, ny + (WIDE ? 24 : 20), { size: WIDE ? 15 : 14, w: 600, al: 'center', f: 'd' });
      // 8 concurrency slots around the ring
      for (let i = 0; i < 8; i++) {
        const a = -Math.PI / 2 + i * Math.PI / 4, busy = LIC_ROWS.some((id, j) => t > LIC_SEND[j] && t < LIC_SEND[j] + 1.3 && j % 8 === i) || (t > 3.6 && t < 6.2 && (Math.floor(t * 5) + i) % 3 === 0);
        dot(nx + Math.cos(a) * (L.r + 12), ny + Math.sin(a) * (L.r + 12), 4, busy ? P.low : P.line2);
      }
    });
    if (WIDE) T('8 lookups at a time', nx, ny + L.r + 34, { size: 12, c: P.muted, al: 'center', a: k(t, 1.2, 1.6) });
    // URL ticker
    const [tx, ty, tw, th] = L.ticker;
    rise(k(t, 1.0, 1.5), () => {
      box(tx, ty, tw, th, { r: 12, fill: P.bg0, stroke: P.line });
      const showing = t < 7 ? Math.min(LIC_ROWS.length - 1, Math.max(0, Math.floor((t - 1.3) / 0.6))) : 2;
      const id = t < 3.5 ? 'crypto' : LIC_ROWS[showing];
      const p = PK[id], sys = p.eco === 'Go' ? 'GO' : 'NPM';
      const esc = encodeURIComponent(p.name).replace(/@/g, '%40');
      T('GET api.deps.dev', tx + 14, ty + 20, { size: 11.5, f: 'm', w: 600, c: P.low });
      const l1 = '/v3/systems/' + sys + '/packages/', l2 = esc + '/versions/' + p.v;
      T(l1, tx + 14, ty + 42, { size: 12, f: 'm', c: P.muted, max: tw - 28 });
      // highlight the escaped slashes
      const parts = l2.split(/(%2F|%40)/);
      runs(parts.map((s) => [s, s === '%2F' || s === '%40' ? P.med : P.text]), tx + 14, ty + 62, { size: 12, f: 'm' });
      if (WIDE) T(id === 'crypto' && t < 3.5 ? '"/" in a module path is sent as %2F' : '', tx + 14, ty + 82, { size: 11, c: P.faint });
    });
    // rows
    LIC_ROWS.forEach((id, i) => {
      const p = PK[id], y = ly + 26 + i * L.rowH, ap = k(t, 0.3 + i * 0.07, 0.7 + i * 0.07);
      if (ap <= 0) return;
      const sent = LIC_SEND[i], back = sent + 1.1, got = k(t, back, back + 0.3);
      const deny = id === 'ffmpeg' ? k(t, 7.2, 7.6) : 0, unk = id === 'uikit' ? k(t, 8.4, 8.8) : 0;
      rise(ap, () => {
        box(lx, y - L.rowH / 2 + 3, lw, L.rowH - 6, { r: 10, fill: deny ? rgba(P.crit, 0.12 * deny) : unk ? rgba(P.med, 0.1 * unk) : rgba(P.panel, 0.7), stroke: deny ? rgba(P.crit, 0.7 * deny) : unk ? rgba(P.med, 0.6 * unk) : P.line, glow: deny ? P.crit : null, gb: 18, ga: deny * 0.5 });
        pill(lx + 12, y, p.eco, { h: 20, size: 10.5, c: P.faint, pad: 7 });
        T(p.s, lx + 50, y + 0.5, { size: 12.5, f: 'm', w: 500, max: WIDE ? 190 : 150 });
        if (WIDE) T(p.v, lx + 250, y + 0.5, { size: 11.5, f: 'm', c: P.faint });
        const sx = lx + lw - 14;
        if (got <= 0) {
          if (t > sent && t < back) spinner(sx - 10, y, 7, t, P.low, 0.9);
          else T('…', sx - 4, y, { size: 13, c: P.faint, al: 'right' });
        } else {
          const lic = p.lic || 'unknown';
          pop(got, sx - 40, y, () => pill(sx, y, lic, { al: 'right', h: 24, size: 11.5, c: licColor(p.lic), fill: rgba(licColor(p.lic), 0.14), stroke: rgba(licColor(p.lic), 0.5) }));
        }
      });
      // request and response travel to deps.dev and back
      const a = [lx + lw, y], b = WIDE ? [nx - L.r, ny] : [nx, ny + L.r], c = WIDE ? [mix(a[0], b[0], 0.5), mix(a[1], b[1], 0.3)] : [mix(a[0], b[0], 0.3) + 60, mix(a[1], b[1], 0.5)];
      packet(a, c, b, E.io(k(t, sent, sent + 0.55)), P.low, { r: 3.5 });
      const col = licColor(p.lic);
      packet(b, c, a, E.io(k(t, sent + 0.6, back + 0.1)), id === 'uikit' ? P.med : col, { r: 3.5 });
      if (id === 'uikit' && t > sent + 0.5 && t < sent + 1.0) T('404', b[0] + (WIDE ? -L.r - 6 : 30), b[1] + (WIDE ? -30 : 10), { size: 12, f: 'm', w: 600, c: P.med, al: 'center', a: k(t, sent + 0.5, sent + 0.6) * (1 - k(t, sent + 0.9, sent + 1.0)) });
    });
    // the "13 more" row as a quick burst
    const yMore = ly + 26 + LIC_ROWS.length * L.rowH;
    rise(k(t, 1.0, 1.4), () => {
      T('+ 13 more packages', lx + 14, yMore, { size: 12.5, c: P.muted });
      const done = Math.round(13 * k(t, 3.6, 6.4));
      T(done + ' / 13 checked', lx + lw - 14, yMore, { size: 12, f: 'm', c: done === 13 ? P.ok : P.faint, al: 'right' });
    });
    for (let i = 0; i < 13; i++) {
      const s = 3.6 + i * 0.2, a = [lx + lw, yMore], b = WIDE ? [nx - L.r, ny] : [nx, ny + L.r], c = [mix(a[0], b[0], 0.5), mix(a[1], b[1], 0.5) + (WIDE ? 40 : 0)];
      packet(a, c, b, E.io(k(t, s, s + 0.45)), P.low, { r: 2.5, a: 0.8 });
      packet(b, c, a, E.io(k(t, s + 0.5, s + 0.95)), P.ok, { r: 2.5, a: 0.8 });
    }
    // policy callouts
    if (t > 7.2) {
      const i = LIC_ROWS.indexOf('ffmpeg'), y = ly + 26 + i * L.rowH, a = k(t, 7.3, 7.7);
      badge(lx - (WIDE ? 0 : 0) + 2, y, 9, P.crit, 'no', a);
      if (WIDE) pill(lx + lw + 14, y, 'denied_licenses', { h: 24, size: 11.5, c: P.crit, a, fill: rgba(P.bg0, 0.92), stroke: rgba(P.crit, 0.6) });
    }
    if (t > 8.4) {
      const i = LIC_ROWS.indexOf('uikit'), y = ly + 26 + i * L.rowH, a = k(t, 8.5, 8.9);
      badge(lx + 2, y, 9, P.med, '!', a);
      if (WIDE) pill(lx + lw + 14, y, 'unknown: warns', { h: 24, size: 11.5, c: P.med, a, fill: rgba(P.bg0, 0.92), stroke: rgba(P.med, 0.6) });
    }
    // tally
    if (t > 9.6 && WIDE) {
      const p = k(t, 9.6, 10.1);
      const items = [['MIT', 15, P.ok], ['BSD-3-Clause', 4, P.ok], ['Apache-2.0', 1, P.ok], ['GPL-3.0-or-later', 1, P.crit], ['unknown', 1, P.med]];
      let y = 456;
      rise(p, () => {
        T('All 22 packages', 592, y, { size: 12.5, w: 600, c: P.text });
        let x = 592; y += 26;
        items.forEach(([l, n, c], i) => {
          const w = pill(x, y + (i > 2 ? 30 : 0), n + '  ' + l, { h: 24, size: 11.5, c, fill: rgba(c, 0.14) });
          x += w + 8; if (i === 2) x = 592;
        });
      }, 8);
    }
  }

  /* ======================= 5. ask OSV.dev ======================= */
  // Detail fetches: 8 workers pull IDs off a queue; one request gets a 503 and is retried.
  const JOBS = (() => {
    const rnd = seeded(7), free = Array.from({ length: 8 }, (_, i) => 5.9 + i * 0.07), jobs = [];
    RAW.forEach((r, i) => {
      let w = 0; for (let j = 1; j < 8; j++) if (free[j] < free[w] - 1e-9) w = j;
      const start = free[w], dur = 1.5 + rnd() * 0.6, retry = r.id === 'GO-2025-3553';
      const att = retry ? [[start, start + 0.85, true], [start + 0.85 + 0.5, start + 0.85 + 0.5 + dur, false]] : [[start, start + dur, false]];
      const end = att[att.length - 1][1];
      jobs.push({ r, i, w, att, start, end, retry });
      free[w] = end + 0.08;
    });
    return jobs;
  })();
  const JOBS_DONE = Math.max(...JOBS.map((j) => j.end));
  const HITS = [['crypto', 6], ['gin', 2], ['jwt', 2], ['net', 2], ['axios', 2], ['follow', 1]];
  const shortSev = (s) => (s === 'CRITICAL' ? 'Critical' : s === 'HIGH' ? 'High' : s === 'MODERATE' ? 'Moderate' : 'no severity');
  function sc5(t) {
    const L = WIDE
      ? { node: [836, 270], r: 70, env: [28, 56, 420, 300], q: [24, 60], qw: 214, lanes: [262, 760], laneY: (i) => 96 + i * 46 }
      : { node: [240, 74], r: 48, env: [16, 150, 448, 300], q: [16, 372], qw: 216, lanes: null, laneY: null };
    const [nx, ny] = L.node;
    // OSV node
    pop(k(t, 0, 0.5), nx, ny, () => {
      const pulse = k(t, 3.5, 4.2);
      glow(nx, ny, L.r * 2, P.act, 0.3 + 0.5 * Math.sin(pulse * Math.PI));
      dot(nx, ny, L.r, P.panel2); ring(nx, ny, L.r, P.act2, 0.9, 2);
      icon('db', nx, ny - (WIDE ? 12 : 8), WIDE ? 34 : 26, P.act2, 1, 1.8);
      T('OSV.dev', nx, ny + (WIDE ? 24 : 18), { size: WIDE ? 16 : 14, w: 600, f: 'd', al: 'center' });
      if (WIDE) T('api.osv.dev', nx, ny + L.r + 22, { size: 11.5, f: 'm', c: P.faint, al: 'center' });
      ripple(nx, ny, pulse, P.act2, L.r * 1.8);
    });
    const [ex, ey, ew, eh] = L.env;

    // ---- phase A: one batch request ----
    const sealed = E.io(k(t, 2.4, 2.9));
    if (t < 3.0) {
      ctx.save();
      const cx = ex + ew / 2, cy = ey + eh / 2, s = 1 - 0.6 * sealed;
      ctx.translate(cx, cy); ctx.scale(s, s); ctx.translate(-cx, -cy);
      fade(k(t, 0, 0.5) * (1 - k(t, 2.6, 2.95)), () => {
        const top = card(ex, ey, ew, eh, { title: 'POST /v1/querybatch', icon: 'doc', tag: '22 of max 100' });
        T('ecosystem', ex + 16, top + 16, { size: 11, c: P.faint });
        T('package', ex + 96, top + 16, { size: 11, c: P.faint });
        T('version', ex + ew - 16, top + 16, { size: 11, c: P.faint, al: 'right' });
        PKGS.forEach((p, i) => {
          const at = 0.3 + i * 0.08, a = k(t, at + 0.35, at + 0.5);
          if (i < 6) {
            const y = top + 38 + i * 19;
            T(p.eco, ex + 16, y, { size: 12, f: 'm', c: P.muted, a });
            T(p.name, ex + 96, y, { size: 12, f: 'm', a, max: ew - 96 - 90 });
            T(p.v.replace(/^v/, ''), ex + ew - 16, y, { size: 12, f: 'm', c: P.med, al: 'right', a });
          } else {
            const y = top + 38 + 6 * 19 + (i - 6) * 7;
            box(ex + 16, y - 2, ew - 32, 4, { r: 2, fill: P.line2, a: a * 0.8 });
          }
        });
        if (t > 1.2) pill(ex + ew - 14, top + 38 + 2 * 19 + 22, 'sent as 0.14.0, without the v', { al: 'right', h: 22, size: 11, c: P.med, fill: rgba(P.bg0, 0.94), stroke: rgba(P.med, 0.6), a: k(t, 1.2, 1.5) * (1 - k(t, 2.2, 2.5)) });
      });
      ctx.restore();
      // dots flying in
      PKGS.forEach((p, i) => {
        const at = 0.3 + i * 0.08, fp = k(t, at, at + 0.45);
        if (fp <= 0 || fp >= 1) return;
        const from = WIDE ? [-10, 120 + i * 18] : [-10, 560 + i * 6], to = [ex + 40, ey + 100 + Math.min(i, 8) * 16];
        packet(from, [mix(from[0], to[0], 0.5), from[1] - 20], to, E.io(fp), p.direct ? P.act2 : P.muted, { r: 3 });
      });
    }
    // the envelope flies to OSV.dev and the answer comes back
    const envC = [ex + ew / 2, ey + eh / 2];
    const nodeIn = WIDE ? [nx - L.r, ny] : [nx, ny + L.r];
    const goC = WIDE ? [mix(envC[0], nodeIn[0], 0.5), ey - 20] : [nx + 140, mix(envC[1], nodeIn[1], 0.5)];
    const backC = WIDE ? [mix(envC[0], nodeIn[0], 0.5), ey + eh + 40] : [nx - 140, mix(envC[1], nodeIn[1], 0.5)];
    const out = E.io(k(t, 2.8, 3.6)), ret = E.io(k(t, 4.0, 4.8));
    if (out > 0 && out < 1) { const q = qpt(envC, goC, nodeIn, out); glow(q[0], q[1], 30, P.act, 0.6); pill(q[0], q[1], '22 queries', { al: 'center', h: 26, size: 12, c: P.act2, fill: P.panel3, stroke: P.act2 }); }
    if (ret > 0 && ret < 1) { const q = qpt(nodeIn, backC, envC, ret); glow(q[0], q[1], 30, P.ok, 0.6); pill(q[0], q[1], '200 OK', { al: 'center', h: 26, size: 12, c: P.ok, fill: P.panel3, stroke: P.ok }); }

    // response: IDs only
    const resp = k(t, 4.7, 5.2) * (1 - k(t, 5.9, 6.4));
    if (resp > 0) rise(resp, () => {
      const top = card(ex, ey, ew, eh, { title: '200 OK: matching IDs', icon: 'doc', tag: 'IDs only', tagc: P.med });
      HITS.forEach(([id, n], i) => {
        const y = top + 22 + i * 30, p = PK[id];
        T(p.s, ex + 16, y, { size: 12.5, f: 'm', w: 500 });
        const w = pill(ex + ew - 16, y, n + (n === 1 ? ' ID' : ' IDs'), { al: 'right', h: 22, size: 11.5, c: P.act2 });
        for (let j = 0; j < Math.min(n, 6); j++) box(ex + ew - 26 - w - j * 12, y - 5, 8, 10, { r: 2, fill: P.act2, a: 0.6 });
      });
      const y = top + 22 + HITS.length * 30 + 6;
      badge(ex + 24, y, 8, P.ok, 'ok', 1);
      T('16 packages: no known vulnerabilities', ex + 40, y, { size: 12.5, c: P.ok });
    });

    // ---- phase B: details, 8 workers ----
    const pb = k(t, 5.7, 6.2);
    if (pb <= 0) return;
    const laneA = (i) => (WIDE ? [L.lanes[0] + 26, L.laneY(i)] : [36 + i * 58, 316]);
    const laneB = (i) => {
      if (WIDE) { const a = (i - 3.5) * 0.17; return [nx - Math.cos(a) * L.r, ny + Math.sin(a) * L.r]; }
      const a = Math.PI / 2 + (i - 3.5) * 0.2; return [nx + Math.cos(a) * L.r, ny + Math.sin(a) * L.r];
    };
    const laneC = (i) => (WIDE ? [650, L.laneY(i)] : [laneA(i)[0], 190]);
    fade(pb, () => {
      for (let i = 0; i < 8; i++) {
        const a = laneA(i), b = laneB(i), c = laneC(i);
        curve(a, c, b, { c: P.line2, lw: 1, dash: [3, 5], a: 0.7 });
        const busy = JOBS.some((j) => j.w === i && t > j.start && t < j.end);
        dot(a[0], a[1], 5, busy ? P.act : P.line2);
        T('w' + (i + 1), a[0] + (WIDE ? -14 : 0), a[1] + (WIDE ? 0 : 16), { size: 10.5, f: 'm', c: busy ? P.act2 : P.faint, al: WIDE ? 'right' : 'center' });
      }
      if (WIDE) T('GET /v1/vulns/{id}', L.lanes[0] + 26, 62, { size: 12, f: 'm', w: 600, c: P.act2 });
      else T('GET /v1/vulns/{id}, 8 at a time', 240, 348, { size: 12, f: 'm', w: 600, c: P.act2, al: 'center' });
    });
    // the queue of IDs
    JOBS.forEach((j) => {
      const r = j.r, col = WIDE ? 0 : (j.i < 8 ? 0 : 1), row = WIDE ? j.i : j.i % 8;
      const x = L.q[0] + col * (L.qw + 16), y = L.q[1] + row * (WIDE ? 30 : 38) + (WIDE ? 6 : 0);
      const a = k(t, 5.8 + j.i * 0.03, 6.2 + j.i * 0.03);
      const done = t > j.end, active = t > j.start && !done, dp = k(t, j.end, j.end + 0.3);
      const c = done ? sevc(r.sev) : P.line2;
      fade(a, () => {
        box(x, y - 12, L.qw, 24, { r: 7, fill: active ? rgba(P.act, 0.18) : rgba(P.panel, 0.85), stroke: active ? P.act2 : P.line, glow: done && r.sev ? sevc(r.sev) : null, gb: 12, ga: (1 - k(t, j.end + 0.3, j.end + 1.2)) * 0.7 });
        box(x + 1, y - 7, 3, 14, { r: 1.5, fill: done ? c : P.line2 });
        T(r.id, x + 10, y + 0.5, { size: 11, f: 'm', w: 500, c: done ? P.text : P.muted, max: L.qw - 74 });
        if (done) T(shortSev(r.sev), x + L.qw - 8, y + 0.5, { size: 10.5, w: 600, c: r.sev ? sevc(r.sev) : P.unk, al: 'right', a: dp });
        else if (active) spinner(x + L.qw - 14, y, 5, t, P.act2);
      });
      // requests on the worker's lane
      j.att.forEach(([s, e, fail], n) => {
        const a0 = laneA(j.w), b0 = laneB(j.w), c0 = laneC(j.w), mid = (s + e) / 2;
        packet(a0, c0, b0, E.io(k(t, s, mid)), P.act2, { r: 3.5 });
        packet(b0, c0, a0, E.io(k(t, mid, e)), fail ? P.crit : r.sev ? sevc(r.sev) : P.unk, { r: 3.5 });
        if (fail && t > mid - 0.05 && t < e + 0.6) {
          const fa = k(t, mid - 0.05, mid + 0.1) * (1 - k(t, e + 0.3, e + 0.6));
          pill(b0[0] + (WIDE ? -14 : 16), b0[1] + (WIDE ? -26 : 4), '503', { al: WIDE ? 'right' : 'left', h: 22, size: 11.5, c: P.crit, fill: rgba(P.bg0, 0.94), stroke: rgba(P.crit, 0.7), a: fa });
          ripple(b0[0], b0[1], k(t, mid, mid + 0.5), P.crit, 30);
        }
        if (fail && t > e && t < j.att[n + 1][0]) {
          const w0 = j.att[n + 1][0], left = Math.max(0, (w0 - t) * 1000);
          const [ax0, ay0] = laneA(j.w), pr = k(t, e, w0);
          A(); ctx.strokeStyle = P.med; ctx.lineWidth = 2.5; ctx.beginPath(); ctx.arc(ax0, ay0, 11, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * pr); ctx.stroke();
          pill(ax0 + (WIDE ? 18 : -60), ay0 + (WIDE ? 0 : -26), 'retry in ' + Math.round(left / 10) * 10 + ' ms', { h: 22, size: 11, c: P.med, fill: rgba(P.bg0, 0.94), stroke: rgba(P.med, 0.6) });
        }
      });
    });
    // summary
    if (t > JOBS_DONE + 0.3) {
      const p = k(t, JOBS_DONE + 0.3, JOBS_DONE + 0.8);
      const x = WIDE ? 262 : 16, y = WIDE ? 478 : 676;
      rise(p, () => {
        if (WIDE) {
          runs([['15', P.text], [' records fetched by ', P.muted], ['8', P.text], [' workers, ', P.muted], ['1', P.med], [' retried after a 503', P.muted]], x, y, { size: 14, w: 500 });
          const fc = k(t, JOBS_DONE + 1.4, JOBS_DONE + 1.9);
          fade(fc, () => { badge(x + 8, y + 32, 8, P.ok, 'ok', 1); T('A request that still fails after 3 tries stops the scan: no silent gaps', x + 24, y + 32, { size: 12.5, c: P.ok }); });
        } else {
          T('15 records, 8 workers, 1 retry after a 503', 240, y, { size: 13, w: 500, al: 'center' });
          T('3 failed tries stop the scan: no silent gaps', 240, y + 24, { size: 12, c: P.ok, al: 'center', a: k(t, JOBS_DONE + 1.4, JOBS_DONE + 1.9) });
        }
      }, 6);
    }
  }

  /* ======================= 6. merge duplicates ======================= */
  const GRID15 = [0, 4, 10, 13, 2, 6, 12, 1, 8, 5, 3, 14, 11, 7, 9];       // shuffled so pairs sit apart
  const GROUPS = ['A', 'B', 'C', 'D', 'E', 'F'];
  const KEEP = RAW.filter((r) => r.id.startsWith('GHSA'));                   // 9 survivors
  function sc6(t) {
    const cw = WIDE ? 172 : 216, ch = WIDE ? 66 : 54;
    const pos0 = (slot) => (WIDE ? [24 + (slot % 5) * 182, 60 + Math.floor(slot / 5) * 82] : [16 + (slot % 2) * 232, 16 + Math.floor(slot / 2) * 58]);
    const pos1 = (slot) => (WIDE ? [24 + (slot % 3) * 190, 60 + Math.floor(slot / 3) * 82] : [16 + (slot % 2) * 232, 16 + Math.floor(slot / 2) * 58]);
    const slotOf = (ri) => GRID15.indexOf(ri);
    const groupT = (g) => 1.0 + GROUPS.indexOf(g) * 0.4;
    const mergeT = (g) => 3.8 + GROUPS.indexOf(g) * 0.25;
    const reflow = E.io(k(t, 5.6, 6.5));

    const center = (ri) => {
      const r = RAW[ri], keepIdx = KEEP.indexOf(r);
      let [x, y] = pos0(slotOf(ri));
      if (keepIdx >= 0) { const [x1, y1] = pos1(keepIdx); x = mix(x, x1, reflow); y = mix(y, y1, reflow); }
      else {
        const partner = RAW.findIndex((o) => o.g === r.g && o !== r);
        const mp = E.io(k(t, mergeT(r.g), mergeT(r.g) + 0.6));
        const [px, py] = pos0(slotOf(partner));
        x = mix(x, px, mp); y = mix(y, py, mp);
      }
      return [x + cw / 2, y + ch / 2];
    };
    // cards
    RAW.forEach((r, ri) => {
      const isKeep = r.id.startsWith('GHSA');
      const partner = RAW.find((o) => o.g === r.g && o !== r);
      const mp = partner ? k(t, mergeT(r.g), mergeT(r.g) + 0.6) : 0;
      const a = k(t, 0.1 + slotOf(ri) * 0.04, 0.5 + slotOf(ri) * 0.04) * (isKeep ? 1 : 1 - k(mp, 0.6, 1));
      if (a <= 0) return;
      const [cx, cy] = center(ri), x = cx - cw / 2, y = cy - ch / 2;
      const s = isKeep ? 1 : 1 - 0.25 * k(mp, 0.5, 1);
      const highlight = r.g === 'F' && t > 6.8 && t < 12 ? k(t, 6.8, 7.2) : 0;
      fade(a, () => {
        ctx.save(); ctx.translate(cx, cy); ctx.scale(s, s); ctx.translate(-cx, -cy);
        const c = sevc(r.sev);
        box(x, y, cw, ch, { r: 10, fill: P.panel, stroke: highlight ? P.act2 : P.line, lw: highlight ? 2 : 1, shadow: 'rgba(0,0,0,.35)', blur: 16, oy: 6, glow: highlight ? P.act : null, gb: 20, ga: highlight * 0.7 });
        box(x + 1, y + 8, 3, ch - 16, { r: 2, fill: c });
        T(r.id, x + 12, y + 17, { size: WIDE ? 11.5 : 12, f: 'm', w: 600, max: cw - 20 });
        T(PK[r.pkg].s, x + 12, y + 36, { size: 11, f: 'm', c: P.muted, max: cw - 90 });
        T(r.sev ? shortSev(r.sev) : 'no severity', x + cw - 10, y + 36, { size: 11, w: 600, c: r.sev ? c : P.unk, al: 'right' });
        const gp = isKeep && partner ? k(t, mergeT(r.g) + 0.5, mergeT(r.g) + 0.8) : 0;
        if (WIDE) {
          T('alias ' + r.cve, x + 12, y + 54, { size: 10.5, f: 'm', c: P.faint, max: cw - 20, a: 1 - gp });
          if (gp > 0) T('also ' + partner.id, x + 12, y + 54, { size: 10.5, f: 'm', w: 600, c: P.act2, max: cw - 20, a: gp });
        } else if (gp > 0) pill(x + cw - 8, y + 17, '+' + partner.id.slice(0, 2), { al: 'right', h: 18, size: 10, c: P.act2, fill: P.panel3, pad: 6, a: gp });
        ctx.restore();
      });
    });
    // links between records that share an alias
    GROUPS.forEach((g) => {
      const pair = RAW.map((r, i) => [r, i]).filter(([r]) => r.g === g);
      if (pair.length < 2) return;
      const lp = k(t, groupT(g), groupT(g) + 0.5), gone = k(t, mergeT(g), mergeT(g) + 0.5);
      if (lp <= 0 || gone >= 1) return;
      const a = center(pair[0][1]), b = center(pair[1][1]);
      const c = [(a[0] + b[0]) / 2, Math.min(a[1], b[1]) - (WIDE ? 70 : 40) - Math.abs(a[0] - b[0]) * 0.08];
      curve(a, c, b, { p: E.io(lp), c: P.act2, lw: 1.4, a: (1 - gone) * (0.55 + 0.45 * (1 - k(t, groupT(g) + 1.1, groupT(g) + 1.5))), glow: P.act, gb: 8 });
      if (lp > 0.6) {
        const m = qpt(a, c, b, 0.5);
        pill(m[0], m[1], pair[0][0].cve, { al: 'center', h: 22, size: 11, c: P.act2, fill: P.bg0, stroke: rgba(P.act2, 0.7), a: k(lp, 0.6, 1) * (1 - gone) * (1 - k(t, groupT(g) + 1.1, groupT(g) + 1.5)) });
      }
    });
    // counter
    const cp = k(t, 3.8, 6.2), n = Math.round(mix(15, 9, E.io(cp)));
    if (t > 0.4) {
      const x = WIDE ? 936 : 464, y = WIDE ? 30 : 0;
      if (WIDE) {
        T('advisories', x, y + 6, { size: 12, c: P.muted, al: 'right', a: k(t, 0.4, 0.8) });
        T(String(n), x - TW('advisories', { size: 12 }) - 10, y + 4, { size: 26, w: 800, f: 'd', c: cp >= 1 ? P.ok : P.text, al: 'right', a: k(t, 0.4, 0.8) });
      }
    }
    // the key example
    if (t > 6.8) {
      const p = k(t, 6.8, 7.3);
      const [bx, by, bw, bh] = WIDE ? [612, 60, 324, 228] : [16, 326, 448, 190];
      rise(p, () => {
        const top = card(bx, by, bw, bh, { title: 'Which record is kept?', icon: 'shield', tag: 'x/net' });
        const r1 = top + 24, r2 = top + 58;
        T('GO-2023-2102', bx + 16, r1, { size: 12.5, f: 'm', w: 500, c: P.muted });
        pill(bx + bw - 14, r1, 'no severity', { al: 'right', h: 22, size: 11, c: P.unk });
        const sp = k(t, 7.6, 8.0);
        line(bx + 14, r1 + 1, bx + 14 + TW('GO-2023-2102', { size: 12.5, f: 'm', w: 500 }) + 4, r1 + 1, { c: P.faint, p: sp, lw: 1.5 });
        T('GHSA-4374-p667-p6c8', bx + 16, r2, { size: 12.5, f: 'm', w: 600 });
        pill(bx + bw - 14, r2, 'High', { al: 'right', h: 22, size: 11, c: P.high });
        badge(bx + bw - 76, r2, 8, P.ok, 'ok', k(t, 7.8, 8.2));
        T('Both list CVE-2023-39325 as an alias.', bx + 16, r2 + 32, { size: 12, c: P.muted, max: bw - 32 });
        const wl = wrap('Unmerged, the GO- copy would be unrated and pass a policy that blocks HIGH.', bw - 44, { size: 12 });
        const wa = k(t, 9.2, 9.7);
        if (wa > 0) { badge(bx + 24, r2 + 62, 8, P.med, '!', wa); wl.forEach((s, i) => T(s, bx + 38, r2 + 62 + i * 17, { size: 12, c: P.med, a: wa })); }
      });
    }
    // the rule
    if (t > 8.0 && WIDE) {
      const rules = ['Same package version, and a shared ID or alias: it is the same flaw', 'Keep the record that has a severity, because an unrated copy could slip past the policy', 'Still tied? Keep the GHSA record', 'Every other ID becomes an alias, so an exception written against any of them still matches'];
      rules.forEach((s, i) => {
        const p = k(t, 8.0 + i * 0.45, 8.4 + i * 0.45), y = 330 + i * 46;
        rise(p, () => {
          box(24, y - 18, 912, 36, { r: 10, fill: rgba(P.panel, 0.8), stroke: P.line });
          dot(46, y, 11, P.act); T(String(i + 1), 46, y + 0.5, { size: 12, w: 700, c: '#fff', al: 'center' });
          T(s, 66, y + 0.5, { size: 13, c: P.text });
        }, 8);
      });
    }
    if (!WIDE && t > 9.8) {
      rise(k(t, 9.8, 10.3), () => {
        T('15 records become 9 advisories', 240, 560, { size: 16, w: 700, f: 'd', al: 'center' });
        T('keep the record with a severity, then GHSA', 240, 588, { size: 12.5, c: P.muted, al: 'center' });
        T('the other IDs become aliases', 240, 608, { size: 12.5, c: P.muted, al: 'center' });
      });
    }
  }

  /* ======================= 7. apply the policy ======================= */
  const GATE = [
    { pkg: 'crypto', label: 'GHSA-v778-237x-gjrc', sev: 'CRITICAL', lines: [0], out: 'block' },
    { pkg: 'crypto', label: 'GHSA-hcg3-q754-cr77', sev: 'HIGH', lines: [0], out: 'block' },
    { pkg: 'jwt', label: 'GHSA-mh63-6h87-95cp', sev: 'HIGH', lines: [0], out: 'block' },
    { pkg: 'net', label: 'GHSA-4374-p667-p6c8', sev: 'HIGH', lines: [0, 2], out: 'block', note: 'transitive' },
    { pkg: 'axios', label: 'GHSA-cph5-m8f7-6c5x', sev: 'HIGH', lines: [0], out: 'block' },
    { pkg: 'follow', label: 'GHSA-74fj-2j2h-c42q', sev: 'HIGH', lines: [0, 2], out: 'block', note: 'transitive' },
    { pkg: 'crypto', label: 'GHSA-45x7-px36-x8w8', sev: 'MODERATE', lines: [1], out: 'warn' },
    { pkg: 'axios', label: 'GHSA-wf5p-g6vw-rhxx', sev: 'MODERATE', lines: [1], out: 'warn' },
    { pkg: 'gin', label: 'GHSA-2c4m-59x9-fr2g', sev: 'MODERATE', lines: [8, 9, 10], out: 'allow', note: 'until 2026-12-31' },
    { pkg: 'ffmpeg', label: 'license GPL-3.0-or-later', sev: 'LIC', lines: [3, 4], out: 'block' },
    { pkg: 'uikit', label: 'license unknown', sev: 'LICU', lines: [6], out: 'warn' }
  ];
  const OUTC = { block: P.crit, warn: P.med, allow: P.ok };
  const OUTL = { block: 'Blocks', warn: 'Warns', allow: 'Allowed' };
  const gateT = (i) => 0.8 + i * 1.0;
  const itemColor = (it) => (it.sev === 'LIC' ? P.crit : it.sev === 'LICU' ? P.med : sevc(it.sev));
  function sc7(t) {
    const L = WIDE
      ? { pol: [24, 24, 336, 304], gate: [396, 168, 540], spawn: [666, 56], lanes: [[396, 232, 176], [580, 232, 172], [760, 232, 176]], laneH: 310, chipW: [160, 156, 160], lh: 21, fs: 12 }
      : { pol: [16, 16, 448, 262], gate: [16, 330, 448], spawn: [240, 300], lanes: [[16, 380, 144], [168, 380, 144], [320, 380, 144]], laneH: 250, chipW: [132, 132, 132], lh: 19, fs: 11.5 };
    const [px, py, pw, ph] = L.pol;
    // which policy lines are lit right now
    const lit = new Array(POLICY_TEXT.length).fill(0);
    GATE.forEach((it, i) => { const s = gateT(i) + 0.3; it.lines.forEach((l) => { lit[l] = Math.max(lit[l], k(t, s, s + 0.15) * (1 - k(t, s + 0.6, s + 0.9))); }); });
    rise(k(t, 0, 0.5), () => {
      const top = card(px, py, pw, ph, { title: 'policy.yaml', icon: 'shield', tag: 'your rules' });
      POLICY_TEXT.forEach((s, i) => {
        const y = top + 16 + i * L.lh;
        if (lit[i] > 0) box(px + 6, y - L.lh / 2, pw - 12, L.lh, { r: 5, fill: rgba(P.act, 0.3 * lit[i]), stroke: rgba(P.act2, 0.6 * lit[i]) });
        ctx.save(); rr(px, y - L.lh / 2, pw - 8, L.lh, 0); ctx.clip();
        codeLine(s, px + 14, y, { size: L.fs });
        ctx.restore();
      });
    });
    // gate
    const [gx, gy, gw] = L.gate;
    rise(k(t, 0.3, 0.8), () => {
      box(gx, gy - 3, gw, 6, { r: 3, fill: P.line2 });
      const scan = (t * 0.6) % 1;
      box(gx + scan * (gw - 80), gy - 3, 80, 6, { r: 3, fill: P.act, glow: P.act, gb: 14, ga: 0.8, a: 0.9 });
      if (WIDE) T('policy gate', gx, gy - 16, { size: 11.5, w: 600, c: P.faint });
    }, 0);
    // lanes
    L.lanes.forEach(([x, y, w], li) => {
      const out = ['block', 'warn', 'allow'][li];
      const n = GATE.filter((it, i) => it.out === out && t > gateT(i) + 1.1).length;
      rise(k(t, 0.4 + li * 0.1, 0.9 + li * 0.1), () => {
        box(x, y, w, L.laneH, { r: 14, fill: rgba(OUTC[out], 0.06), stroke: rgba(OUTC[out], 0.35) });
        T(out === 'block' ? 'Blocks the build' : out === 'warn' ? 'Warns' : 'Allowed', x + 14, y + 22, { size: WIDE ? 13 : 12, w: 600, c: OUTC[out] });
        T(String(n), x + w - 14, y + 22, { size: WIDE ? 20 : 17, w: 800, f: 'd', c: OUTC[out], al: 'right' });
      });
    });
    // items
    GATE.forEach((it, i) => {
      const s = gateT(i), p = PK[it.pkg];
      if (t < s) return;
      const enter = E.out(k(t, s, s + 0.35)), decide = k(t, s + 0.35, s + 0.6), drop = E.io(k(t, s + 0.65, s + 1.1));
      const li = ['block', 'warn', 'allow'].indexOf(it.out), lane = L.lanes[li], cwid = L.chipW[li];
      const idx = GATE.slice(0, i).filter((o) => o.out === it.out).length;
      const target = [lane[0] + 8, lane[1] + 50 + idx * (WIDE ? 30 : 28)];
      const bigW = WIDE ? 300 : 300, bigH = 36;
      const atGate = [L.spawn[0] - bigW / 2, gy - bigH - 8];
      const start = WIDE ? [L.spawn[0] - bigW / 2, L.spawn[1] - 40] : [L.spawn[0] - bigW / 2, gy - bigH - 60];
      let x = mix(start[0], atGate[0], enter), y = mix(start[1], atGate[1], enter), w = bigW, h = bigH;
      if (drop > 0) { x = mix(atGate[0], target[0], drop); y = mix(atGate[1], target[1] - 12, drop); w = mix(bigW, cwid, drop); h = mix(bigH, 24, drop); }
      const c = itemColor(it), oc = OUTC[it.out];
      fade(k(t, s, s + 0.2), () => {
        box(x, y, w, h, { r: 9, fill: P.panel, stroke: decide > 0 ? oc : P.line2, lw: decide > 0 ? 1.6 : 1, glow: decide > 0 && drop < 1 ? oc : null, gb: 18, ga: decide * (1 - drop) * 0.8, shadow: drop < 0.5 ? 'rgba(0,0,0,.4)' : null, blur: 14, oy: 6 });
        box(x + 1, y + 6, 3, h - 12, { r: 2, fill: c });
        const big = drop < 0.5;
        if (big) {
          T(p.s, x + 12, y + h / 2 + 0.5, { size: 12.5, f: 'm', w: 600 });
          const nw = TW(p.s, { size: 12.5, f: 'm', w: 600 });
          T(it.label, x + 22 + nw, y + h / 2 + 0.5, { size: 11, f: 'm', c: P.muted, max: w - nw - 110 });
          const sl = it.sev === 'LIC' || it.sev === 'LICU' ? 'license' : shortSev(it.sev);
          pill(x + w - 8, y + h / 2, decide > 0.5 ? OUTL[it.out] : sl, { al: 'right', h: 22, size: 11, c: decide > 0.5 ? oc : c });
          if (it.note && decide > 0.3) pill(x + w / 2, y + h + 14, it.note, { al: 'center', h: 20, size: 10.5, c: it.out === 'allow' ? P.ok : P.act2, fill: rgba(P.bg0, 0.94), stroke: rgba(it.out === 'allow' ? P.ok : P.act2, 0.6), a: decide * (1 - drop * 2) });
        } else {
          T(p.s, x + 10, y + h / 2 + 0.5, { size: 11.5, f: 'm', w: 500, max: w - 64 });
          const sl = it.sev === 'LIC' ? 'license' : it.sev === 'LICU' ? 'license' : it.sev === 'CRITICAL' ? 'crit' : it.sev === 'HIGH' ? 'high' : 'mod';
          T(sl, x + w - 8, y + h / 2 + 0.5, { size: 10.5, w: 600, c, al: 'right' });
        }
      });
    });
    // result
    if (t > 12.2) {
      const p = k(t, 12.2, 12.7);
      const x = WIDE ? 24 : 16, y = WIDE ? 380 : 646;
      rise(p, () => {
        if (WIDE) {
          box(x, y - 26, 336, 156, { r: 14, fill: rgba(P.crit, 0.08), stroke: rgba(P.crit, 0.45) });
          T('$ depscan -path ./shop-api', x + 16, y, { size: 12.5, f: 'm', c: P.muted });
          T('7 violations, 3 warnings', x + 16, y + 26, { size: 13, f: 'm', c: P.text });
          T('exit status 1', x + 16, y + 60, { size: 26, w: 700, f: 'm', c: P.crit });
          T('CI fails the build. The gin exception lapses', x + 16, y + 96, { size: 11.5, c: P.muted });
          T('on 2026-12-31 and it warns again.', x + 16, y + 112, { size: 11.5, c: P.muted });
        } else {
          box(x, y - 22, 448, 64, { r: 12, fill: rgba(P.crit, 0.08), stroke: rgba(P.crit, 0.45) });
          T('7 violations, 3 warnings', x + 14, y - 2, { size: 12.5, f: 'm', c: P.text });
          T('exit status 1', x + 14, y + 22, { size: 18, w: 700, f: 'm', c: P.crit });
        }
      }, 8);
    }
  }

  /* ======================= 8. read the verdict ======================= */
  const TOWERS = [['crypto', 19, P.crit], ['axios', 9, P.high], ['jwt', 6, P.high], ['net', 6, P.high], ['follow', 6, P.high], ['gin', 3, P.med]];
  const CELLS = [[0, 0], [1, 0], [0, 1], [2, 0], [1, 1], [2, 1]]; // back corner first
  function iso(ox, oy, s) { const c = Math.cos(Math.PI / 6) * s, d = Math.sin(Math.PI / 6) * s; return (x, y, z) => [ox + (x - y) * c, oy + (x + y) * d - z]; }
  function prism(pt, x, y, w, h, col, a, glowA) {
    const t0 = pt(x, y, h), t1 = pt(x + w, y, h), t2 = pt(x + w, y + w, h), t3 = pt(x, y + w, h), b1 = pt(x + w, y, 0), b2 = pt(x + w, y + w, 0), b3 = pt(x, y + w, 0);
    const poly = (pts, fill) => { A(a); ctx.fillStyle = fill; ctx.beginPath(); ctx.moveTo(pts[0][0], pts[0][1]); for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i][0], pts[i][1]); ctx.closePath(); ctx.fill(); };
    const shade = (hex, f) => { const n = parseInt(hex.slice(1), 16); return 'rgb(' + (((n >> 16) & 255) * f | 0) + ',' + (((n >> 8) & 255) * f | 0) + ',' + ((n & 255) * f | 0) + ')'; };
    poly([t3, t2, b2, b3], shade(col, 0.78));
    poly([t1, t2, b2, b1], shade(col, 0.58));
    if (glowA > 0) { ctx.shadowColor = col; ctx.shadowBlur = 22 * glowA; }
    poly([t0, t1, t2, t3], col);
    ctx.shadowColor = 'transparent'; ctx.shadowBlur = 0;
  }
  function sc8(t) {
    const L = WIDE
      ? { v: [28, 34], city: [760, 146, 44], fix: [24, 296, 600, 244], all: [644, 296, 292, 244], ts: 6.5 }
      : { v: [20, 30], city: [240, 290, 34], fix: [16, 436, 448, 238], all: null, ts: 5.2 };
    // verdict
    const [vx, vy] = L.v;
    rise(k(t, 0, 0.5), () => {
      dot(vx + 5, vy, 5, P.crit); ring(vx + 5, vy, 9, P.crit, 0.35, 3);
      T('Blocked', vx + 18, vy + 0.5, { size: 13, w: 600, c: P.crit });
    });
    const words = 'This build would be blocked'.split(' ');
    let wx = vx;
    const hs = WIDE ? 36 : 28;
    words.forEach((w, i) => {
      const p = k(t, 0.3 + i * 0.08, 0.8 + i * 0.08);
      if (p > 0) { ctx.save(); rr(wx - 2, vy + 12, TW(w, { size: hs, w: 800, f: 'd' }) + 4, hs + 14, 0); ctx.clip(); T(w, wx, vy + 22 + hs / 2 + (1 - E.out(p)) * hs, { size: hs, w: 800, f: 'd', bl: 'middle' }); ctx.restore(); }
      wx += TW(w + ' ', { size: hs, w: 800, f: 'd' });
    });
    T(WIDE ? '6 packages break your policy. Upgrade them to pass.' : '6 packages break your policy.', vx, vy + 22 + hs + 22, { size: 13.5, c: P.muted, a: k(t, 0.9, 1.3) });
    const facts = [['22', 'Dependencies'], ['6', 'Direct'], ['6', 'With advisories'], ['6', 'Blocking']];
    facts.forEach(([n, l], i) => {
      const x = vx + i * (WIDE ? 128 : 110), y = vy + 22 + hs + 66, p = k(t, 1.0 + i * 0.1, 1.5 + i * 0.1);
      rise(p, () => {
        if (i) box(x - 14, y - 16, 1, 46, { r: 0, fill: P.line });
        T(String(Math.round(+n * E.out(k(t, 1.0, 2.0)))), x, y, { size: WIDE ? 28 : 24, w: 800, f: 'd', c: i === 3 ? P.crit : P.text });
        T(l, x, y + 26, { size: 11.5, c: P.muted });
      }, 6);
    });
    // city: the 16 clean packages are the plate, the 6 risky ones stand on it
    const [cx, cy, cs] = L.city, pt = iso(cx, cy, cs);
    const cityA = k(t, 1.2, 1.7);
    if (cityA > 0) fade(cityA, () => {
      glow(cx, cy + cs, cs * 4, P.act, 0.35);
      const P0 = pt(-0.35, -0.35, 0), P1 = pt(3.35, -0.35, 0), P2 = pt(3.35, 2.35, 0), P3 = pt(-0.35, 2.35, 0), th = 8;
      const plate = rgba(P.ok, 0.2);
      A(); ctx.fillStyle = '#0F3B45'; ctx.beginPath(); ctx.moveTo(P3[0], P3[1]); ctx.lineTo(P2[0], P2[1]); ctx.lineTo(P2[0], P2[1] + th); ctx.lineTo(P3[0], P3[1] + th); ctx.closePath(); ctx.fill();
      ctx.fillStyle = '#0B2C35'; ctx.beginPath(); ctx.moveTo(P1[0], P1[1]); ctx.lineTo(P2[0], P2[1]); ctx.lineTo(P2[0], P2[1] + th); ctx.lineTo(P1[0], P1[1] + th); ctx.closePath(); ctx.fill();
      ctx.fillStyle = '#145060'; ctx.beginPath(); ctx.moveTo(P0[0], P0[1]); ctx.lineTo(P1[0], P1[1]); ctx.lineTo(P2[0], P2[1]); ctx.lineTo(P3[0], P3[1]); ctx.closePath(); ctx.fill();
      ctx.strokeStyle = plate; ctx.lineWidth = 1; ctx.stroke();
      // draw back to front
      const order = TOWERS.map((tw, i) => i).sort((a, b) => (CELLS[a][0] + CELLS[a][1]) - (CELLS[b][0] + CELLS[b][1]));
      order.forEach((i) => {
        const [id, score, col] = TOWERS[i], [gx, gy] = CELLS[i];
        const delay = (gx + gy) * 0.18, h = (12 + score * L.ts) * E.back(k(t, 1.5 + delay, 2.4 + delay));
        prism(pt, gx + 0.15, gy + 0.15, 0.7, h, col, 1, col === P.crit || col === P.high ? 0.8 : 0);
      });
      // label the tallest
      const top = pt(0.5, 0.5, (12 + 19 * L.ts) * E.back(k(t, 1.5, 2.4)));
      const la = k(t, 2.6, 3.0);
      const by = WIDE ? pt(1.5, 2.6, 0)[1] + 22 : pt(3.35, 2.35, 0)[1] + 20;
      T(WIDE ? 'Tallest: x/crypto, 1 critical + 1 high + 1 moderate' : 'Tallest: x/crypto', cx, by, { size: 11.5, w: 600, c: P.crit, al: 'center', a: la });
      T('16 clean packages form the base', cx, by + (WIDE ? 18 : 15), { size: 11.5, c: P.ok, al: 'center', a: k(t, 3.0, 3.4) });
    });
    // the fix for x/crypto
    const [fx, fy, fw, fh] = L.fix;
    rise(k(t, 3.6, 4.1), () => {
      const top = card(fx, fy, fw, fh, { title: 'golang.org/x/crypto v0.14.0', icon: 'gear', tag: '3 advisories', tagc: P.crit, tf: 'm', ts: 13 });
      T('Upgrade path', fx + 16, top + 20, { size: 12, w: 600, c: P.muted });
      const stops = [['v0.14.0', 'Installed', P.crit], ['v0.17.0', 'Closes 1, 2 left', P.crit], ['v0.31.0', 'Closes 1, 1 left', P.high], ['v0.35.0', 'Clears all 3', P.ok]];
      const sx0 = fx + 28, step = (fw - 56 - (WIDE ? 120 : 64)) / 3, sy = top + 58;
      stops.forEach(([v, n, c], i) => {
        const x = sx0 + i * step, p = k(t, 4.2 + i * 0.55, 4.6 + i * 0.55);
        if (i < 3) {
          const lp = E.io(k(t, 4.4 + i * 0.55, 4.9 + i * 0.55));
          const g = ctx.createLinearGradient(x, sy, x + step, sy); g.addColorStop(0, c); g.addColorStop(1, stops[i + 1][2]);
          if (lp > 0) { A(); ctx.strokeStyle = g; ctx.lineWidth = 2.5; ctx.beginPath(); ctx.moveTo(x + 8, sy); ctx.lineTo(x + 8 + (step - 16) * lp, sy); ctx.stroke(); }
        }
        pop(p, x, sy, () => { if (i === 3) { glow(x, sy, 22, P.ok, 0.6); dot(x, sy, 8, P.ok); } else { dot(x, sy, 7, P.panel); ring(x, sy, 6, c, 1, 3); } });
        T(v, x - 6, sy + 24, { size: 12.5, f: 'm', w: 600, a: p });
        T(n, x - 6, sy + 42, { size: 11, c: P.muted, a: p });
        if (i === 3) pill(x - 6, sy + 64, 'Recommended', { h: 20, size: 10.5, c: P.ok, a: k(t, 6.0, 6.3), f: 's', w: 600 });
      });
      // the command
      const cmd = 'go get golang.org/x/crypto@v0.35.0', cy0 = fy + fh - 34;
      const bw = 70, bx = fx + fw - 16 - bw;
      fade(k(t, 6.3, 6.7), () => {
        box(fx + 16, cy0 - 17, fw - 32, 34, { r: 9, fill: P.bg0, stroke: P.line });
        T('$ ' + cmd, fx + 28, cy0 + 0.5, { size: WIDE ? 12.5 : 11.5, f: 'm', c: P.text, max: fw - 32 - bw - 26 });
        const pressed = t > 7.65 && t < 7.9;
        box(bx - 4, cy0 - 13, bw, 26, { r: 7, fill: pressed ? P.act : rgba(P.act, 0.2), stroke: rgba(P.act2, 0.5) });
        T(t > 7.8 && t < 9.8 ? 'Copied' : 'Copy', bx - 4 + bw / 2, cy0 + 0.5, { size: 12, w: 600, c: pressed ? '#fff' : P.act2, al: 'center' });
        ripple(bx - 4 + bw / 2, cy0, k(t, 7.7, 8.3), P.act2, 36);
      });
      // pointer
      if (t > 6.6 && t < 9.4) {
        const p = E.io(k(t, 6.7, 7.6)), from = [fx + fw * 0.4, fy + fh + 30], to = [bx + bw / 2 - 2, cy0 + 4];
        pointer(mix(from[0], to[0], p), mix(from[1], to[1], p), t > 7.65 && t < 7.9 ? 1 : 0, 1 - k(t, 9.0, 9.4));
      }
    });
    // every fix
    if (L.all) {
      const [ax, ay, aw, ah] = L.all;
      rise(k(t, 9.4, 9.9), () => {
        const top = card(ax, ay, aw, ah, { title: 'Every fix', icon: 'shield', tag: '5 changes' });
        const rows = [['x/crypto', 'v0.35.0', P.crit], ['jwt/v4', 'v4.5.2', P.high], ['x/net', 'v0.17.0', P.high], ['axios', '0.28.0', P.high], ['ffmpeg-static', 'replace', P.crit]];
        rows.forEach(([n, v, c], i) => {
          const y = top + 22 + i * 30, p = k(t, 9.7 + i * 0.2, 10.1 + i * 0.2);
          rise(p, () => {
            box(ax + 14, y - 7, 3, 14, { r: 1.5, fill: c });
            T(n, ax + 24, y + 0.5, { size: 12.5, f: 'm', w: 500 });
            T(v, ax + aw - 16, y + 0.5, { size: 12.5, f: 'm', w: 600, c: v === 'replace' ? P.crit : P.ok, al: 'right' });
          }, 6);
        });
        const p = k(t, 11.0, 11.5);
        fade(p, () => {
          T('axios 0.28.0 also lifts', ax + 16, top + 22 + 5 * 30 + 4, { size: 11.5, c: P.muted });
          T('follow-redirects past 1.14.7', ax + 16, top + 22 + 5 * 30 + 21, { size: 11.5, c: P.muted });
        });
      });
    } else if (t > 9.4) {
      T('+ 4 more fixes clear the build', 240, 696, { size: 12.5, c: P.muted, al: 'center', a: k(t, 9.4, 9.8) });
    }
  }

  /* ======================= 9. seal the report ======================= */
  const hexOf = (s, n) => Array.from(new TextEncoder().encode(s).slice(0, n), (b) => b.toString(16).padStart(2, '0'));
  const BYTES = hexOf(REPORT_FAIL.join('\n'), 64);
  function sc9(t) {
    const L = WIDE
      ? { doc: [24, 20, 470, 520], lines: [0, REPORT_FAIL.length], lh: 18.2, fs: 11, mach: [548, 92, 388, 206], dig: [548, 330], files: [548, 410], term: [548, 410, 388, 112] }
      : { doc: [16, 16, 448, 318], lines: [4, 15], lh: 19, fs: 11, mach: [16, 350, 448, 150], dig: [16, 516], files: [16, 590], term: [16, 614, 448, 90] };
    const [dx, dy, dw, dh] = L.doc;
    const edited = k(t, 9.5, 10.0);
    // the document
    rise(k(t, 0, 0.5), () => {
      const top = card(dx, dy, dw, dh, { title: 'report.cdx.json', icon: 'doc', tag: 'CycloneDX 1.5' });
      const [l0, l1] = L.lines;
      for (let i = l0; i < l1; i++) {
        const y = top + 14 + (i - l0) * L.lh, at = 0.3 + (i - l0) * (WIDE ? 0.13 : 0.2);
        if (t < at) break;
        let s = REPORT_FAIL[i];
        const tp = k(t, at, at + 0.25);
        if (i === 9 && t > 9.5) s = typed(s.replace('"fail"', '"pass"'), 1);
        ctx.save(); rr(dx + 1, y - L.lh / 2, dw - 2, L.lh, 0); ctx.clip();
        if (i === 9 && t > 9.0) {
          const sel = k(t, 9.0, 9.4), x0 = dx + 14 + TW(REPORT_FAIL[i].slice(0, REPORT_FAIL[i].indexOf('"fail"')), { size: L.fs, f: 'm' });
          box(x0 - 2, y - L.lh / 2 + 2, TW('"fail"', { size: L.fs, f: 'm' }) * sel + 4, L.lh - 4, { r: 3, fill: rgba(edited > 0 ? P.crit : P.act, 0.35) });
        }
        codeLine(typed(s, tp), dx + 14, y, { size: L.fs, str: i === 9 && t > 9.5 ? P.crit : P.ok });
        ctx.restore();
      }
      if (t > 9.5) {
        const y = top + 14 + (9 - L.lines[0]) * L.lh;
        pill(dx + dw - 12, y, 'edited', { al: 'right', h: 20, size: 10.5, c: P.crit, fill: rgba(P.bg0, 0.94), stroke: rgba(P.crit, 0.6), a: k(t, 9.6, 9.9) });
      }
    });
    // what makes it deterministic
    if (WIDE && t > 2.0 && t < 5.2) {
      const a = k(t, 2.0, 2.4) * (1 - k(t, 4.7, 5.1));
      const notes = [[5, 'UTC, to the second', 2.0], [6, 'a name, never a local path', 2.5], [17, 'sorted by purl', 3.0], [21, 'sorted by advisory ID', 3.5]];
      notes.forEach(([li, s, at]) => {
        const y = dy + 44 + 14 + li * L.lh, p = k(t, at, at + 0.3) * a;
        line(dx + dw - 6, y, dx + dw + 16, y, { c: P.act2, a: p, lw: 1.2 });
        pill(dx + dw + 18, y, s, { h: 22, size: 11, c: P.act2, fill: rgba(P.bg0, 0.94), stroke: rgba(P.act2, 0.6), a: p });
      });
    }
    // the hash machine
    const [mx, my, mw, mh] = L.mach;
    const run1 = k(t, 5.1, 6.6), run2 = k(t, 10.2, 11.2);
    rise(k(t, 4.8, 5.2), () => {
      const busy = (run1 > 0 && run1 < 1) || (run2 > 0 && run2 < 1);
      const top = card(mx, my, mw, mh, { title: 'SHA-256', icon: 'hash', tag: busy ? 'computing' : '64 rounds per block', glow: P.act, ga: busy ? 0.8 : 0 });
      const round = run2 > 0 ? Math.min(63, Math.floor(run2 * 64)) : Math.min(63, Math.floor(run1 * 64));
      const regs = TRACE[round] || TRACE[63];
      const names = 'abcdefgh';
      const cols = 4, cw = (mw - 32) / cols, rowH = WIDE ? 44 : 34;
      for (let i = 0; i < 8; i++) {
        const x = mx + 16 + (i % cols) * cw, y = top + 16 + Math.floor(i / cols) * rowH;
        box(x, y, cw - 8, rowH - 8, { r: 7, fill: P.bg0, stroke: busy ? rgba(P.act2, 0.4) : P.line });
        T(names[i], x + 8, y + (rowH - 8) / 2, { size: 10.5, f: 'm', c: P.faint });
        let word = regs[i].toString(16).padStart(8, '0');
        if (busy) { const r2 = seeded(round * 8 + i + Math.floor(t * 20)); word = word.split('').map((ch, j) => (r2() < 0.15 ? '0123456789abcdef'[(r2() * 16) | 0] : ch)).join(''); }
        T(word, x + 20, y + (rowH - 8) / 2, { size: WIDE ? 12.5 : 11.5, f: 'm', w: 500, c: busy ? P.act2 : P.text });
      }
      const by = top + 16 + 2 * rowH + 4;
      box(mx + 16, by, mw - 32, 6, { r: 3, fill: P.line });
      const pr = run2 > 0 ? run2 : run1;
      box(mx + 16, by, (mw - 32) * pr, 6, { r: 3, fill: P.act, glow: P.act, gb: 10, ga: 0.6 });
      if (WIDE) T('round ' + (round + 1) + ' of 64, first block', mx + mw - 16, by + 22, { size: 11, f: 'm', c: P.faint, al: 'right', a: pr > 0 ? 1 : 0 });
    });
    // bytes stream into the machine
    const streamA = (run1 > 0 && run1 < 1) ? 1 : (run2 > 0 && run2 < 1) ? 1 : 0;
    if (streamA) {
      const from = WIDE ? [dx + dw, dy + 200] : [dx + dw / 2, dy + dh], to = WIDE ? [mx, my + mh / 2] : [mx + mw / 2, my];
      for (let i = 0; i < 9; i++) {
        const ph = ((t * 1.6) + i / 9) % 1, q = [mix(from[0], to[0], ph), mix(from[1], to[1], ph) + (WIDE ? Math.sin(ph * Math.PI) * -30 : 0)];
        T(BYTES[(i + Math.floor(t * 12)) % BYTES.length], q[0], q[1], { size: 11, f: 'm', w: 600, c: P.act2, al: 'center', a: Math.sin(ph * Math.PI) });
      }
    }
    // digests
    const [gx, gy] = L.dig;
    const showDigest = (hex, y, p, diff) => {
      const per = WIDE ? 32 : 32, size = WIDE ? 13 : 12;
      const s = typed(hex, p);
      for (let row = 0; row < 2; row++) {
        const chunk = s.slice(row * per, row * per + per);
        if (!diff) { T(chunk, gx + 64, y + row * 20, { size, f: 'm', w: 500, c: P.text }); continue; }
        let x = gx + 64;
        for (let j = 0; j < chunk.length; j++) {
          const ch = chunk[j], d = DIFF[row * per + j];
          T(ch, x, y + row * 20, { size, f: 'm', w: d ? 600 : 400, c: d ? P.crit : P.faint });
          x += TW(ch, { size, f: 'm' });
        }
      }
    };
    if (t > 6.5) {
      fade(k(t, 6.5, 6.8), () => {
        T('sha256:', gx, gy, { size: 12, f: 'm', c: P.act2 });
        showDigest(DIGEST, gy, k(t, 6.6, 7.8), false);
        if (t > 11.1) {
          T('edited:', gx, gy + 48, { size: 12, f: 'm', c: P.crit, a: k(t, 11.1, 11.3) });
          showDigest(DIGEST2, gy + 48, k(t, 11.2, 12.0), true);
          if (WIDE) T(DIFFN + ' of 64 characters changed', gx + 64, gy + 90, { size: 11.5, c: P.muted, a: k(t, 12.0, 12.3) });
        }
      });
    }
    // files written, then the check fails
    const [fx, fy] = L.files;
    const filesA = k(t, 7.9, 8.4) * (1 - k(t, 11.8, 12.1));
    if (filesA > 0 && !(t > 11.1 && !WIDE)) rise(filesA, () => {
      [['report.cdx.json', 'doc'], ['report.cdx.json.sha256', 'hash']].forEach(([n, ic], i) => {
        const x = fx + i * (WIDE ? 190 : 220), w = WIDE ? 180 : 210;
        box(x, fy, w, 40, { r: 10, fill: P.panel, stroke: P.line });
        icon(ic, x + 20, fy + 20, 16, P.act2);
        T(n, x + 36, fy + 20.5, { size: 11.5, f: 'm', max: w - 46 });
      });
      if (WIDE) T(DIGEST.slice(0, 24) + '…  report.cdx.json', fx, fy + 62, { size: 11.5, f: 'm', c: P.faint });
    }, 6);
    if (t > 12.1) {
      const [tx, ty, tw, th] = L.term;
      rise(k(t, 12.1, 12.5), () => {
        box(tx, ty, tw, th, { r: 12, fill: '#04071A', stroke: P.line });
        T('$ sha256sum -c report.cdx.json.sha256', tx + 14, ty + (WIDE ? 24 : 20), { size: WIDE ? 12.5 : 11.5, f: 'm', c: P.muted, max: tw - 28 });
        T('report.cdx.json: FAILED', tx + 14, ty + (WIDE ? 52 : 44), { size: WIDE ? 15 : 13.5, f: 'm', w: 600, c: P.crit, a: k(t, 12.5, 12.7) });
        T('sha256sum: WARNING: 1 computed checksum did NOT match', tx + 14, ty + (WIDE ? 80 : 68), { size: WIDE ? 11 : 10, f: 'm', c: P.faint, a: k(t, 12.7, 12.9), max: tw - 28 });
        ripple(tx + 30, ty + (WIDE ? 52 : 44), k(t, 12.5, 13.2), P.crit, 40);
      }, 6);
    }
  }

  /* ======================= 10. anchor the fingerprint (planned) ======================= */
  function sc10(t) {
    const L = WIDE
      ? { chip: [24, 46], chain: [150, 108, 80, 132], rcpt: [24, 300, 452, 236], ver: [494, 300, 442, 236], news: [330, 14, 420, 72] }
      : { chip: [16, 36], chain: [92, 90, 64, 104], rcpt: [16, 214, 448, 214], ver: [16, 442, 448, 168], news: [16, 624, 448, 80] };
    const [cx, cy] = L.chip;
    rise(k(t, 0, 0.5), () => {
      T('Report fingerprint', cx, cy - 22, { size: 12, w: 600, c: P.muted });
      pill(cx, cy + 4, 'sha256:' + DIGEST.slice(0, WIDE ? 24 : 18) + '…', { h: 32, size: 13, c: P.act2, fill: P.panel3, stroke: rgba(P.act2, 0.6), glow: P.act, gb: 16 });
    });
    // the ledger
    const [by0, bh, bw, step] = L.chain;
    const shift = t * 12, newest = WIDE ? 6 : 4;
    const seal = k(t, 3.3, 3.8);
    for (let i = 0; i < (WIDE ? 9 : 6); i++) {
      const x = (WIDE ? 24 : 16) + i * step - shift % step - (Math.floor(shift / step) > 0 ? 0 : 0);
      const slot = 312450110 + i + Math.floor(shift / step);
      const isNew = i === newest - Math.floor(shift / step);
      const a = k(t, 0.3 + i * 0.06, 0.7 + i * 0.06) * c01((x + bw) / 40) * c01(((WIDE ? 960 : 480) - x) / 40);
      if (a <= 0) continue;
      fade(a, () => {
        box(x, by0, bw, bh, { r: 10, fill: isNew && seal > 0 ? rgba(P.act, 0.22) : P.panel, stroke: isNew && seal > 0 ? P.act2 : P.line, glow: isNew ? P.act : null, gb: 22, ga: isNew ? seal * 0.8 : 0 });
        T('slot', x + 10, by0 + 16, { size: 10, c: P.faint });
        T(String(slot), x + 10, by0 + 32, { size: WIDE ? 11.5 : 10, f: 'm', w: 500, c: P.muted });
        for (let j = 0; j < 3; j++) box(x + 10, by0 + 48 + j * 9, bw - 20 - j * 10, 4, { r: 2, fill: P.line2, a: 0.7 });
        if (isNew && seal > 0) { icon('lock', x + bw - 18, by0 + 18, 14, P.act2, seal); }
        if (i > 0) line(x - (step - bw) + 2, by0 + bh / 2, x - 2, by0 + bh / 2, { c: P.line2, lw: 2 });
      });
    }
    // the transaction carrying the memo
    const txp = E.io(k(t, 1.6, 3.3));
    if (txp > 0 && t < 3.6) {
      const nx = (WIDE ? 24 : 16) + (newest - Math.floor(shift / step)) * step - shift % step + bw / 2;
      const from = [cx + 120, cy + 4], to = [nx, by0 + bh / 2], c = [mix(from[0], to[0], 0.6), cy - 10];
      const q = qpt(from, c, to, txp), s = 1 - 0.55 * k(txp, 0.7, 1);
      ctx.save(); ctx.translate(q[0], q[1]); ctx.scale(s, s);
      box(-104, -24, 208, 48, { r: 10, fill: P.panel3, stroke: P.act2, glow: P.act, gb: 18, ga: 0.7 });
      T('Memo transaction', -92, -9, { size: 11, w: 600, c: P.act2 });
      T('depscan sha256:' + DIGEST.slice(0, 8) + '…', -92, 10, { size: 11, f: 'm', c: P.text });
      ctx.restore();
    }
    if (t > 3.8) {
      const nx = (WIDE ? 24 : 16) + (newest - Math.floor(shift / step)) * step - shift % step + bw / 2;
      badge(nx, by0 + bh + 18, 9, P.ok, 'ok', k(t, 3.8, 4.2));
      T('confirmed', nx + 16, by0 + bh + 18.5, { size: 11.5, w: 600, c: P.ok, a: k(t, 3.9, 4.3) });
    }
    // receipt
    const [rx, ry, rw, rh] = L.rcpt;
    rise(k(t, 4.4, 4.9), () => {
      const top = card(rx, ry, rw, rh, { title: 'report.cdx.json.anchor.json', icon: 'doc', tag: 'receipt' });
      const lines = ['{', '  "digest": "sha256:' + DIGEST.slice(0, 12) + '…",', '  "backend": "solana",', '  "network": "devnet",', '  "tx_id": "' + TXID.slice(0, 14) + '…",', '  "url": "https://explorer.solana.com/tx/' + TXID.slice(0, 6) + '…",', '  "anchored_at": "2026-10-10T04:00:21Z"', '}'];
      lines.forEach((s, i) => {
        const at = 4.7 + i * 0.12;
        if (t < at) return;
        ctx.save(); rr(rx + 1, top, rw - 2, rh - 46, 0); ctx.clip();
        codeLine(typed(s, k(t, at, at + 0.2)), rx + 14, top + 14 + i * (WIDE ? 21 : 19), { size: WIDE ? 11.5 : 11 });
        ctx.restore();
      });
    });
    // verify, weeks later
    const [vx, vy, vw, vh] = L.ver;
    rise(k(t, 5.9, 6.4), () => {
      const top = card(vx, vy, vw, vh, { title: 'depscan verify', icon: 'shield', tag: 'weeks later' });
      const day = Math.round(mix(10, 52, E.io(k(t, 6.2, 7.0))));
      const date = day <= 31 ? 'Oct ' + day : 'Nov ' + (day - 31);
      pill(vx + vw - 16, top + 18, date + ', 2026', { al: 'right', h: 22, size: 11, c: P.muted, f: 's', w: 600 });
      const steps = [['re-hash report.cdx.json', 7.0], ['read the memo from the transaction', 7.5], ['compare the two', 8.0]];
      steps.forEach(([s, at], i) => {
        const y = top + (WIDE ? 20 : 16) + i * (WIDE ? 28 : 24);
        if (t > at) badge(vx + 24, y, 8, P.ok, 'ok', k(t, at, at + 0.3)); else if (t > at - 0.5) spinner(vx + 24, y, 6, t, P.act2);
        else ring(vx + 24, y, 7, P.line2, 1, 1.5);
        T(s, vx + 40, y + 0.5, { size: 12.5, c: t > at ? P.text : P.muted, max: vw - 56 });
      });
      if (t > 8.4) {
        const y = top + (WIDE ? 20 : 16) + 3 * (WIDE ? 28 : 24) + 8, p = k(t, 8.4, 8.8);
        box(vx + 14, y - 16, vw - 28, 32, { r: 9, fill: rgba(P.ok, 0.12 * p), stroke: rgba(P.ok, 0.5 * p) });
        T(WIDE ? 'Match: unchanged since 2026-10-10 04:00 UTC' : 'Match: unchanged since Oct 10', vx + 26, y + 0.5, { size: 12.5, w: 600, c: P.ok, a: p });
      }
    });
    // and yet: new advisories keep coming
    if (t > 9.4) {
      const [nx, ny, nw, nh] = L.news, p = k(t, 9.4, 9.9);
      rise(p, () => {
        box(nx, ny, nw, nh, { r: 12, fill: rgba(P.med, 0.1), stroke: rgba(P.med, 0.5), shadow: 'rgba(0,0,0,.4)', blur: 18, oy: 8 });
        pill(nx + 14, ny + 22, 'New', { h: 20, size: 10.5, c: P.med, f: 's', w: 700 });
        T('advisory published Nov 3 for a package you ship', nx + 62, ny + 22.5, { size: 12, w: 600, c: P.text, max: nw - 76 });
        T('Still a match: the report is genuine, but out of date.', nx + 14, ny + 48, { size: 12, c: P.muted, max: nw - 28 });
        if (!WIDE) T('Scan again for a current answer.', nx + 14, ny + 66, { size: 12, c: P.muted });
      }, 10);
    }
  }

  /* ======================= 11. check every pull request ======================= */
  const PRSTEPS = [
    ['Verify the signature', 'HMAC-SHA256', 2.6, 3.6],
    ['Answer 202 Accepted', 'in milliseconds', 3.6, 4.2],
    ['Queue the job', '2 workers', 4.2, 5.3],
    ['Fetch lockfiles at 9c1e2f7', '2 of 214 files', 5.3, 7.3],
    ['Scan', 'parse, licenses, OSV, policy', 7.3, 9.0],
    ['Post status and comment', 'planned', 9.0, 10.3]
  ];
  function sc11(t) {
    const L = WIDE
      ? { pr: [24, 24, 430, 516], srv: [482, 24, 454, 300], grid: [482, 340, 454, 200] }
      : { pr: [16, 16, 448, 352], srv: [16, 384, 448, 320], grid: null };
    const [px, py, pw, ph] = L.pr;
    // pull request
    rise(k(t, 0, 0.5), () => {
      box(px, py, pw, ph, { r: 16, fill: P.panel, stroke: P.line, shadow: 'rgba(0,0,0,.45)', blur: 30, oy: 12 });
      icon('branch', px + 26, py + 28, 18, P.ok);
      T('#42', px + 44, py + 28.5, { size: 15, w: 700, f: 'd', c: P.muted });
      T('Upgrade x/crypto, jwt, x/net, axios', px + 78, py + 28.5, { size: 15, w: 700, f: 'd', max: pw - 96 });
      T('feature/fix-deps into main', px + 44, py + 52, { size: 11.5, f: 'm', c: P.faint });
      // diff
      const dTop = py + 72, diff = WIDE
        ? [['go.mod', 'h'], ['-\tgolang.org/x/crypto v0.14.0', '-'], ['+\tgolang.org/x/crypto v0.35.0', '+'], ['web/package.json', 'h'], ['-    "axios": "^0.21.1",', '-'], ['+    "axios": "^0.28.0",', '+'], ['  + 2 more changed lines', 'm']]
        : [['go.mod', 'h'], ['- golang.org/x/crypto v0.14.0', '-'], ['+ golang.org/x/crypto v0.35.0', '+'], ['  + 3 more changed lines', 'm']];
      box(px + 14, dTop, pw - 28, diff.length * 21 + 12, { r: 10, fill: P.bg0, stroke: P.line });
      diff.forEach(([s, kd], i) => {
        const y = dTop + 16 + i * 21;
        if (kd === '+' || kd === '-') box(px + 15, y - 10, pw - 30, 20, { r: 0, fill: rgba(kd === '+' ? P.ok : P.crit, 0.12) });
        T(s.replace('\t', ' '), px + 24, y + 0.5, { size: 11.5, f: 'm', c: kd === 'h' ? P.faint : kd === '+' ? P.ok : kd === '-' ? P.crit : P.muted, w: kd === 'h' ? 600 : 400, max: pw - 48 });
      });
      // checks
      const cTop = dTop + diff.length * 21 + 26;
      T('Checks', px + 16, cTop, { size: 12, w: 600, c: P.muted });
      const res = k(t, 9.9, 10.3);
      const ry = cTop + 26;
      box(px + 14, ry - 17, pw - 28, 34, { r: 9, fill: res > 0 ? rgba(P.crit, 0.1 * res) : rgba(P.panel2, 0.6), stroke: res > 0 ? rgba(P.crit, 0.5 * res) : P.line });
      if (res > 0) badge(px + 32, ry, 9, P.crit, 'no', res);
      else if (t > 4.2) spinner(px + 32, ry, 7, t, P.med); else ring(px + 32, ry, 7, P.line2, 1, 1.5);
      T('depscan', px + 48, ry + 0.5, { size: 12.5, w: 600 });
      T(res > 0 ? '1 package blocks this merge' : t > 4.2 ? 'scanning the head commit…' : 'waiting for status', px + 112, ry + 0.5, { size: 12, c: res > 0 ? P.crit : P.muted, max: pw - 140 });
      // comment
      if (t > 10.2) {
        const p = k(t, 10.2, 10.7), y0 = ry + 30;
        rise(p, () => {
          const ch = WIDE ? 128 : 92;
          box(px + 14, y0, pw - 28, ch, { r: 10, fill: P.panel2, stroke: P.line });
          dot(px + 34, y0 + 22, 11, P.act); T('DS', px + 34, y0 + 22.5, { size: 9.5, w: 700, c: '#fff', al: 'center' });
          T('depscan commented', px + 52, y0 + 22.5, { size: 12, w: 600 });
          const rows = WIDE ? [['ffmpeg-static', 'GPL-3.0-or-later', 'denied', P.crit], ['@shop/ui-kit', 'license unknown', 'warning', P.med]] : [['ffmpeg-static', 'GPL-3.0-or-later', 'denied', P.crit]];
          rows.forEach(([n, l, s, c], i) => {
            const y = y0 + 50 + i * 26;
            T(n, px + 28, y, { size: 11.5, f: 'm', w: 500 });
            T(l, px + (WIDE ? 160 : 150), y, { size: 11.5, f: 'm', c: P.muted });
            T(s, px + pw - 28, y, { size: 11.5, w: 600, c, al: 'right' });
          });
          if (WIDE) T('Fixed: x/crypto, jwt/v4, x/net, axios. Replace ffmpeg-static to merge.', px + 28, y0 + 108, { size: 11, c: P.faint, max: pw - 56 });
        }, 8);
        // merge button
        const my = WIDE ? py + ph - 34 : ry + 30 + 92 + 26;
        if (my + 18 < py + ph) {
          fade(k(t, 10.6, 11.0), () => {
            box(px + 14, my - 18, pw - 28, 36, { r: 10, fill: rgba(P.panel3, 0.6), stroke: P.line });
            icon('lock', px + 34, my, 14, P.faint);
            T('Merge blocked: required check failed', px + 50, my + 0.5, { size: 12.5, w: 600, c: P.muted, max: pw - 70 });
          });
        }
      }
    });
    // server and its steps
    const [sx, sy, sw, sh] = L.srv;
    rise(k(t, 0.6, 1.1), () => {
      const top = card(sx, sy, sw, sh, { title: 'DepScan server', icon: 'server', tag: 'POST /webhooks/github' });
      PRSTEPS.forEach(([s, d, a, b], i) => {
        const y = top + 24 + i * (WIDE ? 40 : 42);
        const done = t > b, now = t > a && !done;
        if (now) box(sx + 8, y - 16, sw - 16, 32, { r: 8, fill: rgba(P.act, 0.15) });
        if (done) badge(sx + 26, y, 9, i === 5 ? P.crit : P.ok, i === 5 ? '!' : 'ok', k(t, b, b + 0.3));
        else if (now) spinner(sx + 26, y, 7, t, P.act2); else ring(sx + 26, y, 8, P.line2, 1, 1.5);
        T(s, sx + 44, y + 0.5, { size: 13, w: done || now ? 600 : 400, c: done || now ? P.text : P.muted, max: sw - 200 });
        if (i === 5) pill(sx + sw - 14, y, 'Planned', { al: 'right', h: 20, size: 10.5, c: P.med, f: 's', w: 600 });
        else T(d, sx + sw - 14, y + 0.5, { size: 11.5, f: 'm', c: P.faint, al: 'right' });
        if (i === 4 && now) {
          const pr = k(t, a, b), stages = ['parse', 'licenses', 'OSV', 'policy'];
          box(sx + 44, y + 12, sw - 60, 3, { r: 2, fill: P.line });
          box(sx + 44, y + 12, (sw - 60) * pr, 3, { r: 2, fill: P.act });
          if (!WIDE) return;
          stages.forEach((st, j) => T(st, sx + 44 + (sw - 60) * (j + 0.5) / 4, y + 24, { size: 10, f: 'm', c: pr > (j + 1) / 4 ? P.ok : pr > j / 4 ? P.act2 : P.faint, al: 'center' }));
        }
      });
      // the lock closes when the signature checks out
      if (t > 2.6 && t < 4.6) {
        const y = top + 24, a = 1 - k(t, 4.2, 4.6), x = sx + sw - 120;
        icon(t > 3.3 ? 'lock' : 'unlock', x, y, 15, t > 3.3 ? P.ok : P.med, a);
      }
    });
    // the webhook delivery, the 202, and the result going back
    const prOut = WIDE ? [px + pw, py + 120] : [px + pw / 2, py + ph], srvIn = WIDE ? [sx, sy + 64] : [sx + sw / 2, sy];
    const c1 = WIDE ? [mix(prOut[0], srvIn[0], 0.5), py + 20] : [px + pw - 30, mix(prOut[1], srvIn[1], 0.5)];
    const hp = E.io(k(t, 1.2, 2.6));
    if (hp > 0 && hp < 1) {
      const q = qpt(prOut, c1, srvIn, hp);
      glow(q[0], q[1], 30, P.act, 0.7);
      const w = WIDE ? 250 : 220;
      ctx.save(); ctx.translate(q[0], q[1]);
      box(-w / 2, -34, w, 68, { r: 10, fill: P.panel3, stroke: P.act2, glow: P.act, gb: 16, ga: 0.6 });
      T('X-GitHub-Event: pull_request', -w / 2 + 12, -15, { size: 10.5, f: 'm', c: P.text, max: w - 24 });
      T('X-Hub-Signature-256:', -w / 2 + 12, 3, { size: 10.5, f: 'm', c: P.act2 });
      T('sha256=' + HOOK_SIG.slice(0, 20) + '…', -w / 2 + 12, 19, { size: 10.5, f: 'm', c: P.muted, max: w - 24 });
      ctx.restore();
    }
    const ack = E.io(k(t, 3.6, 4.2));
    if (ack > 0 && ack < 1) { const q = qpt(srvIn, [c1[0], c1[1] + (WIDE ? 120 : 0)], prOut, ack); pill(q[0], q[1], '202 Accepted', { al: 'center', h: 24, size: 11.5, c: P.ok, fill: P.panel3, stroke: P.ok }); }
    const back = E.io(k(t, 9.1, 9.95));
    if (back > 0 && back < 1) { const q = qpt(srvIn, [c1[0], c1[1] + (WIDE ? 160 : 0)], prOut, back); glow(q[0], q[1], 26, P.crit, 0.7); pill(q[0], q[1], 'status: failure', { al: 'center', h: 24, size: 11.5, c: P.crit, fill: P.panel3, stroke: P.crit }); }
    // the repository tree: only two files are downloaded
    if (L.grid && t > 5.0) {
      const [gx, gy, gw, gh] = L.grid, a = k(t, 5.0, 5.5);
      fade(a, () => {
        box(gx, gy, gw, gh, { r: 14, fill: rgba(P.panel, 0.7), stroke: P.line });
        T('Repository at 9c1e2f7: 214 files', gx + 16, gy + 24, { size: 12.5, w: 600 });
        T('Trees API', gx + gw - 16, gy + 24, { size: 11, f: 'm', c: P.faint, al: 'right' });
        const cols = 27, cell = 14, ox = gx + 18, oy = gy + 44;
        const lock = [37, 150];
        for (let i = 0; i < 214; i++) {
          const x = ox + (i % cols) * (cell + 1.5), y = oy + Math.floor(i / cols) * (cell + 1.5);
          const isLock = lock.includes(i), lit = isLock && t > 5.8 + lock.indexOf(i) * 0.4;
          const scan = k(t, 5.3 + (i / 214) * 0.6, 5.4 + (i / 214) * 0.6);
          box(x, y, cell, cell, { r: 3, fill: lit ? P.act : rgba(P.line2, 0.25 + 0.35 * scan), glow: lit ? P.act : null, gb: 12, ga: 0.8 });
        }
        const names = [['go.mod', 5.8], ['web/package-lock.json', 6.2]];
        names.forEach(([n, at], i) => {
          const p = k(t, at, at + 0.3);
          pill(gx + 16 + i * 150, gy + gh - 22, n, { h: 22, size: 11, c: P.act2, a: p, dot: true });
          const src = [ox + (lock[i] % cols) * (cell + 1.5) + 7, oy + Math.floor(lock[i] / cols) * (cell + 1.5) + 7];
          packet(src, [src[0] + 40, gy - 30], [sx + sw * 0.6, sy + sh], E.io(k(t, at + 0.1, at + 0.9)), P.act2, { r: 4 });
        });
      });
    }
  }

  /* ======================= chapters ======================= */
  const RETRY = JOBS.find((j) => j.retry);
  const r2 = (n) => Math.round(n * 10) / 10;
  const CH = [
    {
      title: 'Point it at a folder', dur: 11, scene: sc1, terms: ['lockfile', 'dependency'], file: 'internal/api/handlers.go, internal/scan/engine.go',
      p: 'You give DepScan a folder on your machine. Nothing is uploaded: the server reads the files where they are, and only inside the scan root it was started with.',
      li: ['The path is resolved with symlinks followed, then compared with the scan root, so <code>..\\</code> tricks and links that point outside are rejected.', 'The walk skips <code>.git</code>, <code>vendor</code> and <code>node_modules</code>: they hold copies, not the dependencies you declared.'],
      beats: [[0, 'You paste a folder path and press <b>Scan</b>.'], [3.1, 'The page sends <code>POST /scans</code> with the path to the DepScan server on your machine.'], [4.3, 'The server only reads inside its scan root, so the path is checked first.'], [5.4, 'A path that climbs out with <code>..\\</code> is rejected before any file is opened.'], [7.0, 'Then it walks the folder, skipping <code>.git</code>, <code>vendor</code> and <code>node_modules</code>.'], [9.6, 'Two lockfiles found: <code>go.mod</code> and <code>package-lock.json</code>.']],
      code: [[3.1, 'POST /scans HTTP/1.1'], [3.1, 'Content-Type: application/json'], [3.2, '{"path": "C:\\\\Users\\\\you\\\\code\\\\shop-api"}'], [null, ''], [4.3, '// resolveScanPath'], [4.4, 'target, err := filepath.EvalSymlinks(candidate)'], [4.6, 'rel, err := filepath.Rel(h.scanRoot, target)'], [5.4, 'if err != nil || rel == ".." ||'], [5.6, '\tstrings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {'], [6.0, '\treturn "", errOutsideRoot // 400 Bad Request'], [null, '}'], [null, ''], [7.0, '// collect: walk the folder'], [7.2, 'if name == "vendor" || name == "node_modules" || name == ".git" {'], [7.3, '\treturn filepath.SkipDir'], [null, '}']]
    },
    {
      title: 'Read the lockfiles', dur: 13, scene: sc2, terms: ['lockfile', 'transitive', 'semver'], file: 'internal/parser/gomod.go, npm.go',
      p: 'Each lockfile becomes a flat list of packages with exact versions. DepScan never runs <code>go</code> or <code>npm</code>: it only reads the files.',
      li: ['<code>go.mod</code>: every <code>require</code> line is a module, and <code>// indirect</code> marks a transitive one.', '<code>package-lock.json</code> (npm 7 or newer): every <code>node_modules/…</code> entry is a package, and the root entry <code>""</code> says which ones you asked for.', 'A <code>replace</code> directive is applied, so the version scanned is the version that builds.'],
      beats: [[0, 'DepScan parses every lockfile it found.'], [0.8, '<code>go.mod</code> lists each module and version. <code>// indirect</code> marks the ones you did not add yourself.'], [5.0, '<code>package-lock.json</code> records the whole installed tree. Its root entry lists what you asked for.'], [10.0, '22 packages: 6 you chose, 16 that came along.']],
      code: [[0.6, '// gomod.go'], [0.9, 'for _, req := range f.Require {'], [1.0, '\tmod, ok := applyReplace(f.Replace, req.Mod.Path, req.Mod.Version)'], [1.1, '\tdeps = append(deps, model.Dependency{'], [1.2, '\t\tEcosystem: "Go", Name: mod.path,'], [1.3, '\t\tVersion: strings.TrimPrefix(mod.version, "v"), // OSV wants 1.9.0'], [2.5, '\t\tDirect:  !req.Indirect,'], [null, '\t})'], [null, '}'], [5.0, '// npm.go'], [5.2, 'root := lock.Packages[""]'], [5.4, 'for name := range root.Dependencies { direct[name] = true }'], [6.5, 'isTopLevel := path == "node_modules/"+name'], [6.7, 'Direct: isTopLevel && direct[name],']]
    },
    {
      title: 'Direct and transitive', dur: 11, scene: sc3, terms: ['transitive', 'dependency'], file: 'internal/model/types.go',
      p: 'Six packages are ones you chose. The other sixteen came along because your choices depend on them, and you ship all twenty-two.',
      li: ['DepScan reads direct or transitive straight from the lockfile. The graph shows where the transitive ones come from.', 'Go builds one version of each module, so a package needed by three others is still one entry.', 'With <code>check_transitive: true</code>, every one of them is held to your policy.'],
      beats: [[0, 'Every package traces back to something you depend on.'], [2.2, 'Your 6 direct dependencies pull in 16 more. You never picked these, but you ship them.'], [6.8, 'Shared packages appear once: Go builds a single version of each module.'], [8.6, '16 of 22 are transitive. Flaws often arrive this way, so <code>check_transitive: true</code> covers them.']],
      code: [[0, 'type Dependency struct {'], [0.4, '\tEcosystem string // "Go" or "npm"'], [0.6, '\tName      string'], [0.8, '\tVersion   string // exact, from the lockfile'], [2.2, '\tDirect    bool   // false: transitive'], [6.0, '\tLicense   string // filled in by the next step'], [null, '}'], [null, ''], [8.6, '// policy.yaml'], [8.7, 'check_transitive: true']]
    },
    {
      title: 'Look up licenses', dur: 11, scene: sc4, terms: ['license', 'spdx', 'copyleft'], file: 'internal/license/client.go, evaluator.go',
      p: 'Each package\'s license comes from deps.dev, Google\'s open source package index. Your policy then decides which licenses you can ship.',
      li: ['Up to 8 lookups run at once. A failed lookup leaves that license unknown; it never fails the whole scan.', 'Licenses are SPDX identifiers, so <code>GPL-3.0-or-later</code> means exactly one thing.', 'A package deps.dev does not know, like a private one, gets an unknown license. That warns, or blocks with <code>block_unknown_license: true</code>.'],
      beats: [[0, 'Next, every package\'s license is looked up on deps.dev.'], [1.2, 'Up to 8 lookups run at once. A <code>/</code> in a module path is sent as <code>%2F</code>.'], [4.0, 'Permissive licenses like MIT, BSD-3-Clause and Apache-2.0 pass.'], [7.2, '<code>ffmpeg-static</code> is GPL-3.0-or-later, which your policy denies.'], [8.4, '<code>@shop/ui-kit</code> is private, so deps.dev has no record. An unknown license warns.']],
      code: [[1.3, 'GET https://api.deps.dev/v3/systems/GO/packages/'], [1.3, '    golang.org%2Fx%2Fcrypto/versions/v0.14.0'], [2.4, '200 OK  {"licenses": ["BSD-3-Clause"], …}'], [null, ''], [7.0, '// evaluator.go'], [7.2, 'Check("GPL-3.0-or-later", deny, true)'], [7.4, '// → false, "license denied by policy: GPL-3.0-or-later"'], [8.4, 'license.Unknown("") // true: not on deps.dev'], [8.6, '// block_unknown_license: false → a warning']]
    },
    {
      title: 'Ask OSV.dev', dur: 16, scene: sc5, terms: ['osv', 'advisory', 'vulnerability'], file: 'internal/osv/client.go, worker.go, internal/httpx',
      p: 'OSV.dev gathers advisories from GitHub, the Go team and other databases. DepScan asks about every package in one batch, then fetches the details of each match.',
      li: ['One <code>querybatch</code> request covers up to 100 packages and returns only advisory IDs.', '8 workers fetch each advisory\'s severity and fixed version in parallel.', 'Connection errors, 429 and 5xx responses are retried after 500 ms and 1 s. If a request still fails, the scan fails instead of passing on missing data.'],
      beats: [[0, 'All 22 packages go to OSV.dev in one batch request.'], [2.4, 'OSV.dev gathers advisories from GitHub, the Go team, PyPI, RustSec and more.'], [3.8, 'The answer lists matching IDs per package: 6 packages have 15 records between them.'], [5.6, 'Details come from <code>GET /v1/vulns/{id}</code>, fetched by 8 workers at once.'], [r2(RETRY.att[0][1] - 0.4), 'A <code>503</code> is retried after 500 ms. Other 4xx errors are not retried.'], [r2(JOBS_DONE + 0.3), 'If a request still fails after 3 tries, the scan stops rather than report a false pass.']],
      code: [[0.3, 'POST https://api.osv.dev/v1/querybatch'], [0.4, '{"queries": ['], [0.6, '  {"package": {"name": "golang.org/x/crypto", "ecosystem": "Go"},'], [0.7, '   "version": "0.14.0"},'], [2.0, '  … 21 more'], [null, ']}'], [4.6, '200 OK  {"results": [{"vulns": [{"id": "GHSA-v778-237x-gjrc"}, …]}, …]}'], [null, ''], [5.8, 'GET https://api.osv.dev/v1/vulns/GHSA-v778-237x-gjrc'], [5.9, '200 OK  {"database_specific": {"severity": "CRITICAL"}, …}'], [r2(RETRY.att[0][0]), 'GET https://api.osv.dev/v1/vulns/GO-2025-3553'], [r2((RETRY.att[0][0] + RETRY.att[0][1]) / 2), '503 Service Unavailable  // retry in 500 ms'], [r2(RETRY.att[1][1]), '200 OK']]
    },
    {
      title: 'Merge duplicates', dur: 12, scene: sc6, terms: ['duplicates', 'advisory', 'severity'], file: 'internal/osv/dedupe.go',
      p: 'The same flaw often comes back under two or three IDs. DepScan merges records that share an alias, so every number counts real problems.',
      li: ['Records are merged only within the same package version.', 'The kept record is the one with a severity, then the GHSA one. Without this, the GO- copy of a HIGH flaw would show up as unrated.', 'Every other ID becomes an alias, so an exception written against any of them still matches.'],
      beats: [[0, 'The same flaw is often published under several IDs.'], [1.0, 'GitHub (GHSA), the Go team (GO-) and the CVE list each number it, and each record lists the others as aliases.'], [3.8, 'DepScan joins records that share an alias and keeps one.'], [6.8, 'It keeps the record that has a severity, preferring GHSA. The GO- record has none.'], [9.4, '15 records become 9 real advisories, each counted once.']],
      code: [[1.0, 'for _, id := range append([]string{f.VulnID}, f.Aliases...) {'], [1.1, '\tkey := pkg + "|" + strings.ToUpper(id)'], [1.2, '\tif j, ok := owner[key]; ok { parent[find(i)] = find(j) } // union'], [null, '}'], [3.8, 'best := members[0]'], [3.9, 'for _, m := range members[1:] {'], [4.0, '\tif better(findings[m], findings[best]) { best = m }'], [null, '}'], [4.2, 'out = append(out, merge(findings[best], members, findings))'], [null, ''], [6.8, 'func better(a, b model.Finding) bool {'], [7.0, '\tif ka, kb := knownSeverity(a), knownSeverity(b); ka != kb {'], [7.2, '\t\treturn ka // a record with a severity wins'], [null, '\t}'], [8.4, '\tif ga, gb := strings.HasPrefix(a.VulnID, "GHSA-"), strings.HasPrefix(b.VulnID, "GHSA-"); ga != gb {'], [8.6, '\t\treturn ga // then GHSA'], [null, '\t}'], [null, '\treturn a.VulnID < b.VulnID'], [null, '}']]
    },
    {
      title: 'Apply your policy', dur: 15, scene: sc7, terms: ['policy', 'exception', 'severity'], file: 'internal/policy/evaluate.go',
      p: 'Your <code>policy.yaml</code> turns findings into a verdict: blocks, warns or allowed. The same file applies on a laptop and in CI.',
      li: ['CRITICAL and HIGH block. Transitive packages count, because <code>check_transitive</code> is on.', 'An exception needs a reason and can expire, so accepted risk comes back for review.', 'Any violation makes <code>depscan</code> exit with status 1 and the API answer 422.'],
      beats: [[0, 'Now your policy decides what each finding means for the build.'], [0.8, 'CRITICAL and HIGH block. Transitive packages count too, because <code>check_transitive</code> is on.'], [6.8, 'MODERATE findings warn: visible, but they do not fail the build.'], [8.8, 'An exception needs a reason and can expire. Until 2026-12-31, this gin advisory is allowed.'], [9.8, 'Licenses go through the same gate: GPL-3.0-or-later is denied, an unknown license warns.'], [12.2, '7 violations. <code>depscan</code> exits with status 1, so CI fails the build.']],
      code: [[0.8, 'for _, f := range findings {'], [3.8, '\tif !p.CheckTransitive && !f.Dep.Direct {'], [null, '\t\tcontinue'], [null, '\t}'], [9.0, '\tif excepted, reason := p.IsException(f); excepted {'], [9.1, '\t\tcontinue // reason required, expiry checked'], [null, '\t}'], [0.9, '\tif p.IsBlocked(f.Severity) {'], [1.0, '\t\tviolations = append(violations, v)'], [6.9, '\t} else if p.IsWarned(f.Severity) {'], [7.0, '\t\twarnings = append(warnings, v)'], [null, '\t}'], [null, '}'], [9.9, 'license.Check(dep.License, deny, true) // GPL-3.0-or-later: denied'], [12.2, '$ depscan -path ./shop-api'], [12.4, 'exit status 1']]
    },
    {
      title: 'Read the verdict', dur: 13, scene: sc8, terms: ['fixed', 'semver'], file: 'POST /scans response',
      p: 'The dashboard shows what blocks the build, and for each package the smallest upgrade that fixes it.',
      li: ['Tower height is risk: critical counts 10, high 6, moderate 3. Clean packages form the base.', 'The recommended version is the highest fixed version among a package\'s active advisories, so one upgrade clears them all.', 'Copy the command, run it, and scan again.'],
      beats: [[0, 'The result: blocked, with the reason for every package.'], [1.2, 'Tower height is risk. <code>x/crypto</code> stands tallest: one critical, one high, one moderate.'], [4.0, 'For each package, DepScan works out the smallest upgrade that clears every active advisory.'], [6.6, 'Copy the command, run it, scan again.'], [9.4, 'Five changes clear this build. Upgrading axios also lifts follow-redirects past its fix.']],
      code: [[0.2, 'HTTP/1.1 422 Unprocessable Entity'], [0.3, '{'], [0.4, '  "path": "C:\\\\Users\\\\you\\\\code\\\\shop-api",'], [0.5, '  "result": {'], [0.8, '    "Deps":       [ 22 packages ],'], [0.9, '    "Findings":   [ 9 advisories ],'], [1.0, '    "Violations": [ 7 ],'], [1.1, '    "Warnings":   [ 3 ]'], [null, '  }'], [null, '}'], [null, ''], [4.2, '// fixed in 0.17.0, 0.31.0 and 0.35.0: the highest clears all three'], [7.8, '$ go get golang.org/x/crypto@v0.35.0']]
    },
    {
      title: 'Seal the report', dur: 15, scene: sc9, terms: ['sbom', 'sha256', 'purl'], file: 'internal/report/cyclonedx.go, hash.go',
      p: '<code>depscan -report</code> writes a CycloneDX SBOM and its SHA-256 fingerprint, so anyone can check later that the report was not changed.',
      li: ['The bytes are deterministic: sorted lists, a UTC timestamp, no absolute paths. The same scan always writes the same file.', 'The fingerprint goes in <code>report.cdx.json.sha256</code>, in the format <code>sha256sum -c</code> reads.', 'Change one word and the fingerprint changes beyond recognition: here ' + DIFFN + ' of 64 characters.'],
      beats: [[0, 'The result is written as a CycloneDX 1.5 SBOM: <code>report.cdx.json</code>.'], [2.0, 'The bytes are deterministic: sorted lists, a UTC timestamp, no local paths. Same scan, same file.'], [5.0, 'SHA-256 turns the whole file into a 64-character fingerprint. These are its real working registers.'], [7.8, 'The fingerprint is saved next to the report, in the format <code>sha256sum</code> reads.'], [9.0, 'Now someone edits one word: <code>fail</code> becomes <code>pass</code>.'], [11.2, 'The new fingerprint shares almost nothing with the old one, so the check fails.']],
      code: [[0.2, '$ depscan -path ./shop-api -report report.cdx.json'], [4.6, 'wrote report.cdx.json'], [7.8, 'sha256:' + DIGEST.slice(0, 32)], [7.8, '       ' + DIGEST.slice(32)], [8.0, 'wrote report.cdx.json.sha256'], [null, ''], [12.2, '$ sha256sum -c report.cdx.json.sha256'], [12.5, 'report.cdx.json: FAILED'], [12.7, 'sha256sum: WARNING: 1 computed checksum did NOT match']]
    },
    {
      title: 'Anchor the hash', dur: 12, scene: sc10, planned: 0, terms: ['anchoring', 'sha256'], file: 'internal/anchor (planned backend)',
      p: 'Planned: write the fingerprint into a public ledger, so not even someone who controls the server can rewrite the record.',
      li: ['The SHA-256 goes into the memo of a Solana transaction, and the ledger records when it arrived.', '<code>depscan verify</code> re-hashes the report and compares it with the memo.', 'A match proves the report is unchanged since that moment. It does not prove the project is still safe: new advisories appear every day, so scan again for a current answer.'],
      beats: [[0, 'Planned: publish the fingerprint where nobody can quietly change it.'], [1.6, 'The SHA-256 goes into a Solana transaction memo. The ledger timestamps it.'], [4.4, 'DepScan keeps a receipt: which network, which transaction, when.'], [5.9, 'Later, <code>depscan verify</code> re-hashes the report and compares it with the memo.'], [9.4, 'A match proves the report is unchanged, not that the project is still safe. Scan again for today\'s answer.']],
      code: [[0.2, '$ depscan -path ./shop-api -report report.cdx.json -anchor solana'], [4.6, '{'], [4.7, '  "digest": "sha256:' + DIGEST.slice(0, 16) + '…",'], [4.8, '  "backend": "solana", "network": "devnet",'], [4.9, '  "tx_id": "' + TXID.slice(0, 20) + '…",'], [5.0, '  "anchored_at": "2026-10-10T04:00:21Z"'], [null, '}'], [5.9, '$ depscan verify report.cdx.json'], [8.4, 'OK: matches the anchor from 2026-10-10T04:00:21Z']]
    },
    {
      title: 'Check pull requests', dur: 14, scene: sc11, planned: 9.0, terms: ['webhook', 'status'], file: 'internal/github/webhook.go, fetch.go',
      p: 'Start the server with a webhook secret and the same scan runs on every pull request, at its latest commit.',
      li: ['GitHub signs each delivery, and DepScan checks <code>X-Hub-Signature-256</code> before trusting the body.', 'It answers 202 right away, drops repeated deliveries, and scans in a background queue.', 'Only the lockfiles at the head commit are downloaded. Planned: post the result back as a commit status and a comment.'],
      beats: [[0, 'The same scan runs on every pull request.'], [1.2, 'GitHub sends a webhook when a pull request opens or gets new commits.'], [2.6, 'DepScan checks the HMAC signature with your secret before reading the event.'], [3.6, 'It answers 202 at once and scans in the background. Repeated deliveries are ignored.'], [5.3, 'Only the lockfiles at the head commit are downloaded: 2 of 214 files.'], [9.0, 'Planned: the result comes back as a commit status and a comment, and a failing check blocks the merge.']],
      code: [[1.2, 'POST /webhooks/github HTTP/1.1'], [1.3, 'X-GitHub-Event: pull_request'], [1.4, 'X-Hub-Signature-256: sha256=' + HOOK_SIG.slice(0, 32) + '…'], [2.6, '// VerifySignature: HMAC-SHA256(secret, body), constant-time compare'], [3.6, 'HTTP/1.1 202 Accepted  {"status": "queued"}'], [null, ''], [5.3, 'GET /repos/you/shop-api/git/trees/9c1e2f7?recursive=1'], [5.8, 'GET /repos/you/shop-api/git/blobs/…  (go.mod)'], [6.2, 'GET /repos/you/shop-api/git/blobs/…  (web/package-lock.json)'], [9.0, '// planned: POST /repos/you/shop-api/statuses/9c1e2f7  {"state": "failure"}']]
    }
  ];
  let acc = 0;
  CH.forEach((c, i) => { c.i = i; c.start = acc; acc += c.dur; });
  const TOTAL = acc;
  const TRANS = 0.6;

  /* ======================= DOM ======================= */
  const stage = $('demoStage'), screen = $('screen'), capEl = $('cap'), plannedEl = $('planned'), bigPlay = $('bigPlay'), endCard = $('endCard');
  const playBtn = $('tPlay'), prevBtn = $('tPrev'), nextBtn = $('tNext'), timeEl = $('tTime'), scrub = $('scrub'), knob = $('knob'), hoverTip = $('hoverTip'), speedBtn = $('tSpeed'), fullBtn = $('tFull');
  const rail = $('chapters'), narr = $('narr'), hoodFile = $('hoodFile'), hoodCode = $('hoodCode');
  const rmq = matchMedia('(prefers-reduced-motion: reduce)'), nmq = matchMedia('(max-width: 640px)');
  const fmt = (s) => { s = Math.max(0, Math.round(s)); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
  const escH = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  $('howCount').textContent = CH.length;
  $('howLen').textContent = fmt(TOTAL);
  rail.innerHTML = CH.map((c, i) => '<li><button class="chap" type="button" data-i="' + i + '" aria-label="Step ' + (i + 1) + ': ' + c.title + '"><span class="n">' + (i + 1) + '</span><span class="t">' + c.title + (c.planned != null ? '<span class="pdot" title="Planned"></span><span class="sr"> (planned)</span>' : '') + '</span><span class="d">' + fmt(c.start) + '</span><span class="p"></span></button></li>').join('');
  const railBtns = Array.from(rail.querySelectorAll('.chap'));
  CH.forEach((c) => {
    const s = document.createElement('span'); s.className = 'sg' + (c.planned != null ? ' plan' : ''); s.style.setProperty('--d', c.dur); s.innerHTML = '<i></i>';
    scrub.insertBefore(s, knob);
  });
  const segs = Array.from(scrub.querySelectorAll('.sg'));
  scrub.setAttribute('aria-valuemax', String(TOTAL));

  // Small highlighter for the "under the hood" lines.
  function hl(s) {
    const re = /("(?:[^"\\]|\\.)*")|(\/\/.*$)|(^\$ .*$)|\b(FAILED|WARNING|503 Service Unavailable|422 Unprocessable Entity|exit status 1)\b|\b(func|return|if|for|range|else|continue|type|struct|bool|string|true|false|nil|switch|case)\b|\b(POST|GET|HTTP\/1\.1|200 OK|202 Accepted|OK)\b|(sha256[:=][0-9a-f…]+)|(\b\d[\d.]*\b)/g;
    let out = '', last = 0, m;
    while ((m = re.exec(s))) {
      out += escH(s.slice(last, m.index));
      const cls = m[1] ? 's' : m[2] ? 'c' : m[3] ? 'k' : m[4] ? 'e' : m[5] ? 'k' : m[6] ? 'h' : m[7] ? 'h' : 'n';
      out += '<span class="' + cls + '">' + escH(m[0]) + '</span>';
      last = m.index + m[0].length;
    }
    return out + escH(s.slice(last));
  }

  /* ======================= engine ======================= */
  let t = 0, playing = false, speed = 1, raf = 0, last = 0, cur = -1, beat = -1, codeNow = -2;
  let entered = false, resumeOnEnter = false, pausedByView = false, dragging = false, everPlayed = false;
  let cssW = 0, cssH = 0, dpr = 1;
  const SPEEDS = [0.5, 1, 1.5, 2];

  function chapterAt(tt) { for (let i = CH.length - 1; i >= 0; i--) if (tt >= CH[i].start) return i; return 0; }
  function resize() {
    const r = stage.getBoundingClientRect();
    cssW = r.width; cssH = r.height; dpr = Math.min(2, devicePixelRatio || 1);
    canvas.width = Math.max(1, Math.round(cssW * dpr)); canvas.height = Math.max(1, Math.round(cssH * dpr));
    WIDE = !nmq.matches || (document.fullscreenElement === screen && cssW > cssH);
  }
  function drawScene(c, lt, alpha, zoom) {
    if (alpha <= 0.002) return;
    const W = SW(), H = SH(), s = Math.min(cssW / W, cssH / H), ox = (cssW - W * s) / 2, oy = (cssH - H * s) / 2;
    ctx.save();
    ctx.setTransform(dpr * s, 0, 0, dpr * s, dpr * ox, dpr * oy);
    if (zoom !== 1) { ctx.translate(W / 2, H / 2); ctx.scale(zoom, zoom); ctx.translate(-W / 2, -H / 2); }
    BA = alpha; NOW = lt;
    try { c.scene(lt); } catch (e) { console.error('walkthrough step ' + (c.i + 1) + ':', e); }
    BA = 1;
    ctx.restore();
  }
  function render() {
    if (!cssW) resize();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // blueprint dots, in world space
    const W = SW(), H = SH(), s = Math.min(cssW / W, cssH / H), ox = (cssW - W * s) / 2, oy = (cssH - H * s) / 2;
    ctx.setTransform(dpr * s, 0, 0, dpr * s, dpr * ox, dpr * oy);
    ctx.globalAlpha = 1; ctx.fillStyle = 'rgba(170,185,255,0.07)';
    for (let x = 12; x < W; x += 24) for (let y = 12; y < H; y += 24) ctx.fillRect(x - 0.75, y - 0.75, 1.5, 1.5);
    const i = chapterAt(t), c = CH[i], lt = Math.min(t - c.start, c.dur);
    const tr = rmq.matches ? 1 : c01(lt / TRANS);
    if (i > 0 && tr < 1) {
      const e = E.io(tr);
      drawScene(CH[i - 1], CH[i - 1].dur, 1 - e, 1 + 0.03 * e);
      drawScene(c, lt, e, 0.97 + 0.03 * e);
    } else drawScene(c, lt, 1, 1);
  }

  function setCaption(html) {
    if (capEl.dataset.html === html) return;
    capEl.dataset.html = html;
    if (rmq.matches) { capEl.innerHTML = html; return; }
    capEl.classList.add('swap');
    clearTimeout(setCaption.h);
    setCaption.h = setTimeout(() => { capEl.innerHTML = html; capEl.classList.remove('swap'); }, 160);
  }
  function renderNarr(c) {
    narr.innerHTML = '<p class="kick">Step ' + (c.i + 1) + ' of ' + CH.length + (c.planned != null ? ' <span class="plan">Planned</span>' : '') + '</p>' +
      '<h2>' + c.title + '</h2><p>' + c.p + '</p><ul>' + c.li.map((x) => '<li>' + x + '</li>').join('') + '</ul>' +
      '<div class="terms"><span>Terms in this step</span>' + c.terms.map((id) => {
        const tp = window.Learn && window.Learn.topics[id];
        return tp ? '<button class="term" type="button" data-learn="' + id + '"><i>?</i>' + escH(tp.title.replace(/ \(planned\)$/, '')) + '</button>' : '';
      }).join('') + '</div>';
    narr.classList.remove('swap'); void narr.offsetWidth; narr.classList.add('swap');
    hoodFile.textContent = c.file;
    let at = 0;
    hoodCode.innerHTML = c.code.map(([a, s]) => { if (a != null) at = a; return '<span class="ln" data-at="' + at + '">' + (hl(s.replace(/\t/g, '    ')) || ' ') + '</span>'; }).join('');
    hoodCode.scrollTop = 0;
    codeNow = -2;
  }
  function syncCode(lt) {
    const lines = hoodCode.children;
    let now = -1;
    for (let j = 0; j < lines.length; j++) if (+lines[j].dataset.at <= lt) now = j;
    if (now === codeNow) return;
    codeNow = now;
    for (let j = 0; j < lines.length; j++) {
      lines[j].classList.toggle('seen', j <= now);
      lines[j].classList.toggle('now', j === now || (now >= 0 && j < now && lines[j].dataset.at === lines[now].dataset.at));
    }
    const el = lines[now];
    if (el && hoodCode.scrollHeight > hoodCode.clientHeight + 4) {
      const top = el.offsetTop - hoodCode.clientHeight / 2;
      hoodCode.scrollTo({ top, behavior: rmq.matches ? 'auto' : 'smooth' });
    }
  }
  function syncUI() {
    const i = chapterAt(t), c = CH[i], lt = t - c.start;
    if (i !== cur) {
      cur = i; beat = -1;
      renderNarr(c);
      railBtns.forEach((b, j) => { b.classList.toggle('cur', j === i); b.classList.toggle('done', j < i); if (j === i) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current'); });
      const rb = railBtns[i];
      if (rb && rail.scrollWidth > rail.clientWidth + 4) rail.scrollTo({ left: rb.parentElement.offsetLeft - 16, behavior: rmq.matches ? 'auto' : 'smooth' });
    }
    let b = 0;
    c.beats.forEach(([bt], j) => { if (lt >= bt) b = j; });
    if (b !== beat) { beat = b; setCaption(c.beats[b][1]); canvas.setAttribute('aria-label', 'Step ' + (i + 1) + ', ' + c.title + ': ' + c.beats[b][1].replace(/<[^>]+>/g, '')); }
    plannedEl.classList.toggle('off', !(c.planned != null && lt >= c.planned));
    syncCode(lt);
    railBtns[i].style.setProperty('--p', c01(lt / c.dur).toFixed(3));
    segs.forEach((s, j) => { const p = j < i ? 1 : j > i ? 0 : c01(lt / c.dur); if (s._p !== p) { s._p = p; s.firstChild.style.setProperty('--p', p.toFixed(4)); } });
    // knob position follows the segments, gaps included
    const sr = scrub.getBoundingClientRect(), segR = segs[i].getBoundingClientRect();
    knob.style.left = (segR.left - sr.left + segR.width * c01(lt / c.dur)).toFixed(1) + 'px';
    timeEl.innerHTML = '<b>' + fmt(t) + '</b> / ' + fmt(TOTAL);
    scrub.setAttribute('aria-valuenow', String(Math.round(t)));
    scrub.setAttribute('aria-valuetext', fmt(t) + ', step ' + (i + 1) + ': ' + c.title);
    screen.classList.toggle('playing', playing);
    playBtn.setAttribute('aria-label', playing ? 'Pause' : 'Play');
    prevBtn.disabled = t <= 0.01; nextBtn.disabled = i === CH.length - 1;
    endCard.hidden = !(t >= TOTAL - 0.001 && !playing);
    bigPlay.hidden = playing || everPlayed || t > 0.01;
    capEl.setAttribute('aria-live', playing ? 'off' : 'polite');
  }
  function frame(ts) {
    raf = 0;
    if (playing && !dragging) {
      const dt = Math.min(0.1, Math.max(0, (ts - last) / 1000));
      t = Math.min(TOTAL, t + dt * speed);
      if (t >= TOTAL) playing = false;
    }
    last = ts;
    render(); syncUI();
    if (playing) raf = requestAnimationFrame(frame);
  }
  function kick() { if (!raf) { last = performance.now(); raf = requestAnimationFrame(frame); } }
  function play() { if (t >= TOTAL - 0.001) t = 0; playing = true; everPlayed = true; pausedByView = false; kick(); }
  function pause() { playing = false; kick(); }
  function seek(nt) { t = clamp(nt, 0, TOTAL); kick(); }
  function goChapter(i, autoplay) {
    i = clamp(i, 0, CH.length - 1);
    // With reduced motion a step opens on its finished state, which says the most.
    seek(rmq.matches && !autoplay ? CH[i].start + CH[i].dur - 0.05 : CH[i].start);
    if (autoplay) play();
  }

  /* ======================= controls ======================= */
  playBtn.addEventListener('click', () => (playing ? pause() : play()));
  bigPlay.addEventListener('click', play);
  prevBtn.addEventListener('click', () => { const i = chapterAt(t); goChapter(t - CH[i].start > 1.5 ? i : i - 1, playing); });
  nextBtn.addEventListener('click', () => goChapter(chapterAt(t) + 1, playing));
  speedBtn.addEventListener('click', () => { speed = SPEEDS[(SPEEDS.indexOf(speed) + 1) % SPEEDS.length]; speedBtn.textContent = speed + '×'; speedBtn.setAttribute('aria-label', 'Playback speed ' + speed + '×'); });
  $('endReplay').addEventListener('click', () => { t = 0; play(); });
  $('endScan').addEventListener('click', () => { pause(); document.dispatchEvent(new CustomEvent('depscan:try')); });
  rail.addEventListener('click', (e) => { const b = e.target.closest('.chap'); if (b) goChapter(+b.dataset.i, !rmq.matches && (playing || !everPlayed)); });
  fullBtn.addEventListener('click', () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else if (screen.requestFullscreen) screen.requestFullscreen().catch(() => {});
  });
  if (!screen.requestFullscreen) fullBtn.hidden = true;
  document.addEventListener('fullscreenchange', () => { resize(); kick(); });

  // scrubbing
  function timeAtX(clientX) {
    for (let j = 0; j < segs.length; j++) {
      const r = segs[j].getBoundingClientRect();
      if (clientX <= r.right + 1.5 || j === segs.length - 1) return CH[j].start + CH[j].dur * c01((clientX - r.left) / r.width);
    }
    return 0;
  }
  let wasPlaying = false;
  scrub.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    dragging = true; wasPlaying = playing; scrub.classList.add('drag');
    try { scrub.setPointerCapture(e.pointerId); } catch (err) { /* capture is best effort */ }
    seek(timeAtX(e.clientX));
  });
  scrub.addEventListener('pointermove', (e) => {
    const tt = timeAtX(e.clientX), i = chapterAt(tt), sr = scrub.getBoundingClientRect();
    hoverTip.innerHTML = '<b>' + (i + 1) + '. ' + CH[i].title + '</b><span>' + fmt(tt) + '</span>';
    hoverTip.style.left = clamp(e.clientX - sr.left, 90, sr.width - 90) + 'px';
    if (dragging) seek(tt);
  });
  const endDrag = () => { if (!dragging) return; dragging = false; scrub.classList.remove('drag'); if (wasPlaying) play(); };
  scrub.addEventListener('pointerup', endDrag);
  scrub.addEventListener('pointercancel', endDrag);
  scrub.addEventListener('keydown', (e) => {
    const i = chapterAt(t);
    const map = { ArrowLeft: () => seek(t - 5), ArrowRight: () => seek(t + 5), PageUp: () => goChapter(i - 1, playing), PageDown: () => goChapter(i + 1, playing), Home: () => seek(0), End: () => seek(TOTAL) };
    if (map[e.key]) { e.preventDefault(); map[e.key](); }
  });

  // tap the stage to play or pause; swipe to change step
  let down = null;
  stage.addEventListener('pointerdown', (e) => { if (e.target.closest('button')) return; down = { x: e.clientX, y: e.clientY }; });
  stage.addEventListener('pointerup', (e) => {
    if (!down || e.target.closest('button')) { down = null; return; }
    const dx = e.clientX - down.x, dy = e.clientY - down.y; down = null;
    if (Math.abs(dx) > 50 && Math.abs(dx) > Math.abs(dy) * 1.4) goChapter(chapterAt(t) + (dx < 0 ? 1 : -1), playing);
    else if (Math.hypot(dx, dy) < 8 && endCard.hidden) (playing ? pause() : play());
  });

  // keyboard, while this pane is open
  document.addEventListener('keydown', (e) => {
    if (pane.hidden || e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey) return;
    const tag = document.activeElement && document.activeElement.tagName;
    if (/INPUT|TEXTAREA|SELECT/.test(tag)) return;
    if (document.activeElement && document.activeElement.closest('#learn')) return;
    const onButton = tag === 'BUTTON';
    const i = chapterAt(t);
    if ((e.key === ' ' && !onButton) || e.key === 'k') { e.preventDefault(); playing ? pause() : play(); }
    else if (e.key === 'ArrowRight' && document.activeElement !== scrub) { e.preventDefault(); e.shiftKey ? goChapter(i + 1, playing) : seek(t + 5); }
    else if (e.key === 'ArrowLeft' && document.activeElement !== scrub) { e.preventDefault(); e.shiftKey ? goChapter(i - 1, playing) : seek(t - 5); }
    else if (e.key === 'f' && screen.requestFullscreen) { e.preventDefault(); fullBtn.click(); }
    else if (/^[1-9]$/.test(e.key) && !onButton) { goChapter(+e.key - 1, playing); }
  });

  /* ======================= lifecycle ======================= */
  const ro = new ResizeObserver(() => { resize(); kick(); });
  ro.observe(stage);
  nmq.addEventListener('change', () => { resize(); kick(); });
  rmq.addEventListener('change', kick);
  const io = new IntersectionObserver((en) => {
    const vis = en.some((x) => x.isIntersecting);
    if (!vis && playing) { pausedByView = true; pause(); }
    else if (vis && pausedByView && !pane.hidden) { pausedByView = false; play(); }
  }, { threshold: 0.25 });
  io.observe(stage);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && playing) { pausedByView = true; pause(); }
    else if (!document.hidden && pausedByView && !pane.hidden) { pausedByView = false; play(); }
  });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(kick);

  window.DepscanDemo = {
    enter() {
      resize();
      if (!entered) { entered = true; if (!rmq.matches) play(); else { t = 0; kick(); } }
      else if (resumeOnEnter) { resumeOnEnter = false; play(); }
      else kick();
    },
    leave() { resumeOnEnter = playing; if (playing) pause(); },
    goChapter(i, autoplay) { entered = true; resize(); goChapter(i, autoplay && !rmq.matches); },
    get time() { return t; }, set time(v) { seek(v); }, chapters: CH, total: TOTAL
  };
  syncUI();
})();
