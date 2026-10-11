/* depscan dashboard: routing, the scan flow (folder picker, drag and drop,
   path), the live survey while a scan runs, and the History and Policy pages.
   Results are drawn by results.js; history is kept by store.js. */
(function () {
  'use strict';
  const DS = window.DS;
  const { $, esc, plural, fmtN, fmtBytes, fmtMs, ago, when, toast, download, icon, codeBlock, reduced } = DS;
  const ROOT = DS.ROOT;
  const SEP = ROOT.indexOf('\\') !== -1 ? '\\' : '/';
  const app = { route: '', policy: null, policyErr: '', scanning: null, entry: null };

  /* ================================================================ server */
  async function getJSON(url, opts) {
    const res = await fetch(url, Object.assign({ cache: 'no-store' }, opts || {}));
    let data = null;
    try { data = await res.json(); } catch (e) { /* not JSON */ }
    return { res, data };
  }
  async function loadPolicy() {
    try {
      const { res, data } = await getJSON('/policy');
      if (res.ok && data && data.digest) { app.policy = data; app.policyErr = ''; }
      else { app.policy = null; app.policyErr = res.status === 404 ? 'This server does not expose GET /policy. Update it to see your rules here.' : 'The server answered ' + res.status + '.'; }
    } catch (e) { app.policy = null; app.policyErr = 'The server is not reachable.'; }
    return app.policy;
  }
  let health = { ok: null, ms: 0, at: 0 };
  async function checkHealth() {
    const t = performance.now();
    try { const { res } = await getJSON('/healthz'); health = { ok: res.ok, ms: Math.round(performance.now() - t), at: Date.now() }; }
    catch (e) { health = { ok: false, ms: 0, at: Date.now() }; }
    const b = $('statusBtn');
    b.classList.toggle('ok', health.ok === true); b.classList.toggle('down', health.ok === false);
    $('statusText').textContent = health.ok ? 'Local server' : 'Server offline';
    if (!$('statusPop').hidden) renderStatus();
    return health.ok;
  }
  async function renderStatus() {
    const n = (await DS.store.listScans()).length;
    const pol = app.policy;
    $('statusPop').innerHTML = '<h3>' + (health.ok ? 'Connected to your depscan server' : 'Cannot reach the depscan server') + '</h3><dl>' +
      '<dt>Address</dt><dd class="mono">' + esc(location.host) + (health.ok ? ' <span class="chip" style="--c:var(--clean);--t:var(--clean-t)">' + health.ms + ' ms</span>' : '') + '</dd>' +
      '<dt>Path scans</dt><dd>Folders inside <span class="mono">' + esc(ROOT || 'the scan root') + '</span></dd>' +
      '<dt>Folder picker</dt><dd>Any folder on this computer</dd>' +
      '<dt>Policy</dt><dd>' + (pol ? '<a class="xlink mono" href="#policy">' + esc(pol.digest.slice(0, 12)) + '</a>' : esc(app.policyErr || 'Loading')) + '</dd>' +
      '<dt>History</dt><dd>' + plural(n, 'scan') + ' in this browser' + (DS.store.persistent ? '' : ', not kept after you close it') + '</dd></dl>' +
      (health.ok ? '<p>The server only listens on this computer. Scans contact OSV.dev and deps.dev.</p>' : '<p>Start it from the project folder with <code>make run-server</code>, then reload this page.</p>');
  }

  /* ================================================================ theme and motion */
  const THEMES = ['system', 'dark', 'light'];
  function applyTheme(mode) {
    const d = document.documentElement;
    if (mode === 'system') d.removeAttribute('data-theme'); else d.setAttribute('data-theme', mode);
    try { if (mode === 'system') localStorage.removeItem('depscan.theme'); else localStorage.setItem('depscan.theme', mode); } catch (e) { /* storage blocked */ }
    const b = $('themeBtn'); b.dataset.mode = mode;
    b.setAttribute('aria-label', 'Theme: ' + (mode === 'system' ? 'match the system' : mode) + '. Click to change.');
    b.title = b.getAttribute('aria-label');
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = getComputedStyle(d).getPropertyValue('--bg').trim() || '#06080b';
  }
  function applyMotion(on) {
    document.documentElement.classList.toggle('still', !on);
    const b = $('motionBtn'); b.setAttribute('aria-pressed', String(!on));
    b.setAttribute('aria-label', on ? 'Pause background motion' : 'Play background motion'); b.title = b.getAttribute('aria-label');
    try { localStorage.setItem('depscan.motion', on ? 'on' : 'off'); } catch (e) { /* storage blocked */ }
    DS.field.setMotion(on);
  }

  /* ================================================================ routing */
  const VIEWS = { scan: 'viewScan', history: 'viewHistory', policy: 'viewPolicy', how: 'viewHow' };
  const TITLES = { scan: 'depscan', history: 'History · depscan', policy: 'Policy · depscan', how: 'How a scan works · depscan' };
  const scrollMemo = {};
  function parseHash() {
    const h = location.hash.replace(/^#/, '');
    const [name, id] = h.split('/');
    return { name: VIEWS[name] ? name : 'scan', id: id ? decodeURIComponent(id) : '' };
  }
  function moveNav(instant) {
    const a = document.querySelector('.nav a[aria-current="page"]'), ind = $('navInd');
    if (!a || !ind) return;
    if (instant) ind.style.transition = 'none';
    ind.style.width = a.offsetWidth + 'px'; ind.style.transform = 'translateX(' + a.offsetLeft + 'px)';
    if (instant) { void ind.offsetWidth; ind.style.transition = ''; }
  }
  function swapTo(name) {
    for (const k in VIEWS) $(VIEWS[k]).hidden = k !== name;
    document.querySelectorAll('.nav a').forEach((a) => { if (a.dataset.route === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    moveNav(false);
  }
  async function route(first) {
    const { name, id } = parseHash();
    const prev = app.route;
    if (prev) scrollMemo[prev] = scrollY;
    if (name !== prev) {
      const go = () => { swapTo(name); if (!first && name !== 'scan') scrollTo(0, scrollMemo[name] || 0); };
      if (!first && document.startViewTransition && !reduced()) await document.startViewTransition(go).updateCallbackDone.catch(() => {});
      else go();
      app.route = name;
      if (first) moveNav(true);
    }
    document.title = TITLES[name];
    if (name !== 'scan' && !controller) DS.field.set({ mode: 'idle' });
    else if (name === 'scan' && app.entry && !controller && app.fieldState) DS.field.set(app.fieldState);
    setMenu(false);
    syncWord();
    setRail(name === 'scan' && !!app.entry && !$('results').hidden);
    const demo = window.DepscanDemo;
    if (demo) { if (name === 'how') demo.enter(); else demo.leave(); }
    if (name === 'history') renderHistory();
    if (name === 'policy') renderPolicy();
    if (name === 'scan' && id && (!app.entry || app.entry.id !== id)) {
      const e = await DS.store.getScan(id);
      if (e) showEntry(e, { scroll: true });
    }
    if (name === 'scan' && !id && !prev && !first) scrollTo(0, scrollMemo.scan || 0);
  }
  function go(hash) { if (location.hash !== hash) history.pushState(null, '', hash); route(); }
  addEventListener('popstate', () => route());
  addEventListener('hashchange', () => route());

  /* ================================================================ scan: helpers */
  const sourceKey = (kind, v) => kind + ':' + String(v).trim().replace(/[\\/]+$/, '').toLowerCase();
  function guessSource(label) {
    const m = /^github\.com\/([^#]+)#(\d+)@/.exec(label);
    if (m) return { kind: 'pr', key: 'pr:' + m[1].toLowerCase(), name: m[1] + ' #' + m[2], repo: m[1] };
    if (/[\\/]|^[a-z]:/i.test(label)) return { kind: 'path', key: sourceKey('path', label), name: label.split(/[\\/]/).filter(Boolean).pop() || label, path: label };
    return { kind: 'folder', key: sourceKey('folder', label), name: label };
  }
  async function lastOf(key) { return (await DS.store.listScans()).find((e) => e.source && e.source.key === key) || null; }
  function setScanning(on) { document.documentElement.classList.toggle('scanning', on); $('pickBtn').disabled = on; $('pathBtn').disabled = on; syncWord(); }
  function compactHero(on) {
    const hero = $('hero');
    if (hero.classList.contains('small') === on) { syncWord(); return; }
    const f = () => { hero.classList.toggle('small', on); syncWord(); };
    if (document.startViewTransition && !reduced()) document.startViewTransition(f); else f();
  }
  // The giant wordmark stands in the landscape only on the landing view.
  function syncWord() {
    const on = app.route === 'scan' && !$('hero').classList.contains('small') && !document.documentElement.classList.contains('scanning');
    DS.field.word(on ? $('heroWord') : null);
    $('cue').hidden = !(on && app.recentCount);
    if (app.route !== 'scan' || !app.entry) setRail(false);
  }

  /* ================================================================ survey (progress while scanning) */
  const STAGES = [
    ['read', 'Read lockfiles', ''],
    ['lic', 'Look up licenses', 'deps.dev, up to 8 lookups at a time'],
    ['osv', 'Check advisories', 'OSV.dev: one batch query, then every matching record'],
    ['pol', 'Apply your policy', '']
  ];
  function surveyHTML(s) {
    const pol = app.policy;
    const det = { read: s.kind === 'folder' ? 'In your browser: looking for go.mod and package-lock.json' : 'On the server: walking the folder', pol: pol ? 'policy.yaml, digest ' + pol.digest.slice(0, 7) : 'policy.yaml loaded by the server' };
    return '<div class="sv-top"><p class="eyebrow survey-kicker"><span class="pulse" aria-hidden="true"></span><span id="svState">Surveying the dependencies</span></p><button class="btn btn-sm" type="button" id="svCancel">Cancel<span class="sr"> the scan</span></button></div>' +
      '<div class="survey-head"><div><h2 class="survey-name">' + esc(s.name) + '</h2><p class="survey-sub" id="svSub">' + esc(s.sub || '') + '</p></div>' +
      '<div class="clock" id="svClock" aria-hidden="true">0.0<small>s</small></div></div>' +
      '<div class="radar"><canvas id="svRadar" aria-hidden="true"></canvas><div class="radar-tick"><b id="svTick"></b><span id="svCount"></span></div></div>' +
      '<ol class="stages" id="svStages">' + STAGES.map(([id, title, d], i) => '<li class="stage wait" data-s="' + id + '"><span class="stage-n">0' + (i + 1) + '</span><b>' + title + icon.check + '</b><p id="sv-' + id + '">' + esc(d || det[id]) + '</p></li>').join('') + '</ol>' +
      '<div class="eta"><div class="eta-bar loose" id="svBar"><i></i></div><p id="svEta"></p></div>' +
      '<div class="survey-files" id="svFiles"></div>';
  }
  function stage(id, state, text) {
    const li = document.querySelector('#svStages [data-s="' + id + '"]'); if (!li) return;
    li.className = 'stage ' + state;
    if (text != null) $('sv-' + id).textContent = text;
  }
  function startSurvey(s) {
    const el = $('survey');
    el.innerHTML = surveyHTML(s); el.hidden = false;
    $('svCancel').onclick = () => cancelScan();
    const t0 = performance.now();
    let raf = 0, alive = true;
    const radar = startRadar($('svRadar'), s);
    const tickClock = () => {
      if (!alive) return;
      const ms = performance.now() - t0;
      $('svClock').innerHTML = (ms / 1000).toFixed(1) + '<small>s</small>';
      if (s.est) {
        const p = Math.min(0.96, ms / s.est);
        const bar = $('svBar'); bar.classList.remove('loose'); bar.firstChild.style.width = (p * 100).toFixed(1) + '%';
        $('svEta').textContent = ms > s.est * 1.2 ? 'Taking longer than the ' + fmtMs(s.est) + ' your last scan of ' + s.name + ' took. OSV.dev can be slow; dropped connections are retried.' : 'About ' + fmtMs(s.est) + ', based on your last scan of ' + s.name + ' (' + ago(s.estAt) + ').';
      } else if (!$('svEta').textContent) {
        $('svEta').textContent = 'First scan of this project. Large projects can take a minute, because every advisory is fetched from OSV.dev.';
      }
      raf = setTimeout(tickClock, 100);
    };
    tickClock();
    el.scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'center' });
    return {
      t0, radar,
      set(o) { if (o.sub != null) $('svSub').textContent = o.sub; if (o.names) radar.setNames(o.names, o.count, o.groups); if (o.files) $('svFiles').innerHTML = o.files; },
      stop() { alive = false; clearTimeout(raf); radar.stop(); },
      ms: () => performance.now() - t0
    };
  }

  // The panel's scan field: one cell per package, swept by a beam.
  function startRadar(canvas, s) {
    const ctx = canvas.getContext('2d');
    let names = [], count = s.count || 0, groups = [], raf = 0, alive = true, t0 = performance.now(), dpr = 1, W = 0, H = 0;
    let colLine = [223, 231, 224], colBeam = [224, 35, 28], colAlt = [165, 191, 220];
    const probe = document.createElement('canvas').getContext('2d');
    const rgbOf = (c) => { probe.fillStyle = '#000'; probe.fillStyle = c; probe.fillRect(0, 0, 1, 1); const d = probe.getImageData(0, 0, 1, 1).data; return [d[0], d[1], d[2]]; };
    const cs = getComputedStyle(document.documentElement);
    colLine = rgbOf(cs.getPropertyValue('--text').trim()); colBeam = rgbOf(cs.getPropertyValue('--brand').trim()); colAlt = rgbOf(cs.getPropertyValue('--low-t').trim());
    const size = () => { const r = canvas.getBoundingClientRect(); dpr = Math.min(2, devicePixelRatio || 1); W = r.width; H = r.height; canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); };
    size();
    const ro = new ResizeObserver(size); ro.observe(canvas);
    const draw = (now) => {
      if (!alive) return;
      const t = (now - t0) / 1000;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
      const known = count > 0, n = known ? count : 320, cells = Math.min(n, 2400), per = n / cells;
      const top = 16, bottom = 40, availH = Math.max(20, H - top - bottom), availW = W - 28;
      let cell = Math.max(4, Math.min(16, Math.floor(Math.sqrt((availW * availH) / cells) - 2)));
      let cols = Math.max(1, Math.floor(availW / (cell + 2))), rows = Math.ceil(cells / cols);
      while (rows * (cell + 2) > availH && cell > 3) { cell--; cols = Math.max(1, Math.floor(availW / (cell + 2))); rows = Math.ceil(cells / cols); }
      const gw = cols * (cell + 2) - 2, ox = (W - gw) / 2, oy = top + (availH - rows * (cell + 2)) / 2;
      const period = 2.6, ph = reduced() ? 0.5 : (t % period) / period, beamX = ox - 60 + ph * (gw + 120);
      const split = groups.length > 1 ? groups[0].n : Infinity;
      for (let i = 0; i < cells; i++) {
        const cx = ox + (i % cols) * (cell + 2), cy = oy + Math.floor(i / cols) * (cell + 2);
        const d = (cx + cell / 2) - beamX, g = Math.exp(-(d * d) / (2 * 34 * 34)), trail = d < 0 ? Math.exp(d / 200) * 0.4 : 0;
        const a = (known ? 0.16 : 0.07) + g * 0.82 + trail * 0.35;
        const k = Math.min(1, g * 1.5), base = i * per >= split ? colAlt : colLine;
        const r = base[0] + (colBeam[0] - base[0]) * k * 0.85, gg = base[1] + (colBeam[1] - base[1]) * k * 0.85, b = base[2] + (colBeam[2] - base[2]) * k * 0.85;
        ctx.fillStyle = 'rgba(' + (r | 0) + ',' + (gg | 0) + ',' + (b | 0) + ',' + Math.min(1, a).toFixed(3) + ')';
        ctx.fillRect(cx, cy, cell, cell);
      }
      // the beam itself
      const grd = ctx.createLinearGradient(beamX - 90, 0, beamX + 4, 0);
      grd.addColorStop(0, 'rgba(' + colBeam.join(',') + ',0)'); grd.addColorStop(1, 'rgba(' + colBeam.join(',') + ',.26)');
      ctx.fillStyle = grd; ctx.fillRect(beamX - 90, 6, 94, H - 46);
      ctx.fillStyle = 'rgba(' + colBeam.join(',') + ',.9)'; ctx.fillRect(beamX, 6, 1.5, H - 46);
      if (names.length && !reduced()) {
        const idx = Math.min(names.length - 1, Math.floor(ph * names.length));
        $('svTick').textContent = names[idx];
      }
      $('svCount').textContent = known ? (groups.length > 1 ? groups.map((g) => fmtN(g.n) + ' ' + g.label).join(', ') : (s.approx ? 'about ' : '') + fmtN(count) + ' packages' + (s.approx ? ' last time' : '')) + (per > 1.01 ? ', ' + Math.round(per) + ' per square' : '') : 'package count arrives with the result';
      if (!reduced()) raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return {
      setNames(list, c, gr) { names = list || []; if (c != null) count = c; groups = gr || []; if (reduced()) { $('svTick').textContent = names.length ? names.length + ' package names read' : ''; raf = requestAnimationFrame(draw); } },
      stop() { alive = false; cancelAnimationFrame(raf); ro.disconnect(); }
    };
  }

  /* ================================================================ scan: run */
  let controller = null;
  function cancelScan() { if (controller) controller.abort(); }

  async function begin(source, sub) {
    if (controller) controller.abort();
    controller = new AbortController();
    $('scanError').innerHTML = '';
    $('results').hidden = true; DS.results.destroy();
    app.entry = null; setRail(false);
    compactHero(true); setScanning(true);
    DS.field.set({ mode: 'scan' });
    const last = await lastOf(source.key);
    const sv = startSurvey({ name: source.name, kind: source.kind, sub, est: last && last.ms ? last.ms : 0, estAt: last ? last.at : 0, count: source.kind === 'path' && last && last.summary ? last.summary.deps : 0, approx: source.kind === 'path' && !!last });
    return { sv, signal: controller.signal };
  }
  function end(sv) {
    if (sv) sv.stop();
    setScanning(false);
    controller = null;
  }

  // Path scans: the server reads the folder itself (it must be inside its scan root).
  async function scanPath(path) {
    path = (path || $('pathIn').value).trim().replace(/^"(.*)"$/, '$1');
    if (!path) { $('pathIn').focus(); return; }
    $('pathIn').value = path;
    const source = { kind: 'path', key: sourceKey('path', path), name: path.split(/[\\/]/).filter(Boolean).pop() || path, path };
    const { sv, signal } = await begin(source, /^([a-z]:)?[\\/]/i.test(path) ? path : 'Inside ' + ROOT + SEP + path);
    STAGES.forEach(([id]) => stage(id, 'run'));
    stage('read', 'run', 'On the server: walking the folder, skipping .git, vendor and node_modules');
    await send(source, sv, signal, () => fetch('/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path }), signal }));
  }

  // Folder scans: the browser finds the lockfiles and sends only those.
  async function scanWalk(source, walker) {
    const { sv, signal } = await begin(source, 'Looking for lockfiles');
    stage('read', 'run');
    let w;
    try {
      w = await walker((p) => { sv.set({ sub: 'Looking for lockfiles: ' + plural(p.dirs, 'folder') + ' checked, ' + plural(p.found.length, 'lockfile') + ' found' }); }, signal);
      if (!w) throw new Error('No folder was read.');
      source.name = w.name || source.name;
      source.key = sourceKey('folder', source.name);
      document.querySelector('#survey .survey-name').textContent = source.name;
      if (w.handle) DS.store.putHandle(source.key, w.handle);
      if (!w.found.length) { end(sv); $('survey').hidden = true; showNoLockfiles(source.name, w); DS.field.set({ mode: 'idle' }); compactHero(false); return; }
      const items = await DS.picker.readAll(w.found, signal);
      const usable = items.filter((i) => !i.skip);
      const count = usable.reduce((s, i) => s + i.count, 0);
      // Go modules first, then npm packages, so the field shows two blocks.
      const byKind = (k) => usable.filter((i) => i.kind === k);
      const names = [], groups = [];
      [['go', 'Go'], ['npm', 'npm']].forEach(([k, label]) => { const its = byKind(k); const n = its.reduce((a, i) => a + i.count, 0); if (n) { groups.push({ n, label }); its.forEach((i) => i.names.forEach((x) => names.push(x))); } });
      const chips = items.map((i) => '<span class="lockchip' + (i.problem ? ' warn' : '') + '" title="' + esc(i.problem ? i.path + ' ' + i.problem : i.path) + '"><span>' + esc(i.path) + '</span><b>' + (i.problem ? 'skipped' : fmtN(i.count)) + '</b></span>').join('') +
        (w.skipped.length ? '<span class="lockchip" title="' + esc(w.skipped.slice(0, 20).join('\n')) + '"><span>skipped</span><b>' + plural(w.skipped.length, 'folder') + '</b></span>' : '');
      sv.set({ names, count, groups, files: chips });
      if (!usable.length) { end(sv); $('survey').hidden = true; showNoLockfiles(source.name, w, items); DS.field.set({ mode: 'idle' }); compactHero(false); return; }
      const pl = await DS.picker.payload(source.name, items);
      stage('read', 'done', 'Read in your browser: ' + plural(usable.length, 'lockfile') + ', ' + fmtN(count) + ' entries');
      ['lic', 'osv', 'pol'].forEach((id) => stage(id, 'run'));
      sv.set({ sub: plural(count, 'package') + ' in ' + plural(usable.length, 'lockfile') + ', sent as ' + fmtBytes(pl.sent) + (pl.encoding ? ' compressed' : '') + (pl.slim ? ' (trimmed to the fields depscan reads)' : '') });
      source.files = usable.map((i) => i.path);
      const headers = { 'Content-Type': 'application/json' };
      if (pl.encoding) headers['Content-Encoding'] = pl.encoding;
      await send(source, sv, signal, () => fetch('/scans/upload', { method: 'POST', headers, body: pl.body, signal }));
    } catch (e) {
      end(sv); $('survey').hidden = true;
      if (e.name === 'AbortError') { toast('Scan cancelled'); DS.field.set({ mode: 'idle' }); compactHero(!!app.entry); return; }
      DS.field.set({ mode: 'idle' });
      showError({ message: e.message, code: e.code });
    }
  }

  async function send(source, sv, signal, doFetch) {
    let res, data;
    try {
      res = await doFetch();
      try { data = await res.json(); } catch (e) { data = null; }
    } catch (e) {
      end(sv); $('survey').hidden = true; DS.field.set({ mode: 'idle' });
      if (e.name === 'AbortError') { toast('Scan cancelled'); compactHero(!!app.entry); return; }
      checkHealth();
      showError({ offline: true, message: e.message });
      return;
    }
    if (!res.ok && res.status !== 422) {
      end(sv); $('survey').hidden = true; DS.field.set({ mode: 'idle' });
      showError({ status: res.status, message: (data && data.error) || ('The server answered ' + res.status), path: source.path });
      return;
    }
    ['read', 'lic', 'osv', 'pol'].forEach((id) => stage(id, 'done'));
    $('svState').textContent = 'Survey complete';
    const ms = sv.ms();
    end(sv);
    const entry = { id: data.id, at: Date.parse(data.scanned_at) || Date.now(), label: source.kind === 'path' ? source.path : source.name, source, ms, record: data };
    const m = DS.model.build(data, app.policy);
    entry.summary = DS.model.summarize(m);
    DS.store.putScan(entry);
    await new Promise((r) => setTimeout(r, reduced() ? 0 : 420));
    $('survey').hidden = true;
    history.replaceState(null, '', '#scan/' + encodeURIComponent(entry.id));
    await showEntry(entry, { scroll: true, fresh: true });
  }

  async function showEntry(entry, opt) {
    opt = opt || {};
    app.entry = entry;
    compactHero(true);
    $('scanError').innerHTML = '';
    const [reviews, all] = await Promise.all([DS.store.reviewMap(), DS.store.listScans()]);
    const prevList = all.filter((e) => e.source && entry.source && e.source.key === entry.source.key && e.id !== entry.id && e.at < entry.at);
    const m = await DS.results.render($('results'), entry, { policy: app.policy, reviews, prev: prevList[0] || null, prevList, onRescan: rescan });
    app.fieldState = { mode: 'result', verdict: m.verdict, block: m.blockPkgs + m.licBlocks, warn: m.warnPkgs, seed: entry.id };
    DS.field.set(app.fieldState);
    if (opt.fresh) DS.field.sweep();
    document.title = (m.verdict === 'block' ? 'Blocked' : m.verdict === 'warn' ? 'Passes with warnings' : m.verdict === 'pass' ? 'Passes' : 'Nothing to scan') + ': ' + entry.label + ' · depscan';
    if (opt.scroll) $('results').scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'start' });
    renderRecent();
    buildRail();
  }

  /* ---------------- the rail beside a result ---------------- */
  let railIO = null;
  function buildRail() {
    const rail = $('rail'), parts = Array.from(document.querySelectorAll('#results [data-ch]'));
    if (railIO) railIO.disconnect();
    rail.innerHTML = parts.map((el, i) => '<button type="button" data-i="' + i + '" aria-label="' + esc(el.dataset.ch) + '"><span>' + esc(el.dataset.ch) + '</span><i></i></button>').join('');
    const btns = Array.from(rail.children);
    const seen = new Map();
    railIO = new IntersectionObserver((en) => {
      en.forEach((x) => seen.set(x.target, x.isIntersecting ? x.intersectionRatio : 0));
      let best = 0, bi = 0;
      parts.forEach((p, i) => { const r = seen.get(p) || 0; if (r > best) { best = r; bi = i; } });
      btns.forEach((b, i) => { b.classList.toggle('on', i === bi); if (i === bi) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current'); });
    }, { threshold: [0, 0.1, 0.25, 0.5, 0.75, 1], rootMargin: '-20% 0px -30% 0px' });
    parts.forEach((p) => railIO.observe(p));
    rail.onclick = (e) => { const b = e.target.closest('[data-i]'); if (b) parts[+b.dataset.i].scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'start' }); };
    setRail(parts.length > 1);
  }
  function setRail(on) { $('rail').hidden = !on || app.route !== 'scan'; }

  /* ---------------- errors ---------------- */
  function showNoLockfiles(name, w, items) {
    const other = Array.from((w && w.other) || []).map(([k, v]) => k + ' (' + v.slice(0, 2).join(', ') + (v.length > 2 ? ', …' : '') + ')');
    const tips = [];
    if (items && items.some((i) => i.problem)) items.filter((i) => i.problem).forEach((i) => tips.push('<code>' + esc(i.path) + '</code> ' + esc(i.problem)));
    if (w && w.noLock && w.noLock.length) tips.push('Found <code>package.json</code> without a <code>package-lock.json</code> in ' + esc(w.noLock.slice(0, 3).join(', ')) + '. Run <code>npm install</code> there to create the lockfile.');
    if (other.length) tips.push('Found other lockfiles depscan cannot read yet: ' + esc(other.join('; ')) + '.');
    if (w && w.truncated) tips.push('The folder is very large, so the search stopped after ' + fmtN(w.dirs) + ' folders. Pick the project folder itself rather than a parent.');
    $('scanError').innerHTML = '<div class="alert" role="alert" style="--c:var(--medium)"><b>No go.mod or package-lock.json in ' + esc(name) + '</b><p>depscan scans Go modules and npm lockfiles (npm 7 or newer). It looked through ' + plural((w && w.dirs) || 0, 'folder') + ', skipping .git, vendor and node_modules.</p>' + (tips.length ? '<ul>' + tips.map((t) => '<li>' + t + '</li>').join('') + '</ul>' : '') + '<div class="row"><button class="btn btn-primary" type="button" data-pick>Choose another folder</button></div></div>';
  }
  function showError(e) {
    let title = 'The scan did not finish', body = '<p>' + esc(e.message) + '</p>', actions = '';
    const msg = String(e.message || '');
    if (e.offline) {
      title = 'The depscan server is not reachable';
      body = '<p>The page could not connect to <span class="mono">' + esc(location.host) + '</span>. Start the server from the project folder, then try again:</p>' + codeBlock('make run-server', 'command');
    } else if (/scan root/i.test(msg)) {
      title = 'This server cannot read that folder';
      body = '<p>Scans by path only work inside <span class="mono">' + esc(ROOT) + '</span>, so a web page can never make the server read the rest of your disk. Choose the folder instead: that works for any folder on any drive.</p>';
      actions = '<button class="btn btn-primary" type="button" data-pick>Choose the folder</button>';
    } else if (/no such file|cannot find|not find|does not exist|The system cannot/i.test(msg)) {
      title = 'Folder not found';
      body = '<p>Nothing exists at <span class="mono">' + esc(e.path || '') + '</span>. Check the spelling, or choose the folder instead.</p>';
      actions = '<button class="btn btn-primary" type="button" data-pick>Choose the folder</button>';
    } else if (/OSV|querybatch|osv\.dev/i.test(msg)) {
      title = 'Could not get advisories from OSV.dev';
      body = '<p>depscan retried, then stopped rather than report a pass with missing data. Check your internet connection and scan again.</p><p class="mono" style="font-size:12.5px">' + esc(msg) + '</p>';
    } else if (e.status === 413 || e.code === 'too-large') {
      title = 'These lockfiles are too large to send';
      body = '<p>' + esc(msg) + '</p>';
    }
    $('scanError').innerHTML = '<div class="alert" role="alert"><b>' + title + '</b>' + body + '<div class="row">' + actions + '<button class="btn" type="button" data-dismiss>Dismiss</button></div></div>';
    compactHero(!!app.entry);
  }
  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-pick]')) { e.preventDefault(); pickFolder(); }
    if (e.target.closest('[data-dismiss]')) { $('scanError').innerHTML = ''; }
  });

  /* ---------------- choosing a folder ---------------- */
  async function pickFolder() {
    if (DS.picker.supportsDialog()) {
      let h;
      try { h = await DS.picker.chooseWithDialog(); }
      catch (e) { $('dirInput').click(); return; } // e.g. blocked in an iframe: use the input
      if (!h) return;
      const src = { kind: 'folder', key: sourceKey('folder', h.name), name: h.name };
      scanWalk(src, async (onP, sig) => { const w = await DS.picker.walkHandle(h, onP, sig); w.handle = h; return w; });
    } else $('dirInput').click();
  }
  $('dirInput').addEventListener('change', (e) => {
    const w = DS.picker.fromFileList(e.target.files);
    e.target.value = '';
    if (!w) return;
    scanWalk({ kind: 'folder', key: sourceKey('folder', w.name), name: w.name }, async () => w);
  });
  async function rescan(entry) {
    const s = entry.source || guessSource(entry.label);
    if (s.kind === 'path') { go('#scan'); scanPath(s.path || entry.label); return; }
    if (s.kind === 'folder') {
      const h = await DS.store.getHandle(s.key);
      if (h) {
        try {
          if (await DS.picker.reopen(h)) {
            scanWalk({ kind: 'folder', key: s.key, name: s.name }, async (onP, sig) => { const w = await DS.picker.walkHandle(h, onP, sig); w.handle = h; return w; });
            return;
          }
        } catch (e) { /* fall through to the picker */ }
      }
      toast('Choose the ' + s.name + ' folder again');
      pickFolder();
      return;
    }
    toast('Pull request scans run again when the pull request gets a new commit');
  }

  // Drag and drop, anywhere on the Scan page.
  let dragDepth = 0;
  const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
  addEventListener('dragenter', (e) => { if (!hasFiles(e) || app.route !== 'scan') return; e.preventDefault(); dragDepth++; document.body.classList.add('dragging'); });
  addEventListener('dragleave', (e) => { if (!hasFiles(e)) return; dragDepth = Math.max(0, dragDepth - 1); if (!dragDepth) { document.body.classList.remove('dragging'); $('drop').classList.remove('over'); } });
  addEventListener('dragover', (e) => { if (!hasFiles(e) || app.route !== 'scan') return; e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; $('drop').classList.toggle('over', !!e.target.closest('#drop')); });
  addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); dragDepth = 0; document.body.classList.remove('dragging'); $('drop').classList.remove('over');
    if (app.route !== 'scan' || controller) return;
    const run = DS.picker.startDrop(e);
    if (run) scanWalk({ kind: 'folder', key: 'folder:dropped', name: 'dropped folder' }, run);
  });

  /* ================================================================ recent projects */
  function latestPerSource(list, n) {
    const seen = new Set(), out = [];
    for (const e of list) { const k = (e.source && e.source.key) || e.id; if (seen.has(k)) continue; seen.add(k); out.push(e); if (out.length >= n) break; }
    return out;
  }
  const VCOL = { block: 'critical', warn: 'medium', pass: 'clean', empty: 'unknown' };
  const VWORD = { block: 'Blocked', warn: 'Warnings', pass: 'Passed', empty: 'Empty' };
  const kindIcon = (s) => (s && s.kind === 'pr' ? icon.pr : s && s.kind === 'folder' ? icon.folder : icon.path);
  async function renderRecent() {
    const all = await DS.store.listScans();
    const n = $('navHist'); n.hidden = !all.length; n.textContent = all.length > 99 ? '99+' : all.length;
    const list = latestPerSource(all, 6), el = $('recent');
    app.recentCount = list.length;
    syncWord();
    if (!list.length) { el.hidden = true; return; }
    el.hidden = false;
    el.innerHTML = '<div class="recent-head"><div><p class="eyebrow"><span class="ey-dot" aria-hidden="true"></span>Latest result per project</p><h2>Recent projects</h2></div><a href="#history">All history</a></div><div class="recent-list">' + list.map((e) => {
      const v = (e.summary && e.summary.verdict) || 'empty', s = e.source || guessSource(e.label);
      return '<div class="proj"><span class="proj-ic">' + kindIcon(s) + '</span><button class="proj-main" type="button" data-open="' + esc(e.id) + '" title="Open the last result"><b>' + esc(s.name || e.label) + '</b><span><i class="dot" style="--c:var(--' + VCOL[v] + ')"></i>' + VWORD[v] + ', ' + esc(ago(e.at)) + '</span></button>' +
        (s.kind !== 'pr' ? '<button class="icon-btn" type="button" data-rescan="' + esc(e.id) + '" aria-label="Scan ' + esc(s.name || e.label) + ' again" title="Scan again">' + icon.redo + '</button>' : '<span></span>') + '</div>';
    }).join('') + '</div>';
  }
  $('recent').addEventListener('click', async (e) => {
    const o = e.target.closest('[data-open]'); if (o) { go('#scan/' + encodeURIComponent(o.dataset.open)); return; }
    const r = e.target.closest('[data-rescan]'); if (r) { const en = await DS.store.getScan(r.dataset.rescan); if (en) rescan(en); }
  });

  /* ================================================================ history page */
  const hist = { q: '', v: 'all', confirm: '' };
  async function syncServer() {
    // Scans made by other tabs or by pull request webhooks live on the server
    // until it restarts; copy any we have not saved yet.
    try {
      const { res, data } = await getJSON('/scans');
      if (!res.ok || !Array.isArray(data)) return;
      const have = new Set((await DS.store.listScans()).map((e) => e.id));
      for (const rec of data) {
        if (!rec || !rec.id || have.has(rec.id)) continue;
        const entry = { id: rec.id, at: Date.parse(rec.scanned_at) || Date.now(), label: rec.path, source: guessSource(rec.path), ms: 0, record: rec };
        entry.summary = DS.model.summarize(DS.model.build(rec, app.policy));
        await DS.store.putScan(entry);
      }
    } catch (e) { /* offline: the saved history is still shown */ }
  }
  function spark(entries) {
    const pts = entries.slice(0, 24).reverse();
    if (pts.length < 2) return '<svg class="spark" viewBox="0 0 200 48" aria-hidden="true"><line x1="0" y1="40" x2="200" y2="40" stroke="var(--line-2)" stroke-dasharray="3 4"/></svg>';
    const max = Math.max(1, ...pts.map((e) => (e.summary ? e.summary.advisories : 0)));
    const x = (i) => 6 + i * (188 / (pts.length - 1)), y = (v) => 40 - (v / max) * 32;
    const line = pts.map((e, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(e.summary ? e.summary.advisories : 0).toFixed(1)).join(' ');
    return '<svg class="spark" viewBox="0 0 200 48" aria-hidden="true"><path d="' + line + '" fill="none" stroke="var(--text-2)" stroke-width="1.4" stroke-linejoin="round"/>' +
      pts.map((e, i) => '<circle cx="' + x(i).toFixed(1) + '" cy="' + y(e.summary ? e.summary.advisories : 0).toFixed(1) + '" r="3" fill="var(--' + VCOL[(e.summary && e.summary.verdict) || 'empty'] + ')"/>').join('') + '</svg>';
  }
  async function renderHistory(skipSync) {
    const root = $('historyRoot');
    if (!skipSync) { syncServer().then(() => renderHistory(true)); }
    const all = await DS.store.listScans();
    const usage = await DS.store.usage();
    let h = '<div class="page-head"><div><p class="eyebrow"><span class="ey-dot" aria-hidden="true"></span>' + (all.length ? plural(all.length, 'scan') + ' kept in this browser' : 'Kept in this browser') + '</p><h1 class="h1" id="histTitle">History</h1><p class="lede">Every scan you run is saved in this browser, so it is still here after you close the tab, restart the server or turn the computer off. Open a scan to see its full result, or compare it with an earlier scan of the same project.</p></div>' +
      '<div class="page-actions"><button class="btn btn-sm" type="button" id="hExport"' + (all.length ? '' : ' disabled') + '>' + icon.download + 'Export</button><button class="btn btn-sm" type="button" id="hImport">Import</button>' +
      (all.length ? '<button class="btn btn-sm" type="button" id="hClear">' + (hist.confirm === 'all' ? 'Click again to delete ' + plural(all.length, 'scan') : 'Delete all') + '</button>' : '') + '<input type="file" id="hFile" accept="application/json,.json" hidden></div></div>';
    if (!DS.store.persistent) h += '<div class="note" style="--c:var(--medium);margin-bottom:24px"><span class="dot" style="--c:var(--medium)"></span><span><b>This browser is not keeping history.</b> It blocks storage in this window (private browsing often does). Scans stay until you close the tab; export them to keep them.</span></div>';
    if (!all.length) {
      h += '<div class="empty"><b>No scans yet</b><span>Scan a project and it shows up here, with its full result.</span><div style="margin-top:16px"><a class="btn btn-primary" href="#scan">Scan a project</a></div></div>';
      root.innerHTML = h; wireHistory(all); return;
    }
    // Projects: one card per source.
    const groups = new Map();
    all.forEach((e) => { const k = (e.source && e.source.key) || e.id; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(e); });
    h += '<div class="sec-head"><div><h2>Projects</h2><p>The trend line is the number of advisories in each scan; dots show the verdict.</p></div></div><div class="projects">' +
      Array.from(groups.values()).slice(0, 12).map((list) => {
        const e = list[0], s = e.source || guessSource(e.label), v = (e.summary && e.summary.verdict) || 'empty', sm = e.summary || {};
        return '<div class="pcard"><div class="pcard-top"><span class="proj-ic">' + kindIcon(s) + '</span><div style="min-width:0"><b>' + esc(s.name || e.label) + '</b><span>' + plural(list.length, 'scan') + ', last ' + esc(ago(e.at)) + '</span></div></div>' +
          spark(list) + '<div class="pcard-foot"><span><i class="dot" style="--c:var(--' + VCOL[v] + ')"></i> ' + VWORD[v] + ', ' + fmtN(sm.advisories || 0) + ' advisories</span><span class="row"><button class="btn btn-sm" type="button" data-open="' + esc(e.id) + '">Open</button>' +
          (s.kind !== 'pr' ? '<button class="btn btn-sm" type="button" data-rescan="' + esc(e.id) + '">Scan again</button>' : '') + '</span></div></div>';
      }).join('') + '</div>';

    // Timeline
    const q = hist.q.trim().toLowerCase();
    const rows = all.filter((e) => (hist.v === 'all' || (e.summary && e.summary.verdict) === hist.v) && (!q || (e.label || '').toLowerCase().includes(q) || ((e.source && e.source.name) || '').toLowerCase().includes(q)));
    h += '<div class="sec-head" style="margin-top:8px"><div><h2>All scans</h2></div></div><div class="toolbar"><label class="search">' + icon.search + '<span class="sr">Search scans</span><input id="hQ" value="' + esc(hist.q) + '" placeholder="Search by project or path" autocomplete="off"></label>' +
      '<div class="seg" id="hSeg" role="group">' + [['all', 'All'], ['block', 'Blocked'], ['warn', 'Warnings'], ['pass', 'Passed']].map(([v, l]) => '<button type="button" data-v="' + v + '" aria-pressed="' + (hist.v === v) + '">' + l + '</button>').join('') + '</div><span class="grow"></span><span class="count-line">' + plural(rows.length, 'scan') + '</span></div>';
    const days = new Map();
    rows.forEach((e) => { const d = new Date(e.at), k = d.toDateString(); if (!days.has(k)) days.set(k, []); days.get(k).push(e); });
    const today = new Date().toDateString(), yest = new Date(Date.now() - 86400000).toDateString();
    days.forEach((list, k) => {
      h += '<div class="tl-day"><h3>' + (k === today ? 'Today' : k === yest ? 'Yesterday' : new Date(k).toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })) + '</h3>' + list.map((e) => {
        const s = e.source || guessSource(e.label), v = (e.summary && e.summary.verdict) || 'empty', sm = e.summary || {};
        const where = s.kind === 'pr' ? 'Pull request' : s.kind === 'folder' ? 'Picked folder' + (s.files && s.files.length ? ', ' + plural(s.files.length, 'lockfile') : '') : (s.path || e.label);
        return '<div class="hrow"><span class="ic">' + kindIcon(s) + '</span><button class="nm" type="button" data-open="' + esc(e.id) + '"><b>' + esc(s.name || e.label) + '</b><span>' + esc(where) + '</span></button>' +
          '<span class="vd"><i class="dot" style="--c:var(--' + VCOL[v] + ')"></i>' + VWORD[v] + '<span class="small" style="color:var(--muted)">' + esc(new Date(e.at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })) + (e.ms ? ', ' + fmtMs(e.ms) : '') + '</span></span>' +
          '<span class="ct">' + plural(sm.deps || 0, 'package') + ', ' + fmtN(sm.vulnPkgs || 0) + ' with advisories' + (sm.blockPkgs ? ', <b style="color:var(--critical-t);font-weight:500">' + sm.blockPkgs + ' blocking</b>' : '') + '</span>' +
          '<span class="act"><button class="icon-btn" type="button" data-del="' + esc(e.id) + '" aria-label="' + (hist.confirm === e.id ? 'Confirm delete' : 'Delete this scan') + '" title="' + (hist.confirm === e.id ? 'Click again to delete' : 'Delete') + '"' + (hist.confirm === e.id ? ' style="color:var(--critical-t);background:color-mix(in srgb,var(--critical) 14%,transparent)"' : '') + '>' + icon.trash + '</button></span></div>';
      }).join('') + '</div>';
    });
    if (!rows.length) h += '<div class="empty"><b>No scans match</b>Clear the search or the filter.</div>';
    h += '<p class="store-line"><span>' + plural(all.length, 'scan') + ' saved in this browser' + (usage && usage.usage ? ', about ' + fmtBytes(usage.usage) : '') + '.</span><span>Keeps the newest ' + DS.store.KEEP + '.</span><span>Export to move them to another browser or computer.</span></p>';
    root.innerHTML = h;
    wireHistory(all);
  }
  function wireHistory(all) {
    const root = $('historyRoot');
    root.onclick = async (e) => {
      const o = e.target.closest('[data-open]'); if (o) { go('#scan/' + encodeURIComponent(o.dataset.open)); return; }
      const r = e.target.closest('[data-rescan]'); if (r) { const en = await DS.store.getScan(r.dataset.rescan); if (en) { go('#scan'); rescan(en); } return; }
      const d = e.target.closest('[data-del]');
      if (d) {
        const id = d.dataset.del;
        if (hist.confirm === id) { hist.confirm = ''; await DS.store.deleteScan(id); toast('Scan deleted'); }
        else { hist.confirm = id; clearTimeout(hist.t); hist.t = setTimeout(() => { hist.confirm = ''; renderHistory(true); }, 4000); }
        renderHistory(true); return;
      }
    };
    const q = $('hQ'); if (q) q.oninput = () => { const pos = q.selectionStart; hist.q = q.value; renderHistory(true).then(() => { const n = $('hQ'); if (n) { n.focus(); n.setSelectionRange(pos, pos); } }); };
    const seg = $('hSeg'); if (seg) seg.onclick = (e) => { const b = e.target.closest('button'); if (b) { hist.v = b.dataset.v; renderHistory(true); } };
    const ex = $('hExport'); if (ex) ex.onclick = async () => { const data = await DS.store.exportAll(); download('depscan-history-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(data), 'application/json'); toast('Exported ' + plural(data.scans.length, 'scan')); };
    const im = $('hImport'), file = $('hFile');
    if (im) im.onclick = () => file.click();
    if (file) file.onchange = async () => {
      const f = file.files[0]; file.value = ''; if (!f) return;
      try { const n = await DS.store.importAll(JSON.parse(await f.text())); toast('Imported ' + plural(n, 'scan')); renderHistory(true); }
      catch (err) { toast(err.message || 'That file could not be read', 'bad'); }
    };
    const cl = $('hClear');
    if (cl) cl.onclick = async () => {
      if (hist.confirm === 'all') { hist.confirm = ''; await DS.store.clearScans(); toast('History deleted'); }
      else { hist.confirm = 'all'; clearTimeout(hist.t); hist.t = setTimeout(() => { hist.confirm = ''; renderHistory(true); }, 4000); }
      renderHistory(true);
    };
  }

  /* ================================================================ policy page */
  const SEV_ORDER = ['CRITICAL', 'HIGH', 'MODERATE', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const sevTone = (s) => ({ CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' }[s] || 'unknown');
  const pchip = (label, tone) => '<span class="chip" style="--c:var(--' + tone + ');--t:var(--' + tone + '-t)">' + esc(label) + '</span>';
  async function renderPolicy() {
    const root = $('policyRoot');
    if (!app.policy) await loadPolicy();
    const p = app.policy;
    let h = '<div class="page-head"><div><p class="eyebrow"><span class="ey-dot" aria-hidden="true"></span>policy.yaml, digest ' + esc(p.digest.slice(0, 12)) + '</p><h1 class="h1" id="polTitle">Policy</h1><p class="lede">The rules this server applies to every scan. They come from <code>policy.yaml</code>, read when the server started. Commit the same file to your repository and CI judges pull requests by exactly these rules.</p></div>' +
      (p ? '<div class="page-actions"><span class="chip chip-line mono" title="SHA-256 of the loaded policy">sha256 ' + esc(p.digest.slice(0, 12)) + '</span></div>' : '') + '</div>';
    if (!p) { root.innerHTML = h + '<div class="alert" style="--c:var(--medium)"><b>The policy could not be loaded</b><p>' + esc(app.policyErr) + '</p></div>'; return; }
    const sevs = (list) => SEV_ORDER.filter((s) => (list || []).map((x) => String(x).toUpperCase()).includes(s)).map((s) => pchip(s, sevTone(s))).join('') || '<span class="small">None</span>';
    const rule = (title, about, key, val) => '<div class="rule"><dt>' + title + '<small>' + about + ' <span class="yaml-key">' + key + '</span></small></dt><dd>' + val + '</dd></div>';
    const today = new Date().toISOString().slice(0, 10);
    const excs = (p.exceptions || []).map((e) => {
      const expired = e.expires && e.expires < today, days = e.expires ? Math.floor((Date.parse(e.expires + 'T23:59:59Z') - Date.now()) / 86400000) : null;
      const st = !e.expires ? pchip('No expiry', 'unknown') : expired ? pchip('Expired ' + e.expires, 'critical') : days <= 30 ? pchip('Expires in ' + plural(days, 'day'), 'medium') : pchip('Active until ' + e.expires, 'clean');
      return '<div class="exc"><b><a class="xlink" href="' + esc(DS.links.advisory(e.id)) + '" target="_blank" rel="noopener noreferrer">' + esc(e.id) + '</a></b>' + st + '<p>' + esc(e.reason) + '</p></div>';
    }).join('');
    h += '<div class="pol-grid">' +
      '<section class="pol-card"><h2>Vulnerabilities</h2><p>What happens to an advisory, by the severity OSV.dev reports for it.</p><dl class="rules">' +
        rule('Blocks the build', 'Any of these fails the scan and CI.', 'block_severities', sevs(p.block_severities)) +
        rule('Warns', 'Shown, but the build passes.', 'warn_severities', sevs(p.warn_severities)) +
        rule('Unrated advisories', 'Records with no severity, like most GO- entries.', 'block_unknown_severity', p.block_unknown_severity ? pchip('Block', 'critical') : pchip('Allowed', 'clean')) +
        rule('Transitive packages', 'Packages you did not add yourself.', 'check_transitive', p.check_transitive ? pchip('Checked', 'clean') : pchip('Ignored', 'medium')) +
      '</dl></section>' +
      '<section class="pol-card"><h2>Licenses</h2><p>Looked up on deps.dev for every package version.</p><dl class="rules">' +
        rule('License lookups', 'Turn off for offline runs.', 'skip_license_check', p.skip_license_check ? pchip('Off', 'medium') : pchip('On', 'clean')) +
        rule('Unknown licenses', 'deps.dev has no SPDX license.', 'block_unknown_license', p.block_unknown_license ? pchip('Block', 'critical') : pchip('Warn', 'medium')) +
        rule('Denied', plural(p.denied_licenses.length, 'license') + '. Expressions count: "MIT OR GPL-3.0-only" passes.', 'denied_licenses', p.denied_licenses.map((l) => pchip(l, 'critical')).join('') || '<span class="small">None</span>') +
      '</dl></section>' +
      '<section class="pol-card pol-wide"><h2>Exceptions</h2><p>Advisories you accepted on purpose. Each needs a reason; one with an expiry date applies through that whole day, then blocks again.</p>' +
        (excs || '<p class="small">No exceptions. Add one under <span class="mono">exceptions:</span> when an advisory cannot affect you.</p>') + '</section>' +
      '<section class="pol-card"><h2>Try a rule</h2><p>Pick an advisory and see what this policy does with it.</p><div class="sim"><select class="select" id="simSev" aria-label="Severity">' + ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'].map((s) => '<option value="' + s + '">' + (s === 'UNKNOWN' ? 'Unrated' : s.charAt(0) + s.slice(1).toLowerCase()) + '</option>').join('') + '</select>' +
        '<select class="select" id="simScope" aria-label="Scope"><option value="direct">Direct package</option><option value="trans">Transitive package</option></select>' +
        '<input class="field-in mono" id="simId" placeholder="Advisory ID (optional)" style="max-width:240px;min-height:40px" autocomplete="off"></div><div class="sim-out" id="simOut"></div></section>' +
      '<section class="pol-card"><h2>When a scan stops</h2><dl class="rules">' +
        rule('Stop at the first violation', 'Faster, but you only see one problem.', 'fail_fast', p.fail_fast ? pchip('On', 'medium') : pchip('Off', 'clean')) +
        rule('Violation limit', 'Stop after this many. 0 means no limit.', 'max_violations', pchip(p.max_violations ? String(p.max_violations) : 'No limit', 'unknown')) +
      '</dl></section>' +
      '<section class="pol-card pol-wide"><h2>Change a rule</h2><p>Edit <code>policy.yaml</code>, then restart the server (Ctrl+C, then <code>make run-server</code>). Commit the change so CI uses it too.</p><div class="cols">' +
        '<div class="stack"><h4 class="small">Accept an advisory for 90 days</h4>' + codeBlock('exceptions:\n  - id: GHSA-xxxx-xxxx-xxxx\n    reason: "Explain why this does not affect us"\n    expires: "' + new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10) + '"', 'exception') + '</div>' +
        '<div class="stack"><h4 class="small">Fail CI on unknown licenses</h4>' + codeBlock('block_unknown_license: true', 'setting') + '<h4 class="small">Also block moderate advisories</h4>' + codeBlock('block_severities:\n  - CRITICAL\n  - HIGH\n  - MODERATE', 'setting') + '</div></div></section>' +
      '</div>';
    root.innerHTML = h;
    const sim = () => {
      const raw = $('simSev').value, trans = $('simScope').value === 'trans', id = $('simId').value.trim();
      const exc = id ? (p.exceptions || []).find((e) => e.id.toLowerCase() === id.toLowerCase() && (!e.expires || e.expires >= today)) : null;
      const inL = (l) => (l || []).map((x) => String(x).toUpperCase()).includes(raw);
      let out, tone;
      if (trans && !p.check_transitive) { out = '<b>Ignored.</b> It is transitive and <span class="mono">check_transitive</span> is off.'; tone = 'unknown'; }
      else if (exc) { out = '<b>Allowed by an exception.</b> ' + esc(exc.reason) + (exc.expires ? ' (until ' + esc(exc.expires) + ')' : ''); tone = 'unknown'; }
      else if (raw === 'UNKNOWN' ? p.block_unknown_severity : inL(p.block_severities)) { out = '<b>Blocks the build.</b> ' + (raw === 'UNKNOWN' ? '<span class="mono">block_unknown_severity</span> is on.' : raw + ' is in <span class="mono">block_severities</span>.') + ' CI fails and the API answers 422.'; tone = 'critical'; }
      else if (inL(p.warn_severities) || (raw === 'MODERATE' && inL(p.warn_severities))) { out = '<b>Warns.</b> ' + raw + ' is in <span class="mono">warn_severities</span>. The build passes.'; tone = 'medium'; }
      else { out = '<b>Allowed.</b> ' + (raw === 'UNKNOWN' ? 'Unrated advisories are not blocked.' : raw + ' is in neither list.') + ' It still shows under Fixes as below your threshold.'; tone = 'clean'; }
      const o = $('simOut'); o.innerHTML = out; o.style.setProperty('--c', 'var(--' + tone + ')'); o.style.setProperty('--t', 'var(--' + tone + '-t)');
    };
    ['simSev', 'simScope'].forEach((id) => $(id).addEventListener('change', sim));
    $('simId').addEventListener('input', sim);
    $('simSev').value = 'HIGH'; sim();
  }

  /* ================================================================ wiring */
  $('pickBtn').addEventListener('click', pickFolder);
  $('pathForm').addEventListener('submit', (e) => { e.preventDefault(); scanPath(); });
  $('pathIn').placeholder = ROOT ? ROOT + SEP + 'your-project' : 'Path to a project folder';
  $('pathHint').innerHTML = ROOT ? 'This server can read folders inside <code>' + esc(ROOT) + '</code>. For any other folder, choose it above.' : '';
  $('statusBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    const pop = $('statusPop'), open = pop.hidden;
    pop.hidden = !open; $('statusBtn').setAttribute('aria-expanded', String(open));
    if (open) { renderStatus(); checkHealth(); }
  });
  document.addEventListener('click', (e) => { const pop = $('statusPop'); if (!pop.hidden && !pop.contains(e.target)) { pop.hidden = true; $('statusBtn').setAttribute('aria-expanded', 'false'); } });
  $('themeBtn').addEventListener('click', () => { const cur = $('themeBtn').dataset.mode || 'system'; applyTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]); });
  $('motionBtn').addEventListener('click', () => applyMotion($('motionBtn').getAttribute('aria-pressed') === 'true'));
  addEventListener('keydown', (e) => {
    const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
    if (e.key === 'Escape' && controller && !DS.sheet.isOpen) { cancelScan(); return; }
    if (app.route !== 'scan' || typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === '/') { e.preventDefault(); $('pathIn').focus(); $('pathIn').select(); }
  });
  addEventListener('scroll', () => { $('bar').classList.toggle('solid', scrollY > 8); }, { passive: true });
  addEventListener('resize', () => moveNav(true));

  // Small screens: the sections slide in from the right.
  function setMenu(open) {
    document.documentElement.classList.toggle('menu-open', open);
    $('menuBtn').setAttribute('aria-expanded', String(open));
    $('menuBtn').setAttribute('aria-label', open ? 'Close the menu' : 'Menu');
  }
  $('menuBtn').addEventListener('click', () => setMenu(!document.documentElement.classList.contains('menu-open')));
  addEventListener('keydown', (e) => { if (e.key === 'Escape' && document.documentElement.classList.contains('menu-open')) setMenu(false); });
  $('cue').addEventListener('click', () => $('recent').scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'start' }));

  // A ring that follows the pointer and opens over things you can press.
  (function cursor() {
    const el = $('cursor');
    if (!matchMedia('(pointer: fine)').matches || !matchMedia('(hover: hover)').matches) return;
    let x = -100, y = -100, cx = -100, cy = -100, raf = 0, shown = false;
    const HOT = 'a, button, [role="tab"], [role="slider"], summary, label[for], .drow, .proj-main, .peek, canvas#skyCanvas';
    const TEXT = 'input, textarea, select, [contenteditable], .sheet-panel, .learn, pre, code';
    const step = () => {
      raf = 0;
      const k = reduced() || document.documentElement.classList.contains('still') ? 1 : 0.22;
      cx += (x - cx) * k; cy += (y - cy) * k;
      el.style.transform = 'translate3d(' + cx.toFixed(1) + 'px,' + cy.toFixed(1) + 'px,0)';
      if (Math.abs(x - cx) > 0.3 || Math.abs(y - cy) > 0.3) raf = requestAnimationFrame(step);
    };
    addEventListener('pointermove', (e) => {
      if (e.pointerType !== 'mouse') return;
      x = e.clientX; y = e.clientY;
      if (!shown) { shown = true; cx = x; cy = y; document.documentElement.classList.add('has-cursor'); }
      const t = e.target;
      el.classList.toggle('off', !!(t.closest && t.closest(TEXT)));
      el.classList.toggle('hot', !!(t.closest && t.closest(HOT)));
      if (!raf) raf = requestAnimationFrame(step);
    }, { passive: true });
    addEventListener('pointerdown', () => el.classList.add('down'));
    addEventListener('pointerup', () => el.classList.remove('down'));
    document.documentElement.addEventListener('mouseleave', () => { document.documentElement.classList.remove('has-cursor'); shown = false; });
  })();

  // The walkthrough preview on the landing view: one frame from the result step.
  function drawPeek() {
    const demo = window.DepscanDemo, c = $('peekCanvas');
    if (!demo || !demo.thumb || !c || !c.offsetWidth) return;
    const ch = demo.chapters.find((x) => /verdict|result|report/i.test(x.title)) || demo.chapters[Math.floor(demo.chapters.length / 2)];
    demo.thumb(c, ch.start + ch.dur * 0.9);
    const m = Math.round(demo.total);
    $('peekLen').textContent = demo.chapters.length + ' steps, ' + Math.floor(m / 60) + ':' + String(m % 60).padStart(2, '0');
  }
  new ResizeObserver(() => drawPeek()).observe($('peekCanvas'));

  // The intro counts real start-up work: fonts, saved history, the server, the policy.
  const intro = (() => {
    const d = document.documentElement, on = d.classList.contains('intro');
    const left = new Map([['fonts', 'Loading the typefaces'], ['store', 'Opening your scan history'], ['server', 'Reaching the depscan server'], ['policy', 'Reading your policy']]);
    let done = 0, shownPct = 0, raf = 0;
    const total = left.size, t0 = performance.now();
    const paint = () => {
      raf = 0;
      const target = Math.round(done / total * 100);
      shownPct += Math.max(1, Math.round((target - shownPct) * 0.24));
      if (shownPct > target) shownPct = target;
      $('ldPct').textContent = shownPct; $('ldBar').style.transform = 'scaleX(' + (shownPct / 100) + ')';
      if (shownPct < target) raf = requestAnimationFrame(paint);
      else if (done >= total) setTimeout(() => { d.classList.remove('intro'); try { sessionStorage.setItem('depscan.intro', '1'); } catch (e) { /* storage blocked */ } }, Math.max(250, 1100 - (performance.now() - t0)));
    };
    return {
      step(key) {
        if (!on || !left.has(key)) return;
        left.delete(key); done++;
        $('ldStep').textContent = left.size ? left.values().next().value : 'Ready';
        if (!raf) raf = requestAnimationFrame(paint);
      }
    };
  })();
  document.addEventListener('depscan:store', () => { renderRecent(); if (app.route === 'history') renderHistory(true); });
  // From the Learn panel and the walkthrough.
  document.addEventListener('depscan:watch', (e) => { go('#how'); if (window.DepscanDemo) window.DepscanDemo.goChapter(e.detail.chapter, true); });
  document.addEventListener('depscan:try', () => { go('#scan'); setTimeout(() => { $('source').scrollIntoView({ behavior: reduced() ? 'auto' : 'smooth', block: 'center' }); $('pickBtn').focus({ preventScroll: true }); }, 120); });
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[href^="#"]');
    if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    const href = a.getAttribute('href');
    if (href === '#main') return;
    e.preventDefault(); go(href);
    if (href === '#scan' && !app.entry) scrollTo({ top: 0, behavior: reduced() ? 'auto' : 'smooth' });
  });

  let theme = 'system';
  try { theme = localStorage.getItem('depscan.theme') || 'system'; } catch (e) { /* storage blocked */ }
  applyTheme(THEMES.includes(theme) ? theme : 'system');
  applyMotion(!document.documentElement.classList.contains('still'));
  DS.splitWords($('scanTitle'));
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => moveNav(true));

  (async () => {
    (document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve()).then(() => intro.step('fonts'));
    await DS.store.ready();
    intro.step('store');
    DS.store.persist();
    await Promise.all([loadPolicy().then(() => intro.step('policy')), checkHealth().then(() => intro.step('server'))]);
    renderRecent();
    route(true);
    drawPeek();
    syncServer();
    setInterval(() => { if (!document.hidden) checkHealth(); }, 60000);
  })();
})();
