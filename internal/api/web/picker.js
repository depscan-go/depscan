/* Picking a project folder in the browser.

   Browsers never tell a page a folder's real path, so instead of a path the
   page walks the folder itself, keeps only the lockfiles depscan understands,
   and sends those to POST /scans/upload. Three ways in:
     - the system folder dialog (showDirectoryPicker in Chrome and Edge, a
       webkitdirectory file input everywhere else),
     - dragging a folder onto the page,
     - a saved folder handle, to scan the same folder again in one click.
   The walk skips the same folders the server skips: .git, vendor, node_modules. */
(function () {
  'use strict';
  const DS = (window.DS = window.DS || {});

  // Keep in sync with internal/parser and uploadable in internal/api/upload.go.
  const LOCKFILES = ['go.mod', 'package-lock.json'];
  const SKIP = new Set(['node_modules', 'vendor', '.git']);
  const OTHER = {
    'yarn.lock': 'Yarn', 'pnpm-lock.yaml': 'pnpm', 'bun.lockb': 'Bun', 'bun.lock': 'Bun', 'npm-shrinkwrap.json': 'npm shrinkwrap',
    'Cargo.lock': 'Rust', 'requirements.txt': 'Python', 'poetry.lock': 'Python', 'Pipfile.lock': 'Python', 'uv.lock': 'Python',
    'Gemfile.lock': 'Ruby', 'composer.lock': 'PHP', 'pom.xml': 'Maven', 'build.gradle': 'Gradle', 'build.gradle.kts': 'Gradle', 'go.work': 'Go workspace'
  };
  const MAX_DIRS = 60000, MAX_DEPTH = 32;
  // The server wraps every request in a 1 MB limit; stay a little under it.
  const LIMIT = (1 << 20) - 8192;

  const supportsDialog = () => typeof window.showDirectoryPicker === 'function';
  const abortError = () => new DOMException('Cancelled', 'AbortError');

  function newWalk(name) {
    return { name, found: [], dirs: 0, skipped: [], other: new Map(), pkgJson: new Set(), truncated: false };
  }
  function noteFile(w, name, rel, getFile) {
    if (LOCKFILES.includes(name)) { w.found.push({ path: rel, getFile }); return; }
    if (name === 'package.json') { w.pkgJson.add(rel.slice(0, -'package.json'.length)); return; }
    if (OTHER[name]) { const k = OTHER[name]; if (!w.other.has(k)) w.other.set(k, []); w.other.get(k).push(rel); }
  }
  function finish(w) {
    w.found.sort((a, b) => a.path.split('/').length - b.path.split('/').length || a.path.localeCompare(b.path));
    // package.json with no package-lock.json next to it cannot be scanned.
    const locks = new Set(w.found.filter((f) => f.path.endsWith('package-lock.json')).map((f) => f.path.slice(0, -'package-lock.json'.length)));
    w.noLock = Array.from(w.pkgJson).filter((d) => !locks.has(d)).map((d) => (d || './'));
    return w;
  }

  // Walks a FileSystemDirectoryHandle (dialog, drop or saved handle).
  async function walkHandle(root, onProgress, signal) {
    const w = newWalk(root.name);
    const stack = [[root, '']];
    while (stack.length) {
      if (signal && signal.aborted) throw abortError();
      const [dir, prefix] = stack.pop();
      if (++w.dirs > MAX_DIRS) { w.truncated = true; break; }
      if (onProgress && w.dirs % 40 === 0) onProgress(w);
      for await (const [name, h] of dir.entries()) {
        const rel = prefix ? prefix + '/' + name : name;
        if (h.kind === 'directory') {
          if (SKIP.has(name)) { if (w.skipped.length < 200) w.skipped.push(rel); continue; }
          if (rel.split('/').length < MAX_DEPTH) stack.push([h, rel]);
        } else noteFile(w, name, rel, () => h.getFile());
      }
    }
    return finish(w);
  }

  // Walks a FileSystemDirectoryEntry from a drop in browsers without handles.
  async function walkEntry(root, onProgress, signal) {
    const w = newWalk(root.name);
    const readAll = (dir) => new Promise((resolve, reject) => {
      const reader = dir.createReader(), out = [];
      const next = () => reader.readEntries((batch) => { if (!batch.length) resolve(out); else { out.push(...batch); next(); } }, reject);
      next();
    });
    const stack = [[root, '']];
    while (stack.length) {
      if (signal && signal.aborted) throw abortError();
      const [dir, prefix] = stack.pop();
      if (++w.dirs > MAX_DIRS) { w.truncated = true; break; }
      if (onProgress && w.dirs % 40 === 0) onProgress(w);
      for (const e of await readAll(dir)) {
        const rel = prefix ? prefix + '/' + e.name : e.name;
        if (e.isDirectory) {
          if (SKIP.has(e.name)) { if (w.skipped.length < 200) w.skipped.push(rel); continue; }
          if (rel.split('/').length < MAX_DEPTH) stack.push([e, rel]);
        } else noteFile(w, e.name, rel, () => new Promise((res, rej) => e.file(res, rej)));
      }
    }
    return finish(w);
  }

  // A webkitdirectory input hands over every file at once, node_modules included.
  function fromFileList(list) {
    const files = Array.from(list || []);
    if (!files.length) return null;
    const first = files[0].webkitRelativePath || files[0].name;
    const w = newWalk(first.split('/')[0]);
    const dirs = new Set();
    for (const f of files) {
      const parts = (f.webkitRelativePath || f.name).split('/').slice(1);
      if (!parts.length) continue;
      const skip = parts.slice(0, -1).findIndex((p) => SKIP.has(p));
      if (skip >= 0) { const s = parts.slice(0, skip + 1).join('/'); if (w.skipped.length < 200 && !w.skipped.includes(s)) w.skipped.push(s); continue; }
      for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
      noteFile(w, parts[parts.length - 1], parts.join('/'), () => Promise.resolve(f));
    }
    w.dirs = dirs.size + 1;
    return finish(w);
  }

  // Starts reading a drop. Must be called synchronously inside the drop event:
  // the browser forgets the dropped items once the event returns.
  function startDrop(e) {
    const items = Array.from((e.dataTransfer && e.dataTransfer.items) || []).filter((i) => i.kind === 'file');
    if (!items.length) return null;
    const handles = items.map((i) => (i.getAsFileSystemHandle ? i.getAsFileSystemHandle() : null));
    const entries = items.map((i) => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
    const files = items.map((i) => i.getAsFile());
    return async (onProgress, signal) => {
      // One folder: walk it, and keep its handle when the browser offers one.
      if (items.length === 1) {
        const h = handles[0] ? await handles[0].catch(() => null) : null;
        if (h && h.kind === 'directory') { const w = await walkHandle(h, onProgress, signal); w.handle = h; return w; }
        if (entries[0] && entries[0].isDirectory) return walkEntry(entries[0], onProgress, signal);
      }
      // Loose files: keep the lockfiles among them.
      const w = newWalk(files.length === 1 && files[0] ? files[0].name.replace(/\.[^.]+$/, '') : 'dropped files');
      files.forEach((f) => { if (f) noteFile(w, f.name, f.name, () => Promise.resolve(f)); });
      if (entries.some((x) => x && x.isDirectory)) w.mixed = true;
      return finish(w);
    };
  }

  async function chooseWithDialog() {
    try { return await window.showDirectoryPicker({ id: 'depscan-project', mode: 'read' }); }
    catch (e) { if (e && e.name === 'AbortError') return null; throw e; }
  }
  // A saved handle needs the user's permission again in each new session.
  async function reopen(handle) {
    if (!handle || !handle.queryPermission) return false;
    let p = await handle.queryPermission({ mode: 'read' });
    if (p === 'prompt') p = await handle.requestPermission({ mode: 'read' });
    return p === 'granted';
  }

  /* ---------- reading lockfiles ---------- */
  function analyzeGoMod(text) {
    const mod = (text.match(/^\s*module\s+("?)([^\s"]+)\1/m) || [])[2] || '';
    const names = [];
    let direct = 0, inBlock = false;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\/\/(?!\s*indirect).*$/, '').trim();
      if (!line) continue;
      if (inBlock) { if (line.startsWith(')')) { inBlock = false; continue; } }
      else if (/^require\s*\($/.test(line)) { inBlock = true; continue; }
      else if (/^require\s+/.test(line)) { /* single-line require, handled below */ }
      else continue;
      const body = inBlock ? line : line.replace(/^require\s+/, '');
      const m = body.match(/^("?)([^\s"]+)\1\s+(\S+)/);
      if (!m) continue;
      names.push(m[2] + '@' + m[3]);
      if (!/\/\/\s*indirect/.test(raw)) direct++;
    }
    return { kind: 'go', module: mod, count: names.length, direct, names };
  }
  function analyzeLock(text) {
    let o;
    try { o = JSON.parse(text); } catch (e) { return { kind: 'npm', count: 0, names: [], problem: 'is not valid JSON, so the server will skip it.' }; }
    if (!o || !o.packages || (o.lockfileVersion || 0) < 2) {
      return { kind: 'npm', count: 0, names: [], skip: true, problem: 'uses lockfileVersion ' + (o && o.lockfileVersion) + ' (npm 6). Run npm install with npm 7 or newer to upgrade it; depscan reads version 2 and 3.' };
    }
    const root = o.packages[''] || {}, direct = new Set(Object.keys(root.dependencies || {}).concat(Object.keys(root.devDependencies || {})));
    const seen = new Set(), names = [];
    let d = 0;
    for (const [p, v] of Object.entries(o.packages)) {
      if (!p || !v || v.link || !v.version) continue;
      const i = p.lastIndexOf('node_modules/');
      const name = i < 0 ? '' : p.slice(i + 13);
      if (!name) continue;
      const key = name + '@' + v.version;
      if (seen.has(key)) continue;
      seen.add(key); names.push(key);
      if (p === 'node_modules/' + name && direct.has(name)) d++;
    }
    return { kind: 'npm', module: o.name || '', count: names.length, direct: d, names };
  }
  async function readAll(found, signal) {
    const out = [];
    for (const f of found) {
      if (signal && signal.aborted) throw abortError();
      const file = await f.getFile();
      const text = await file.text();
      const info = f.path.endsWith('go.mod') ? analyzeGoMod(text) : analyzeLock(text);
      out.push(Object.assign({ path: f.path, size: file.size, text }, info));
    }
    return out;
  }

  /* ---------- the upload body ---------- */
  const canGzip = typeof window.CompressionStream === 'function';
  async function gzip(str) {
    const stream = new Blob([str]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Response(stream).blob();
  }
  // Only the fields internal/parser reads (plus a few small ones), and package
  // maps only for the root entry. Used when a lockfile is too big to send whole.
  function slimLock(text) {
    const o = JSON.parse(text), pk = {};
    const keep = ['version', 'link', 'dev', 'optional', 'devOptional', 'peer', 'license'];
    for (const [k, v] of Object.entries(o.packages || {})) {
      const n = {};
      keep.forEach((f) => { if (v && v[f] !== undefined) n[f] = v[f]; });
      if (k === '') { ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].forEach((f) => { if (v && v[f]) n[f] = v[f]; }); }
      pk[k] = n;
    }
    return JSON.stringify({ name: o.name, version: o.version, lockfileVersion: o.lockfileVersion, packages: pk });
  }
  async function payload(name, items) {
    const send = items.filter((i) => !i.skip);
    const build = (slim) => JSON.stringify({ name, files: send.map((i) => ({ path: i.path, content: slim && i.kind === 'npm' ? slimLock(i.text) : i.text })) });
    let json = build(false), slim = false;
    const raw = new Blob([json]).size;
    let body = json, encoding = '', size = raw;
    if (canGzip) { body = await gzip(json); size = body.size; encoding = 'gzip'; }
    if (size > LIMIT) {
      slim = true; json = build(true);
      if (canGzip) { body = await gzip(json); size = body.size; } else { body = json; size = new Blob([json]).size; }
    }
    if (size > LIMIT) {
      const err = new Error('These lockfiles are ' + DS.fmtBytes(size) + ' even compressed, over the server\'s 1 MB request limit. Scan this project by path instead, or with the depscan command line tool.');
      err.code = 'too-large'; throw err;
    }
    return { body, encoding, raw, sent: size, slim, files: send.length };
  }

  DS.picker = { LOCKFILES, SKIP, supportsDialog, chooseWithDialog, reopen, walkHandle, fromFileList, startDrop, readAll, payload, canGzip, LIMIT };
})();
