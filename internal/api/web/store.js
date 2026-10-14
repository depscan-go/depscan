/* History, license reviews and folder handles, saved in this browser with
   IndexedDB, so they survive closing the tab, restarting the server and
   rebooting the machine. The server keeps its own copy too, in its database
   when it has one (DATABASE_URL).

   Stores (database "depscan", version 1):
     scans    one entry per scan: { id, at, label, source, ms, record, summary }
     reviews  one entry per reviewed package: { key, decision, license, note, by, at }
     handles  folder handles (Chrome, Edge) so a picked folder can be scanned
              again without choosing it: { key, handle }

   If IndexedDB is unavailable (some private windows), everything still works
   for this visit, from memory, and the page says history will not be kept. */
(function () {
  'use strict';
  const DS = (window.DS = window.DS || {});
  const NAME = 'depscan', VERSION = 1, KEEP = 300;
  const mem = { scans: new Map(), reviews: new Map(), handles: new Map() };
  let dbp = null, persistent = true;

  function open() {
    if (dbp) return dbp;
    dbp = new Promise((resolve) => {
      let rq;
      try { rq = indexedDB.open(NAME, VERSION); } catch (e) { persistent = false; resolve(null); return; }
      rq.onupgradeneeded = () => {
        const db = rq.result;
        if (!db.objectStoreNames.contains('scans')) {
          const s = db.createObjectStore('scans', { keyPath: 'id' });
          s.createIndex('at', 'at');
          s.createIndex('source', 'source.key');
        }
        if (!db.objectStoreNames.contains('reviews')) db.createObjectStore('reviews', { keyPath: 'key' });
        if (!db.objectStoreNames.contains('handles')) db.createObjectStore('handles', { keyPath: 'key' });
      };
      rq.onsuccess = () => {
        const db = rq.result;
        db.onversionchange = () => db.close(); // another tab is upgrading
        resolve(db);
      };
      rq.onerror = () => { persistent = false; resolve(null); };
      rq.onblocked = () => { /* waits for other tabs; onsuccess follows */ };
    });
    return dbp;
  }

  // Runs fn(store) in a transaction and resolves with the request's result.
  async function run(name, mode, fn) {
    const db = await open();
    if (!db) return fn(null);
    return new Promise((resolve, reject) => {
      let out;
      try {
        const tx = db.transaction(name, mode);
        const rq = fn(tx.objectStore(name));
        if (rq && 'onsuccess' in rq) rq.onsuccess = () => { out = rq.result; };
        tx.oncomplete = () => resolve(out);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error('transaction aborted'));
      } catch (e) { reject(e); }
    });
  }
  const all = (name) => run(name, 'readonly', (s) => (s ? s.getAll() : null)).then((v) => v || Array.from(mem[name].values()));

  async function putScan(entry) {
    mem.scans.set(entry.id, entry);
    try {
      await run('scans', 'readwrite', (s) => s && s.put(entry));
      await prune();
    } catch (e) {
      // Quota or a closed database: keep it in memory for this visit.
      DS.toast && DS.toast('History is full or unavailable, so this scan is kept until you close the tab', 'bad');
    }
    emit();
    return entry;
  }
  async function prune() {
    const list = await listScans();
    if (list.length <= KEEP) return;
    const old = list.slice(KEEP);
    await run('scans', 'readwrite', (s) => { if (s) old.forEach((x) => s.delete(x.id)); return null; });
    old.forEach((x) => mem.scans.delete(x.id));
  }
  async function listScans() {
    const list = await all('scans');
    return list.sort((a, b) => b.at - a.at);
  }
  async function getScan(id) {
    if (mem.scans.has(id)) return mem.scans.get(id);
    const v = await run('scans', 'readonly', (s) => (s ? s.get(id) : null));
    return v || null;
  }
  async function deleteScan(id) {
    mem.scans.delete(id);
    await run('scans', 'readwrite', (s) => s && s.delete(id));
    emit();
  }
  async function clearScans() {
    mem.scans.clear();
    await run('scans', 'readwrite', (s) => s && s.clear());
    emit();
  }

  async function putReview(r) {
    mem.reviews.set(r.key, r);
    await run('reviews', 'readwrite', (s) => s && s.put(r)).catch(() => {});
    emit('reviews');
    return r;
  }
  async function deleteReview(key) {
    mem.reviews.delete(key);
    await run('reviews', 'readwrite', (s) => s && s.delete(key)).catch(() => {});
    emit('reviews');
  }
  async function reviewMap() {
    const list = await all('reviews').catch(() => Array.from(mem.reviews.values()));
    return new Map(list.map((r) => [r.key, r]));
  }

  async function putHandle(key, handle) {
    mem.handles.set(key, { key, handle });
    try { await run('handles', 'readwrite', (s) => s && s.put({ key, handle })); } catch (e) { /* handles are a convenience */ }
  }
  async function getHandle(key) {
    if (mem.handles.has(key)) return mem.handles.get(key).handle;
    try { const v = await run('handles', 'readonly', (s) => (s ? s.get(key) : null)); return v ? v.handle : null; } catch (e) { return null; }
  }

  async function exportAll() {
    const [scans, reviews] = await Promise.all([listScans(), all('reviews')]);
    return { format: 'depscan-history', version: 1, exported_at: new Date().toISOString(), scans, reviews };
  }
  async function importAll(data) {
    if (!data || data.format !== 'depscan-history' || !Array.isArray(data.scans)) throw new Error('This is not a depscan history file.');
    let n = 0;
    for (const s of data.scans) {
      if (!s || !s.id || !s.record || typeof s.at !== 'number') continue;
      mem.scans.set(s.id, s);
      await run('scans', 'readwrite', (st) => st && st.put(s)); n++;
    }
    for (const r of data.reviews || []) {
      if (!r || !r.key) continue;
      mem.reviews.set(r.key, r);
      await run('reviews', 'readwrite', (st) => st && st.put(r));
    }
    await prune();
    emit(); emit('reviews');
    return n;
  }

  async function usage() {
    try { if (navigator.storage && navigator.storage.estimate) return await navigator.storage.estimate(); } catch (e) { /* not supported */ }
    return null;
  }
  // Ask the browser not to evict this data under storage pressure.
  async function persist() {
    try { if (navigator.storage && navigator.storage.persist) return await navigator.storage.persist(); } catch (e) { /* not supported */ }
    return false;
  }

  function emit(kind) { document.dispatchEvent(new CustomEvent('depscan:store', { detail: { kind: kind || 'scans' } })); }

  DS.store = {
    ready: () => open().then((db) => !!db),
    get persistent() { return persistent; },
    putScan, listScans, getScan, deleteScan, clearScans,
    putReview, deleteReview, reviewMap,
    putHandle, getHandle,
    exportAll, importAll, usage, persist, KEEP
  };
})();
