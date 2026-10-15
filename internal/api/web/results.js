/* The result of one scan: verdict, an ordered plan, the risk map, and the
   Fixes, Licenses, Dependencies and Changes tabs, plus the side sheets for a
   package and for a license review. Reads the server's scan record and, when
   available, the policy from GET /policy to explain every decision. */
(function () {
  'use strict';
  const DS = (window.DS = window.DS || {});
  const { $, esc, plural, fmtN, fmtMs, ago, when, toast, download, slug, SEVS, SEV, sevOf, sevRank, sevColor, nv, cmpVer, maxVer,
    licUnknown, licCheck, licFamily, FAM, SPDX_COMMON, depKey, purl, links, cmd, icon, ext, codeBlock, countUp, sheet } = DS;

  /* ================================================================ model */
  const STATUS = {
    block: { label: 'Blocks', long: 'Blocks the build', c: 'critical' },
    warn: { label: 'Warns', long: 'Warning', c: 'medium' },
    excepted: { label: 'Excepted', long: 'Excepted by your policy', c: 'unknown' },
    below: { label: 'Below threshold', long: 'Below your policy threshold', c: 'low' },
    transitive: { label: 'Not checked', long: 'Not checked: transitive', c: 'unknown' },
    stopped: { label: 'Not evaluated', long: 'Not evaluated', c: 'unknown' },
    clean: { label: 'Clean', long: 'No known advisories', c: 'clean' }
  };
  const ORDER = ['block', 'warn', 'excepted', 'stopped', 'transitive', 'below', 'clean'];

  function inList(list, s) { return (list || []).some((x) => String(x).toUpperCase() === s); }
  function policyBlocks(p, raw) { return raw === 'UNKNOWN' ? !!p.block_unknown_severity : inList(p.block_severities, raw); }
  function policyWarns(p, raw) { return inList(p.warn_severities, raw); }
  function activeException(p, a) {
    if (!p) return null;
    const ids = [a.id].concat(a.aliases || []);
    const today = new Date().toISOString().slice(0, 10);
    for (const e of p.exceptions || []) {
      if (!ids.includes(e.id)) continue;
      if (e.expires && e.expires < today) continue; // valid through its expiry day (UTC)
      return e;
    }
    return null;
  }

  function build(record, policy) {
    const r = (record && record.result) || {};
    const rawDeps = r.Deps || [], findings = r.Findings || [], viol = r.Violations || [], warns = r.Warnings || [];
    const vkey = (v) => depKey(v.Dep) + '#' + (v.ID || '');
    const blockV = new Set(viol.filter((v) => v.Kind === 'vulnerability').map(vkey));
    const warnV = new Set(warns.filter((v) => v.Kind === 'vulnerability').map(vkey));
    const licBlock = new Map(viol.filter((v) => v.Kind === 'license').map((v) => [depKey(v.Dep), v.Reason]));
    const licWarn = new Map(warns.filter((v) => v.Kind === 'license').map((v) => [depKey(v.Dep), v.Reason]));
    const stoppedEarly = !!policy && ((policy.fail_fast && viol.length > 0) || (policy.max_violations > 0 && viol.length >= policy.max_violations));

    const pkgs = new Map();
    const add = (d) => {
      const k = depKey(d);
      let p = pkgs.get(k);
      if (!p) { p = { key: k, dep: Object.assign({}, d), seen: 0, advs: [] }; pkgs.set(k, p); }
      return p;
    };
    rawDeps.forEach((d) => { const p = add(d); p.seen++; if (d.Direct) p.dep.Direct = true; if (!p.dep.License && d.License) p.dep.License = d.License; });

    for (const f of findings) {
      const p = add(f.Dep);
      if (p.advs.some((a) => a.id === f.VulnID)) continue;
      const raw = String(f.Severity || 'UNKNOWN').toUpperCase();
      const a = { id: f.VulnID, aliases: (f.Aliases || []).filter((x) => x !== f.VulnID), sev: sevOf(raw), raw, summary: f.Summary || '', fixed: f.FixedVersion || '', modified: f.Modified || '' };
      const id = p.key + '#' + a.id;
      if (blockV.has(id)) a.status = 'block';
      else if (warnV.has(id)) a.status = 'warn';
      else if (!policy) a.status = 'below';
      else if (!policy.check_transitive && !p.dep.Direct) a.status = 'transitive';
      else if ((a.exc = activeException(policy, a))) a.status = 'excepted';
      else if (stoppedEarly && (policyBlocks(policy, raw) || policyWarns(policy, raw))) a.status = 'stopped';
      else a.status = 'below';
      p.advs.push(a);
    }

    let advCount = 0;
    const bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    const byStatus = { block: 0, warn: 0, excepted: 0, stopped: 0, transitive: 0, below: 0 };
    const fams = {};
    for (const p of pkgs.values()) {
      p.advs.sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status) || sevRank(a.sev) - sevRank(b.sev) || a.id.localeCompare(b.id));
      p.worst = p.advs.reduce((w, a) => (sevRank(a.sev) < sevRank(w) ? a.sev : w), 'NONE');
      p.status = p.advs.length ? p.advs.reduce((s, a) => (ORDER.indexOf(a.status) < ORDER.indexOf(s) ? a.status : s), 'clean') : 'clean';
      const active = p.advs.filter((a) => a.status === 'block' || a.status === 'warn');
      p.pool = active.length ? active : p.advs;
      p.fixTo = maxVer(p.pool.map((a) => a.fixed));
      p.unfixed = p.pool.filter((a) => !a.fixed);
      p.cleared = p.fixTo ? p.pool.filter((a) => a.fixed && cmpVer(a.fixed, p.fixTo) <= 0) : [];
      p.score = p.advs.reduce((s, a) => s + SEV[a.sev].w, 0);
      p.activeScore = active.reduce((s, a) => s + SEV[a.sev].w, 0);
      advCount += p.advs.length;
      p.advs.forEach((a) => { bySev[a.sev]++; byStatus[a.status]++; });

      const lic = p.dep.License || '';
      p.lic = { expr: lic, fam: licFamily(lic), unknown: licUnknown(lic) };
      if (licBlock.has(p.key)) { p.lic.status = p.lic.unknown ? 'unknown-block' : 'denied'; p.lic.reason = licBlock.get(p.key); }
      else if (licWarn.has(p.key)) { p.lic.status = 'unknown-warn'; p.lic.reason = licWarn.get(p.key); }
      else if (p.lic.unknown) p.lic.status = policy && policy.skip_license_check ? 'skipped' : 'unknown-warn';
      else p.lic.status = 'ok';
      if (p.lic.status === 'denied' && policy) p.lic.denied = licCheck(lic, policy.denied_licenses).denied;
      fams[p.lic.fam] = (fams[p.lic.fam] || 0) + 1;
    }

    const list = Array.from(pkgs.values());
    const eco = {};
    list.forEach((p) => { eco[p.dep.Ecosystem] = (eco[p.dep.Ecosystem] || 0) + 1; });
    const m = {
      record, policy, list, pkgs, findings, viol, warns, stoppedEarly,
      direct: list.filter((p) => p.dep.Direct).length,
      vulnPkgs: list.filter((p) => p.advs.length).length,
      blockPkgs: list.filter((p) => p.status === 'block').length,
      warnPkgs: list.filter((p) => p.status === 'warn').length,
      advCount, bySev, byStatus, fams, eco,
      licDenied: list.filter((p) => p.lic.status === 'denied').length,
      licUnknown: list.filter((p) => p.lic.status === 'unknown-warn' || p.lic.status === 'unknown-block').length,
      licBlocks: list.filter((p) => p.lic.status === 'denied' || p.lic.status === 'unknown-block').length,
      skipLicense: !!(policy && policy.skip_license_check)
    };
    m.verdict = viol.length ? 'block' : warns.length ? 'warn' : list.length ? 'pass' : 'empty';
    return m;
  }

  // The few numbers History keeps per scan, so it never re-parses old records.
  function summarize(m) {
    return {
      verdict: m.verdict, deps: m.list.length, direct: m.direct, vulnPkgs: m.vulnPkgs, blockPkgs: m.blockPkgs, warnPkgs: m.warnPkgs,
      advisories: m.advCount, licDenied: m.licDenied, licUnknown: m.licUnknown, bySev: m.bySev, eco: m.eco
    };
  }

  /* ================================================================ wording */
  const VERDICT = {
    block: { word: 'Blocked', state: 'Fails your policy', c: 'critical' },
    warn: { word: 'Passes', state: 'Passes your policy, with warnings', c: 'medium' },
    pass: { word: 'Passes', state: 'Passes your policy', c: 'clean' },
    empty: { word: 'Nothing to scan', state: 'No lockfiles found', c: 'unknown' }
  };
  const list = (arr) => arr.length < 2 ? arr.join('') : arr.slice(0, -1).join(', ') + ' and ' + arr[arr.length - 1];
  const sevNames = (arr) => list((arr || []).map((s) => String(s).toUpperCase()));
  function verdictWhy(m) {
    const p = m.policy;
    if (m.verdict === 'empty') return 'depscan found no <code>go.mod</code> or <code>package-lock.json</code> (npm 7 or newer) here. Other lockfiles are skipped.';
    if (m.verdict === 'block') {
      const parts = [];
      if (m.blockPkgs) parts.push('<b>' + plural(m.blockPkgs, 'package') + '</b> ' + (m.blockPkgs === 1 ? 'has' : 'have') + ' advisories your policy blocks' + (p ? ' (' + esc(sevNames(p.block_severities)) + ')' : ''));
      if (m.licBlocks) parts.push('<b>' + plural(m.licBlocks, 'license') + '</b> ' + (m.licBlocks === 1 ? 'is' : 'are') + (m.licDenied ? ' denied' : ' unknown and your policy blocks unknown licenses'));
      return parts.join(', and ') + '. ' + (m.blockPkgs ? 'The plan below lists the upgrades that clear it.' : 'Replace them, or change the rule in your policy.');
    }
    if (m.verdict === 'warn') {
      const parts = [];
      if (m.warnPkgs) parts.push(plural(m.warnPkgs, 'package') + ' with advisories your policy warns about');
      if (m.licUnknown) parts.push(plural(m.licUnknown, 'license') + ' deps.dev could not identify');
      return 'Nothing blocks the build. There ' + (m.warnPkgs + m.licUnknown === 1 ? 'is ' : 'are ') + list(parts) + ', worth fixing before they become blocking.';
    }
    const below = m.vulnPkgs;
    return below ? 'No package breaks your policy. ' + plural(below, 'package') + ' ' + (below === 1 ? 'has' : 'have') + ' advisories below your threshold, listed under Fixes.' : 'Every package was checked against OSV.dev and none has a known advisory.';
  }
  function advWhy(a, dep, p) {
    const s = a.raw === 'UNKNOWN' ? 'No severity published' : a.raw;
    switch (a.status) {
      case 'block': return a.raw === 'UNKNOWN' ? 'No severity published, and <span class="mono">block_unknown_severity</span> is on' : '<b>' + esc(s) + '</b> is in <span class="mono">block_severities</span>';
      case 'warn': return '<b>' + esc(s) + '</b> is in <span class="mono">warn_severities</span>';
      case 'excepted': return 'Excepted' + (a.exc.expires ? ' until ' + esc(a.exc.expires) : '') + ': ' + esc(a.exc.reason);
      case 'transitive': return 'Transitive, and <span class="mono">check_transitive</span> is off';
      case 'stopped': return 'Not evaluated: the policy stopped early (' + (p && p.fail_fast ? '<span class="mono">fail_fast</span>' : '<span class="mono">max_violations</span>') + ')';
      default:
        if (!p) return 'Allowed by your policy';
        return a.raw === 'UNKNOWN' ? 'No severity published, and <span class="mono">block_unknown_severity</span> is off' : '<b>' + esc(s) + '</b> is not in <span class="mono">block_severities</span> or <span class="mono">warn_severities</span>';
    }
  }

  /* ================================================================ small renderers */
  const chip = (label, c, cls) => '<span class="chip ' + (cls || '') + '" style="--c:var(--' + c + ');--t:var(--' + c + '-t)">' + label + '</span>';
  const sevChip = (sev, n) => chip((n != null ? n + ' ' : '') + SEV[sev].label.toLowerCase(), SEV[sev].v);
  const statusChip = (st) => chip(STATUS[st].label, STATUS[st].c);
  function sevChips(advs) {
    const c = {}; advs.forEach((a) => { c[a.sev] = (c[a.sev] || 0) + 1; });
    return SEVS.filter((s) => c[s]).map((s) => sevChip(s, c[s])).join('');
  }
  const famChip = (fam) => '<span class="chip" style="--c:var(--' + FAM[fam].v + ');--t:var(--text-2)"><span class="d"></span>' + FAM[fam].label + '</span>';
  const scope = (d) => (d.Direct ? 'direct' : 'transitive');
  const ecoName = (e) => (e === 'Go' ? 'Go module' : e === 'npm' ? 'npm package' : e);
  const pkgName = (d) => esc(d.Name) + '<em>@' + esc(d.Version) + '</em>';
  const idLinks = (a) => {
    const ids = [a.id].concat(a.aliases);
    return ids.map((id, i) => '<a class="' + (i ? 'alias' : '') + '" href="' + esc(links.advisory(id)) + '" target="_blank" rel="noopener noreferrer">' + esc(id) + '</a>').join('') +
      '<a class="alias" href="' + esc(links.osv(a.id)) + '" target="_blank" rel="noopener noreferrer">OSV record</a>';
  };
  const RV = { approved: { label: 'Approved', cls: 'rv-approved' }, rejected: { label: 'Rejected', cls: 'rv-rejected' }, legal: { label: 'Needs legal review', cls: 'rv-legal' } };

  /* ================================================================ plan */
  function planSteps(m, reviews) {
    const steps = [];
    const byRisk = (a, b) => b.activeScore - a.activeScore || sevRank(a.worst) - sevRank(b.worst) || a.dep.Name.localeCompare(b.dep.Name);
    m.list.filter((p) => p.status === 'block').sort(byRisk).forEach((p) => steps.push({ kind: 'block', p }));
    m.list.filter((p) => p.lic.status === 'denied' || p.lic.status === 'unknown-block').forEach((p) => steps.push({ kind: 'lic-block', p }));
    m.list.filter((p) => p.status === 'warn').sort(byRisk).forEach((p) => steps.push({ kind: 'warn', p }));
    const unknown = m.list.filter((p) => p.lic.status === 'unknown-warn');
    if (unknown.length) steps.push({ kind: 'lic-review', n: unknown.length, done: unknown.filter((p) => reviews.has(p.key)).length });
    const soon = m.policy ? (m.policy.exceptions || []).filter((e) => e.expires && daysTo(e.expires) >= 0 && daysTo(e.expires) <= 30) : [];
    if (soon.length) steps.push({ kind: 'exc', list: soon });
    return steps;
  }
  function daysTo(ymd) { return Math.floor((Date.parse(ymd + 'T23:59:59Z') - Date.now()) / 86400000); }

  // Steps can be ticked off; this browser remembers them per scan (see planDone).
  const stepKey = (s) => (s.p ? s.kind + ':' + s.p.key : s.kind);
  function stepHTML(s, i) {
    const key = stepKey(s), done = !!(cur && cur.done && cur.done.has(key));
    const n = '<button class="step-n step-tick" type="button" data-step="' + esc(key) + '" aria-pressed="' + done + '" aria-label="Step ' + (i + 1) + ' done" title="Tick off when done"><span class="sn">' + String(i + 1).padStart(2, '0') + '</span>' + icon.check + '</button>';
    const li = (cls) => '<li class="step ' + cls + (done ? ' done' : '') + '" data-key="' + esc(key) + '">';
    if (s.kind === 'block' || s.kind === 'warn') {
      const p = s.p, d = p.dep;
      let title, act = '', meta = sevChips(p.pool);
      if (p.fixTo) {
        title = 'Upgrade <span class="mono">' + esc(d.Name) + '</span> <span class="from">from ' + esc(d.Version) + '</span> to <span class="mono">' + esc(p.fixTo) + '</span>';
        const npmT = d.Ecosystem === 'npm' && !d.Direct;
        const shown = npmT ? '"' + d.Name + '": "' + p.fixTo + '"' : cmd.upgrade(d, p.fixTo);
        const copied = npmT ? cmd.override(d, p.fixTo) : shown;
        act = '<div class="cmdline"><code title="' + (npmT ? 'Add under &quot;overrides&quot; in package.json, then run npm install' : '') + '">' + esc(shown) + '</code><button class="copy-btn" type="button" data-copy="' + esc(copied) + '" data-copy-label="' + (npmT ? 'Copied the override for package.json' : 'Copied: ' + esc(shown)) + '">' + icon.copy + (npmT ? 'Copy override' : 'Copy') + '</button></div>';
        meta += '<span class="small">' + (p.unfixed.length ? 'fixes ' + p.cleared.length + ' of ' + p.pool.length + '; ' + p.unfixed.length + ' still have no fix' : (p.pool.length === 1 ? 'fixes it' : 'fixes all ' + p.pool.length)) + (d.Direct ? '' : '. Transitive' + (d.Ecosystem === 'npm' ? ': add the override to package.json, then npm install' : ': go get still works')) + '</span>';
      } else {
        title = 'No fixed release yet for <span class="mono">' + esc(d.Name) + '@' + esc(d.Version) + '</span>';
        meta += '<span class="small">Replace it, or add a time-limited exception with a reason</span>';
      }
      act += '<button class="btn btn-sm" type="button" data-open-pkg="' + esc(p.key) + '">Details</button>';
      return li(s.kind) + n + '<div class="step-main"><p class="step-title">' + title + '</p><div class="step-meta">' + statusChip(p.status) + meta + '</div></div><div class="step-act">' + act + '</div></li>';
    }
    if (s.kind === 'lic-block') {
      const p = s.p;
      const what = p.lic.status === 'denied' ? 'uses <span class="mono">' + esc(p.lic.expr) + '</span>, which your policy denies' : 'has an unknown license, and your policy blocks unknown licenses';
      return li('block') + n + '<div class="step-main"><p class="step-title"><span class="mono">' + esc(p.dep.Name) + '</span> ' + what + '</p><div class="step-meta">' + chip('Blocks', 'critical') + '<span class="small">Replace or remove it, or change the license rule in policy.yaml</span></div></div><div class="step-act"><button class="btn btn-sm" type="button" data-review="' + esc(p.key) + '">Review</button></div></li>';
    }
    if (s.kind === 'lic-review') {
      return li('lic') + n + '<div class="step-main"><p class="step-title">Review ' + plural(s.n, 'license') + ' deps.dev could not identify</p><div class="step-meta">' + chip('Warns', 'medium') + '<span class="small">' + (s.done ? s.done + ' of ' + s.n + ' reviewed' : 'Find each real license and record a decision') + '</span></div></div><div class="step-act"><button class="btn btn-sm" type="button" data-tab-go="licenses">Open licenses</button></div></li>';
    }
    if (s.kind === 'exc') {
      return li('lic') + n + '<div class="step-main"><p class="step-title">' + plural(s.list.length, 'exception') + ' in your policy ' + (s.list.length === 1 ? 'expires' : 'expire') + ' within 30 days</p><div class="step-meta"><span class="small">' + s.list.map((e) => '<span class="mono">' + esc(e.id) + '</span> on ' + esc(e.expires)).join(', ') + '. Re-check them, then extend or remove the entries.</span></div></div><div class="step-act"><a class="btn btn-sm" href="#policy">Open policy</a></div></li>';
    }
    return '';
  }

  // Ticked-off plan steps, per scan, in this browser only. The newest 40 scans are kept.
  const PLAN_KEY = 'depscan.plan';
  function planDone(id) {
    try { const all = JSON.parse(localStorage.getItem(PLAN_KEY) || '{}'); return new Set((all[id] && all[id].k) || []); }
    catch (e) { return new Set(); }
  }
  function savePlanDone(id, set) {
    try {
      const all = JSON.parse(localStorage.getItem(PLAN_KEY) || '{}');
      if (set.size) all[id] = { k: Array.from(set), at: Date.now() }; else delete all[id];
      Object.keys(all).sort((a, b) => all[b].at - all[a].at).slice(40).forEach((x) => delete all[x]);
      localStorage.setItem(PLAN_KEY, JSON.stringify(all));
    } catch (e) { /* storage blocked: ticks last until the page closes */ }
  }
  function planProg(steps) {
    const n = steps.filter((s) => cur.done.has(stepKey(s))).length;
    return { n, pp: steps.length ? (n / steps.length).toFixed(3) : '0', text: n ? '<b>' + n + ' of ' + steps.length + '</b> done' + (n === steps.length ? '. Scan again to confirm.' : '') : 'Tick a step off when it is done; this browser remembers.' };
  }
  function planProgHTML(steps) {
    const g = planProg(steps);
    return '<i class="' + (g.n ? '' : 'off') + '" style="--pp:' + g.pp + '" aria-hidden="true"></i><span>' + g.text + '</span>';
  }
  function toggleStep(btn) {
    const key = btn.dataset.step, li = btn.closest('.step');
    if (cur.done.has(key)) cur.done.delete(key); else cur.done.add(key);
    const on = cur.done.has(key);
    btn.setAttribute('aria-pressed', String(on));
    if (li) li.classList.toggle('done', on);
    savePlanDone(cur.entry.id, cur.done);
    const pp = $('planProg');
    if (pp) { const g = planProg(planSteps(cur.m, cur.reviews)), bar = pp.querySelector('i'); bar.classList.toggle('off', !g.n); bar.style.setProperty('--pp', g.pp); pp.querySelector('span').innerHTML = g.text; }
  }

  // A pull request scan whose CycloneDX report the server anchored on Solana (DEPSCAN_ANCHOR=solana).
  const ICON_LINK = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M6.7 9.3a2.6 2.6 0 0 0 3.7 0l2.1-2.1a2.6 2.6 0 0 0-3.7-3.7l-.8.8M9.3 6.7a2.6 2.6 0 0 0-3.7 0L3.5 8.8a2.6 2.6 0 0 0 3.7 3.7l.8-.8" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
  function anchorHTML(entry) {
    const rp = entry.record && entry.record.report;
    if (!rp) return '';
    const a = rp.anchor;
    if (a && a.tx_id) {
      const how = 'The SHA-256 of this scan\'s CycloneDX report is in a Solana memo. Check any copy with: depscan verify' + (a.signer ? ' -signer ' + a.signer : '') + ' report.cdx.json';
      return '<span class="anc" title="' + esc(how) + '">' + ICON_LINK + '<span>Anchored on Solana ' + esc(a.network || '') + '</span>' +
        (/^https:\/\//.test(a.url || '') ? ext(a.url, 'tx ' + esc(a.tx_id.slice(0, 8)) + '…', 'xlink mono') : '<span class="mono">' + esc(a.tx_id.slice(0, 8)) + '…</span>') + '</span>' +
        '<span><button class="xlink rep-dl" type="button" data-report="' + esc(entry.id) + '">' + icon.download + 'Report</button></span>';
    }
    if (rp.anchor_error) return '<span class="anc bad" title="' + esc(rp.anchor_error) + '">Report not anchored</span>';
    return '';
  }
  async function downloadReport(id) {
    try {
      const res = await fetch('/scans/' + encodeURIComponent(id) + '/report', { cache: 'no-store' });
      if (!res.ok) throw new Error(String(res.status));
      download('report-' + slug(cur && cur.entry ? cur.entry.label : id) + '.cdx.json', await res.blob());
      toast('Report downloaded. Check it any time with depscan verify.');
    } catch (e) {
      toast('The server no longer has this report: it keeps reports until it restarts. The anchor is still on the ledger.', 'bad');
    }
  }
  // Scans copied before the server finished anchoring: ask once more, quietly.
  async function refreshAnchor(entry) {
    try {
      const res = await fetch('/scans/' + encodeURIComponent(entry.id), { cache: 'no-store' });
      if (!res.ok) return;
      const rec = await res.json();
      if (!rec || !rec.report || !cur || cur.entry !== entry) return;
      entry.record.report = rec.report;
      DS.store.putScan(entry);
      const slot = $('ancSlot'); if (slot) slot.outerHTML = anchorHTML(entry);
    } catch (e) { /* offline: nothing to add */ }
  }

  /* ================================================================ render */
  let cur = null; // { entry, m, ctx, tab, ui, sky }

  async function render(root, entry, ctx) {
    if (cur && cur.sky) cur.sky.destroy();
    const m = build(entry.record, ctx.policy);
    const reviews = ctx.reviews || new Map();
    cur = { root, entry, m, ctx, reviews, done: planDone(entry.id), tab: 'fixes', ui: { q: '', filter: 'all', sort: 'risk', shown: {}, open: new Set(), depQ: '', depScope: 'all', depEco: 'all', depStatus: 'any', depSort: ['status', 1], depShown: 100 } };
    const v = VERDICT[m.verdict], src = entry.source || {};
    const steps = planSteps(m, reviews);
    const dig = m.policy && m.policy.digest ? m.policy.digest.slice(0, 7) : '';
    const srcIcon = src.kind === 'pr' ? icon.pr : src.kind === 'folder' ? icon.folder : icon.path;
    const srcText = src.kind === 'pr' ? 'pull request' : src.kind === 'folder' ? 'picked folder' : 'path on this machine';
    const unknownLic = m.licUnknown, deniedLic = m.licDenied;

    let h = '<div class="verdict" data-ch="Verdict" style="--vc:var(--' + v.c + ');--vt:var(--' + v.c + '-t)">' +
      '<div><p class="eyebrow verdict-state"><span class="dot"></span>' + v.state + '</p>' +
      '<h2 class="verdict-word" data-split>' + v.word + '</h2>' +
      '<p class="verdict-why">' + verdictWhy(m) + '</p>' +
      '<div class="verdict-meta"><span>' + srcIcon + '<span><b>' + esc(entry.label) + '</b>, ' + srcText + '</span></span><span>Scanned ' + esc(when(entry.at)) + '</span>' + (entry.ms ? '<span>Took ' + fmtMs(entry.ms) + '</span>' : '') + (dig ? '<span>Policy <a class="xlink mono" href="#policy">' + dig + '</a></span>' : '') +
      (anchorHTML(entry) || (src.kind === 'pr' ? '<span id="ancSlot" hidden></span>' : '')) + '</div></div>' +
      '<div class="verdict-actions"><button class="btn" type="button" id="rescanBtn">' + icon.redo + 'Scan again</button>' +
      '<div class="menu-wrap"><button class="btn btn-primary" type="button" id="exportBtn" aria-expanded="false">' + icon.download + 'Export</button></div></div>' +
      '</div>';

    if (m.verdict !== 'empty') {
      const trans = m.list.length - m.direct;
      h += '<dl class="stats">' +
        stat('Packages', m.list.length, fmtN(m.direct) + ' direct, ' + fmtN(trans) + ' transitive', '', 'dependency', '<div class="splitbar" aria-hidden="true"><i style="flex:' + m.direct + ';background:var(--text)"></i><i style="flex:' + trans + ';background:var(--line-3)"></i></div>') +
        stat('With advisories', m.vulnPkgs, plural(m.advCount, 'advisory', 'advisories') + ' after merging duplicates', '', 'advisory') +
        stat('Blocking', m.blockPkgs + (m.licBlocks || 0), m.blockPkgs || m.licBlocks ? (m.blockPkgs ? plural(m.blockPkgs, 'package') + ' with advisories' : '') + (m.licBlocks ? (m.blockPkgs ? ', ' : '') + plural(m.licBlocks, 'license') : '') : 'Nothing breaks your policy', m.blockPkgs + m.licBlocks ? 'hot' : '', 'policy') +
        stat('Warnings', m.warnPkgs, m.warnPkgs ? 'Allowed, but worth upgrading' : 'No warnings', m.warnPkgs ? 'warm' : '', 'severity') +
        stat('Licenses to review', deniedLic + unknownLic, m.skipLicense ? 'License checks are off' : (deniedLic ? deniedLic + ' denied, ' : '') + unknownLic + ' unknown', deniedLic ? 'hot' : unknownLic ? 'warm' : '', 'license') +
        '</dl>';

      if (steps.length) {
        h += '<section aria-labelledby="planTitle" data-ch="Plan"><div class="sec-head"><div><p class="eyebrow"><span class="ey-dot" aria-hidden="true"></span>' + plural(steps.length, 'step') + ', ' + (steps[0].kind === 'block' || steps[0].kind === 'lic-block' ? 'blocking problems first' : steps[0].kind === 'warn' ? 'warnings first' : 'reviews to finish') + '</p><h2 id="planTitle">What to do, in order</h2><p>Blocking problems first, then warnings, then reviews. Each step says what it fixes; run the command, then scan again.</p><p class="plan-prog" id="planProg">' + planProgHTML(steps) + '</p></div>' +
          (steps.some((s) => (s.kind === 'block' || s.kind === 'warn') && s.p.fixTo) ? '<button class="btn btn-sm" type="button" id="copyAll">' + icon.copy + 'Copy all upgrade commands</button>' : '') + '</div>' +
          '<ol class="plan" id="plan">' + steps.slice(0, 6).map(stepHTML).join('') + '</ol>' +
          (steps.length > 6 ? '<button class="btn btn-sm plan-more" type="button" id="planMore">Show ' + (steps.length - 6) + ' more steps</button>' : '') + '</section>';
      }

      h += '<section class="overview" aria-labelledby="ovTitle" data-ch="Risk map"><div class="sec-head"><div><p class="eyebrow"><span class="ey-dot" aria-hidden="true"></span>' + fmtN(m.list.length) + ' packages, ' + fmtN(m.vulnPkgs) + ' with advisories' + '</p><h2 id="ovTitle">Where the risk sits</h2><p>Every package is a column: taller means more serious advisories. Hover or tap one to see it, click to open its details.</p></div></div>' +
        '<div class="overview-in">' + (m.list.length ? skyHTML(m) : '') + breakdownHTML(m) + '</div></section>';

      const fixN = m.list.filter((p) => p.advs.length).length;
      const licN = deniedLic + unknownLic;
      h += '<section aria-labelledby="dtTitle" data-ch="Details"><div class="sec-head"><div><p class="eyebrow"><span class="ey-dot" aria-hidden="true"></span>' + plural(fixN, 'package') + ' to fix, ' + plural(licN, 'license') + ' to review</p><h2 id="dtTitle">Every package, in detail</h2></div></div><div class="tabs" role="tablist" id="tabs">' +
        tabBtn('fixes', 'Fixes', fixN, m.blockPkgs ? 'hot' : m.warnPkgs ? 'warm' : '') +
        tabBtn('licenses', 'Licenses', licN, deniedLic ? 'hot' : unknownLic ? 'warm' : '') +
        tabBtn('deps', 'Dependencies', m.list.length, '') +
        (ctx.prev ? tabBtn('changes', 'Changes since last scan', '', '') : '') +
        '<span class="tab-bar" id="tabBar"></span></div><div class="panel" id="panel" role="tabpanel"></div></section>';
    }
    root.innerHTML = h;
    root.hidden = false;
    DS.splitWords(root.querySelector('.verdict-word'));
    countUp(root);
    wire(root);
    // The parts below the verdict settle in as they come into view; the hairlines above them are traced once.
    DS.reveal(root.querySelectorAll('.stats, .plan'), { line: true, rise: false });
    DS.reveal(root.querySelectorAll('.stat'), { offset: 1 });
    DS.reveal(root.querySelectorAll('#plan > .step'), { offset: 1 });
    DS.reveal(root.querySelectorAll('.overview .sec-head, .overview-in > *, [data-ch="Details"] > .sec-head, #tabs'));
    if (src.kind === 'pr' && !(entry.record && entry.record.report)) refreshAnchor(entry);

    if (m.verdict !== 'empty') {
      startSky(m);
      requestAnimationFrame(() => root.querySelectorAll('.brow .track i').forEach((i) => { i.style.width = i.dataset.w; }));
      const first = m.blockPkgs || m.warnPkgs ? 'fixes' : deniedLic + unknownLic ? 'licenses' : m.vulnPkgs ? 'fixes' : 'deps';
      setTab(ctx.tab || first);
    }
    return m;
  }

  function stat(k, n, sub, cls, topic, extra) {
    return '<div class="stat ' + (cls || '') + '"><dt>' + (topic ? '<button type="button" data-learn="' + topic + '">' + k + '</button>' : k) + '</dt><dd><span class="v" data-n="' + n + '">' + fmtN(n) + '</span><span class="s">' + sub + '</span>' + (extra || '') + '</dd></div>';
  }
  const tabBtn = (id, label, n, cls) => '<button class="tab" role="tab" type="button" data-tab="' + id + '" aria-selected="false">' + label + (n !== '' ? '<span class="n ' + cls + '">' + fmtN(n) + '</span>' : '') + '</button>';

  function breakdownHTML(m) {
    const maxSev = Math.max(1, ...SEVS.map((s) => m.bySev[s]));
    const sevRows = SEVS.map((s) => '<div class="brow"><span><i class="dot" style="--c:' + sevColor(s) + '"></i>' + SEV[s].label + '</span><span class="track"><i style="--c:' + sevColor(s) + '" data-w="' + (m.bySev[s] / maxSev * 100).toFixed(1) + '%"></i></span><b>' + m.bySev[s] + '</b></div>').join('');
    const st = m.byStatus;
    const stParts = ['block', 'warn', 'excepted', 'stopped', 'transitive', 'below'].filter((k) => st[k]);
    const stBar = m.advCount ? '<div class="stackbar">' + stParts.map((k) => '<i style="flex:' + st[k] + ';--c:var(--' + STATUS[k].c + ')" title="' + STATUS[k].long + ': ' + st[k] + '"></i>').join('') + '</div><div class="legend">' + stParts.map((k) => '<span><i style="--c:var(--' + STATUS[k].c + ')"></i>' + STATUS[k].long + ' <b>' + st[k] + '</b></span>').join('') + '</div>' : '<p class="small">No advisories in this project.</p>';
    const famKeys = Object.keys(FAM).filter((f) => m.fams[f]).sort((a, b) => FAM[a].rank - FAM[b].rank);
    const famBar = '<div class="stackbar">' + famKeys.map((f) => '<i style="flex:' + m.fams[f] + ';--c:var(--' + FAM[f].v + ')" title="' + FAM[f].label + ': ' + m.fams[f] + '"></i>').join('') + '</div><div class="legend">' + famKeys.map((f) => '<span><i style="--c:var(--' + FAM[f].v + ')"></i>' + FAM[f].label + ' <b>' + m.fams[f] + '</b></span>').join('') + '</div>';
    const ecoKeys = Object.keys(m.eco);
    return '<div class="card breakdown">' +
      '<div><p class="card-title">Advisories by severity</p><p class="card-sub">' + (m.advCount ? plural(m.advCount, 'advisory', 'advisories') + ' across ' + plural(m.vulnPkgs, 'package') + '. Unrated means OSV.dev has no severity for that record.' : 'Nothing found on OSV.dev for these versions.') + '</p><div class="bars">' + sevRows + '</div></div>' +
      '<div><p class="card-title">What your policy did with them</p>' + stBar + '</div>' +
      (m.skipLicense ? '<div><p class="card-title">Licenses</p><p class="small">License lookups are off (<span class="mono">skip_license_check: true</span>).</p></div>' : '<div><p class="card-title">License families</p>' + famBar + '</div>') +
      (ecoKeys.length > 1 ? '<div><p class="card-title">Ecosystems</p><div class="legend">' + ecoKeys.map((e) => '<span>' + esc(ecoName(e)) + 's <b>' + m.eco[e] + '</b></span>').join('') + '</div></div>' : '') +
      '</div>';
  }

  /* ---------------- wiring ---------------- */
  function wire(root) {
    root.addEventListener('click', onClick);
    const rb = $('rescanBtn'); if (rb) rb.onclick = () => cur.ctx.onRescan && cur.ctx.onRescan(cur.entry);
    const eb = $('exportBtn'); if (eb) eb.onclick = (e) => { e.stopPropagation(); toggleExport(eb); };
    const ca = $('copyAll'); if (ca) ca.onclick = () => DS.copy(allCommands(cur.m), 'Copied every upgrade command');
    const pm = $('planMore'); if (pm) pm.onclick = () => { const steps = planSteps(cur.m, cur.reviews); $('plan').innerHTML = steps.map(stepHTML).join(''); pm.remove(); DS.reveal(Array.from($('plan').children).slice(6)); };
    const tabs = $('tabs'); if (tabs) tabs.onclick = (e) => { const b = e.target.closest('.tab'); if (b) setTab(b.dataset.tab); };
  }
  function onClick(e) {
    const st = e.target.closest('[data-step]'); if (st) { toggleStep(st); return; }
    const dl = e.target.closest('[data-report]'); if (dl) { downloadReport(dl.dataset.report); return; }
    const op = e.target.closest('[data-open-pkg]'); if (op) { openPkg(op.dataset.openPkg); return; }
    const rv = e.target.closest('[data-review]'); if (rv) { openReview(rv.dataset.review); return; }
    const tg = e.target.closest('[data-tab-go]'); if (tg) { setTab(tg.dataset.tabGo); $('tabs').scrollIntoView({ behavior: DS.reduced() ? 'auto' : 'smooth', block: 'start' }); }
  }

  function allCommands(m) {
    const go = [], npm = [], over = [];
    m.list.filter((p) => (p.status === 'block' || p.status === 'warn') && p.fixTo).forEach((p) => {
      if (p.dep.Ecosystem === 'Go') go.push(cmd.upgrade(p.dep, p.fixTo));
      else if (p.dep.Direct) npm.push(cmd.upgrade(p.dep, p.fixTo));
      else over.push('  "' + p.dep.Name + '": "' + p.fixTo + '"');
    });
    let out = '';
    if (go.length) out += '# Go\n' + go.join('\n') + '\ngo mod tidy\n';
    if (npm.length) out += (out ? '\n' : '') + '# npm (direct)\n' + npm.join('\n') + '\n';
    if (over.length) out += (out ? '\n' : '') + '# npm (transitive): add to package.json, then run npm install\n"overrides": {\n' + over.join(',\n') + '\n}\n';
    return out.trim();
  }

  /* ---------------- tabs ---------------- */
  function setTab(id) {
    if (!cur || !$('tabs')) return;
    const order = Array.from(document.querySelectorAll('#tabs .tab')).map((b) => b.dataset.tab);
    const from = order.indexOf(cur.shownTab), to = order.indexOf(id);
    cur.tab = id; cur.shownTab = id;
    document.querySelectorAll('#tabs .tab').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === id)));
    moveTabBar();
    const panel = $('panel');
    // The panel slides in from the side of the tab you moved to.
    panel.style.setProperty('--dir', from < 0 || from === to ? '0' : to > from ? '1' : '-1');
    panel.classList.remove('panel'); void panel.offsetWidth; panel.classList.add('panel');
    if (id === 'licenses') renderLicenses(); else if (id === 'deps') renderDeps(); else if (id === 'changes') renderChanges(); else renderFixes();
    DS.edges(cur.root);
  }
  function moveTabBar() {
    const a = document.querySelector('#tabs .tab[aria-selected="true"]'), bar = $('tabBar');
    if (a && bar) { bar.style.width = a.offsetWidth + 'px'; bar.style.transform = 'translateX(' + a.offsetLeft + 'px)'; }
  }
  addEventListener('resize', () => { if (cur) moveTabBar(); });

  const searchBox = (id, value, ph) => '<label class="search">' + icon.search + '<span class="sr">' + esc(ph) + '</span><input id="' + id + '" value="' + esc(value) + '" placeholder="' + esc(ph) + '" autocomplete="off"></label>';
  function keepFocus(id, fn) {
    const el = $(id), pos = el ? el.selectionStart : 0;
    fn();
    const n = $(id); if (n) { n.focus(); try { n.setSelectionRange(pos, pos); } catch (e) { /* not a text input */ } }
  }

  /* ---------------- Fixes ---------------- */
  const GROUPS = [
    { id: 'block', title: 'Blocks the build', about: 'Your policy rejects these. Upgrade them to pass.' },
    { id: 'warn', title: 'Warnings', about: 'Allowed for now, but worth upgrading before they become blocking.' },
    { id: 'excepted', title: 'Excepted by your policy', about: 'Accepted risks from exceptions in policy.yaml, each with a reason and an optional expiry.' },
    { id: 'stopped', title: 'Not evaluated', about: 'The policy stopped at the first violation (fail_fast or max_violations), so these were not judged.' },
    { id: 'transitive', title: 'Not checked: transitive', about: 'check_transitive is off, so advisories in packages you did not add yourself are ignored.' },
    { id: 'below', title: 'Below your policy threshold', about: 'Known advisories at severities your policy neither blocks nor warns about.' }
  ];
  function renderFixes() {
    const m = cur.m, ui = cur.ui, q = ui.q.trim().toLowerCase();
    const withAdv = m.list.filter((p) => p.advs.length);
    const match = (p) => !q || p.dep.Name.toLowerCase().includes(q) || p.advs.some((a) => (a.id + ' ' + a.aliases.join(' ') + ' ' + a.summary).toLowerCase().includes(q));
    const sorters = {
      risk: (a, b) => b.activeScore - a.activeScore || b.score - a.score || sevRank(a.worst) - sevRank(b.worst) || a.dep.Name.localeCompare(b.dep.Name),
      count: (a, b) => b.advs.length - a.advs.length || a.dep.Name.localeCompare(b.dep.Name),
      name: (a, b) => a.dep.Name.localeCompare(b.dep.Name)
    };
    const present = GROUPS.filter((g) => withAdv.some((p) => p.status === g.id));
    const segs = [['all', 'All', withAdv.length]].concat(present.map((g) => [g.id, g.id === 'block' ? 'Blocking' : g.id === 'warn' ? 'Warnings' : g.id === 'below' ? 'Below threshold' : STATUS[g.id].label, withAdv.filter((p) => p.status === g.id).length]));
    if (!segs.some((s) => s[0] === ui.filter)) ui.filter = 'all';

    let h = '';
    if (!withAdv.length) {
      $('panel').innerHTML = '<div class="empty"><b>No advisories</b>OSV.dev has no known advisories for any of these ' + plural(m.list.length, 'package') + '.</div>';
      return;
    }
    h += '<div class="toolbar">' + searchBox('fixQ', ui.q, 'Filter by package, CVE, GHSA or text') +
      '<div class="seg" id="fixSeg" role="group" aria-label="Show">' + segs.map(([id, label, n]) => '<button type="button" data-f="' + id + '" aria-pressed="' + (ui.filter === id) + '">' + label + ' <span class="n">' + n + '</span></button>').join('') + '</div>' +
      '<select class="select" id="fixSort" aria-label="Sort"><option value="risk"' + (ui.sort === 'risk' ? ' selected' : '') + '>Most severe first</option><option value="count"' + (ui.sort === 'count' ? ' selected' : '') + '>Most advisories</option><option value="name"' + (ui.sort === 'name' ? ' selected' : '') + '>Name</option></select></div>';

    let any = false;
    for (const g of present) {
      if (ui.filter !== 'all' && ui.filter !== g.id) continue;
      const rows = withAdv.filter((p) => p.status === g.id && match(p)).sort(sorters[ui.sort]);
      if (!rows.length) continue;
      any = true;
      const shown = ui.shown[g.id] || 25;
      h += '<div class="group"><div class="group-head"><h3><i class="dot" style="--c:var(--' + STATUS[g.id].c + ')"></i>' + g.title + '</h3><p>' + g.about + '</p><span class="n">' + plural(rows.length, 'package') + '</span></div>' +
        rows.slice(0, shown).map(pkgRow).join('') +
        (rows.length > shown ? '<button class="btn btn-sm more" type="button" data-more="' + g.id + '">Show ' + Math.min(25, rows.length - shown) + ' more of ' + (rows.length - shown) + '</button>' : '') + '</div>';
    }
    if (!any) h += '<div class="empty"><b>Nothing matches “' + esc(ui.q) + '”</b>Try a package name, a CVE or GHSA ID, or a word from the advisory.</div>';
    $('panel').innerHTML = h;

    const inp = $('fixQ');
    inp.oninput = () => keepFocus('fixQ', () => { ui.q = inp.value; ui.shown = {}; renderFixes(); });
    $('fixSeg').onclick = (e) => { const b = e.target.closest('button'); if (b) { ui.filter = b.dataset.f; renderFixes(); } };
    $('fixSort').onchange = (e) => { ui.sort = e.target.value; renderFixes(); };
    $('panel').onclick = (e) => {
      const mo = e.target.closest('[data-more]'); if (mo) { ui.shown[mo.dataset.more] = (ui.shown[mo.dataset.more] || 25) + 25; renderFixes(); return; }
      if (e.target.closest('a, [data-copy], .code, input, select, textarea')) return;
      const head = e.target.closest('.pkg-head'); if (head) togglePkg(head.closest('.pkg'));
    };
    // Open the first, most important package so the depth is visible at once.
    if (!ui.autoOpened) {
      ui.autoOpened = true;
      const first = $('panel').querySelector('.pkg');
      if (first && (first.dataset.status === 'block' || first.dataset.status === 'warn')) togglePkg(first, true);
    }
  }

  function pkgRow(p) {
    const d = p.dep, open = cur.ui.open.has(p.key);
    const fix = p.fixTo ? '<span>Upgrade to <b>' + esc(p.fixTo) + '</b></span>' : '<span class="nofix">No fixed release yet</span>';
    const meta = ecoName(d.Ecosystem) + ', ' + scope(d) + ', ' + plural(p.advs.length, 'advisory', 'advisories') + (p.unfixed.length && p.fixTo ? ', ' + p.unfixed.length + ' without a fix' : '');
    return '<div class="pkg' + (open ? ' open' : '') + '" data-key="' + esc(p.key) + '" data-status="' + p.status + '">' +
      '<div class="pkg-head"><span class="pkg-rail" style="--c:' + sevColor(p.worst) + '"></span>' +
      '<button class="pkg-who" type="button" aria-expanded="' + open + '"><span class="pkg-name">' + pkgName(d) + '</span><span class="pkg-meta">' + esc(meta) + '</span></button>' +
      '<span class="pkg-sev">' + sevChips(p.advs) + '</span><span class="pkg-fix">' + fix + '</span><span class="chev" aria-hidden="true">' + icon.chev + '</span></div>' +
      '<div class="pkg-body"><div>' + (open ? pkgDetail(p) : '') + '</div></div></div>';
  }
  function togglePkg(el, force) {
    if (!el) return;
    const p = cur.m.pkgs.get(el.dataset.key);
    const body = el.querySelector('.pkg-body > div');
    if (!body.innerHTML) body.innerHTML = pkgDetail(p);
    const open = force != null ? force : !el.classList.contains('open');
    el.classList.toggle('open', open);
    el.querySelector('.pkg-who').setAttribute('aria-expanded', String(open));
    if (open) cur.ui.open.add(p.key); else cur.ui.open.delete(p.key);
  }

  function whySentence(p) {
    const pol = cur.m.policy, d = p.dep;
    const block = p.advs.filter((a) => a.status === 'block'), warn = p.advs.filter((a) => a.status === 'warn');
    const parts = [];
    const sevList = (arr) => { const c = {}; arr.forEach((a) => { c[a.raw] = (c[a.raw] || 0) + 1; }); return Object.keys(c).map((k) => c[k] + ' ' + (k === 'UNKNOWN' ? 'unrated' : k)).join(', '); };
    if (block.length) parts.push('<b>' + plural(block.length, 'advisory', 'advisories') + ' (' + esc(sevList(block)) + ')</b> ' + (block.length === 1 ? 'is' : 'are') + ' at a severity your policy blocks' + (pol ? ': <span class="mono">block_severities</span> is ' + esc(sevNames(pol.block_severities) || 'empty') : ''));
    if (warn.length) parts.push('<b>' + plural(warn.length, 'advisory', 'advisories') + ' (' + esc(sevList(warn)) + ')</b> ' + (warn.length === 1 ? 'warns' : 'warn'));
    const rest = p.advs.length - block.length - warn.length;
    if (rest) parts.push(rest + ' more ' + (rest === 1 ? 'is' : 'are') + ' ' + (p.advs.filter((a) => a.status === 'excepted').length ? 'excepted or ' : '') + 'below your threshold');
    let s = (parts.length ? parts.join('; ') + '. ' : '');
    s += d.Direct ? 'You depend on this package directly.' : 'Nothing in your project names it directly: another package pulls it in.';
    return s;
  }

  function fixHTML(p) {
    const d = p.dep;
    if (!p.fixTo) {
      const exp = new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10);
      const y = 'exceptions:\n' + p.pool.map((a) => '  - id: ' + a.id + '\n    reason: "Explain why this does not affect us"\n    expires: "' + exp + '"').join('\n');
      return '<div class="stack"><h4>No fixed release yet</h4><p class="small">None of the active advisories lists a fixed version. Your options: replace the package, wait for a fix (the OSV record updates when one ships), or, if the flaw cannot reach your code, record a time-limited exception in <span class="mono">policy.yaml</span>:</p>' + codeBlock(y, 'exception') + '</div>';
    }
    let h = '<div class="stack"><h4>Fix</h4>' + pathHTML(p);
    const done = p.unfixed.length ? 'This fixes ' + p.cleared.length + ' of ' + p.pool.length + '; ' + plural(p.unfixed.length, 'advisory', 'advisories') + ' still ' + (p.unfixed.length === 1 ? 'has' : 'have') + ' no fixed release.' : (p.pool.length === 1 ? 'This fixes it.' : 'This one upgrade fixes all ' + p.pool.length + '.');
    if (d.Ecosystem === 'Go') {
      h += '<p class="small">' + done + (d.Direct ? '' : ' It is transitive: <span class="mono">go get</span> raises the version anyway, and <span class="mono">go mod tidy</span> keeps it marked <span class="mono">// indirect</span>.') + '</p>' + codeBlock(cmd.upgrade(d, p.fixTo) + '\ngo mod tidy', 'upgrade commands');
    } else if (d.Ecosystem === 'npm' && d.Direct) {
      h += '<p class="small">' + done + '</p>' + codeBlock(cmd.upgrade(d, p.fixTo), 'upgrade command');
    } else if (d.Ecosystem === 'npm') {
      h += '<p class="small">' + done + ' It is transitive, so <span class="mono">npm install</span> alone will not move it. Upgrade the package that depends on it, or force the version with an override in <span class="mono">package.json</span>, then run <span class="mono">npm install</span>:</p>' + codeBlock(cmd.override(d, p.fixTo), 'override');
    }
    h += '<details class="small-details"><summary class="small">' + icon.chev + 'Cannot upgrade yet?</summary><p class="small" style="margin:8px 0">Record an exception with a reason and an expiry in <span class="mono">policy.yaml</span>, then restart the server. It comes back for review when it expires.</p>' +
      codeBlock('exceptions:\n' + p.pool.map((a) => '  - id: ' + a.id + '\n    reason: "Explain why this does not affect us"\n    expires: "' + new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10) + '"').join('\n'), 'exception') + '</details>';
    return h + '</div>';
  }
  function infoHTML(p) {
    const d = p.dep;
    return '<div class="stack"><h4>Package</h4><dl class="kv">' +
      '<dt>Ecosystem</dt><dd>' + esc(ecoName(d.Ecosystem)) + '</dd>' +
      '<dt>Scope</dt><dd>' + (d.Direct ? 'Direct: you added it' : 'Transitive: another package needs it') + '</dd>' +
      '<dt>License</dt><dd>' + (p.lic.unknown ? '<span class="small">Unknown</span>' : '<span class="mono">' + esc(p.lic.expr) + '</span>') + ' ' + famChip(p.lic.fam) + '</dd>' +
      '<dt>Package URL</dt><dd class="mono" style="font-size:12.5px">' + esc(purl(d)) + '</dd>' +
      (p.seen > 1 ? '<dt>Lockfiles</dt><dd>Listed ' + p.seen + ' times</dd>' : '') +
      '</dl><div class="linkrow">' + ext(links.pkg(d), d.Ecosystem === 'Go' ? 'pkg.go.dev' : 'npm') + ext(links.depsdev(d), 'deps.dev') + ext(links.repo(d), 'Source') + '</div>' +
      '<h4 style="margin-top:12px">Who pulls it in</h4>' + codeBlock(cmd.why(d), 'command') + '</div>';
  }
  function advsHTML(p) {
    return '<div class="advs">' + p.advs.map((a) => '<div class="adv">' +
      '<div class="adv-sev">' + sevChip(a.sev) + statusChip(a.status) + '</div>' +
      '<div class="adv-main"><p class="adv-sum">' + esc(a.summary || 'No summary published') + '</p><div class="adv-ids">' + idLinks(a) + '</div>' +
      '<p class="adv-out">' + advWhy(a, p.dep, cur.m.policy) + (a.modified ? '. Updated ' + esc(ago(a.modified)) : '') + '</p></div>' +
      '<div class="adv-fix">' + (a.fixed ? '<span>Fixed in</span><b>' + esc(a.fixed) + '</b>' : '<span>No fix yet</span>') + '</div></div>').join('') + '</div>';
  }
  function pkgDetail(p) {
    return '<div class="pkg-in"><p class="why">' + whySentence(p) + '</p><div class="cols">' + fixHTML(p) + infoHTML(p) + '</div><div><h4>' + plural(p.advs.length, 'advisory', 'advisories') + '</h4>' + advsHTML(p) + '</div></div>';
  }

  // Installed version, then each version that closes advisories, coloured by what is left.
  function pathHTML(p) {
    const g = p, fixed = [...new Set(g.advs.map((a) => a.fixed).filter(Boolean))].sort(cmpVer);
    if (!fixed.length) return '';
    const left = (v) => g.advs.filter((a) => !a.fixed || cmpVer(a.fixed, v) > 0);
    const worstOf = (l) => l.reduce((w, a) => (sevRank(a.sev) < sevRank(w) ? a.sev : w), 'NONE');
    const color = (l) => (l.length ? sevColor(worstOf(l)) : 'var(--clean)');
    const stops = [{ v: g.dep.Version, c: color(g.advs), note: 'Installed, ' + plural(g.advs.length, 'advisory', 'advisories') }];
    let prev = g.dep.Version, lastWorst = worstOf(g.advs);
    fixed.forEach((v, i) => {
      if (cmpVer(v, g.dep.Version) <= 0) return;
      const rest = left(v), w = rest.length ? worstOf(rest) : 'CLEAR';
      if (w === lastWorst && v !== g.fixTo && i !== fixed.length - 1) return;
      const closed = g.advs.filter((a) => a.fixed && cmpVer(a.fixed, v) <= 0 && cmpVer(a.fixed, prev) > 0).length;
      stops.push({ v, c: color(rest), note: 'Fixes ' + closed + (rest.length ? ', ' + rest.length + ' left' : ''), rec: v === g.fixTo, rest: rest.length });
      prev = v; lastWorst = w;
    });
    return '<div class="path"><div class="track"><ol>' + stops.map((s, i) => {
      const nx = stops[i + 1];
      return '<li class="stop" style="--a:' + s.c + ';--b:' + (nx ? nx.c : s.c) + '">' + (nx ? '<span class="link" aria-hidden="true"></span>' : '') + '<span class="dot" aria-hidden="true"></span><b>' + esc(s.v) + '</b><small>' + esc(s.note) + '</small>' +
        (s.rec ? '<span class="tag' + (s.rest ? ' part' : '') + '">' + (s.rest ? 'Recommended' : 'Recommended, fixes all') + '</span>' : '') + '</li>';
    }).join('') + '</ol></div></div>';
  }

  /* ---------------- package sheet ---------------- */
  function openPkg(key) {
    const p = cur.m.pkgs.get(key); if (!p) return;
    const d = p.dep;
    sheet.open({
      kicker: chip(STATUS[p.status].long, STATUS[p.status].c) + '<span>' + esc(ecoName(d.Ecosystem)) + ', ' + scope(d) + '</span>',
      title: pkgName(d),
      body: (p.advs.length ? '<section><p>' + whySentence(p) + '</p></section><section>' + fixHTML(p) + '</section>' : '<section><p>No known advisories for this version on OSV.dev.</p></section>') +
        '<section>' + infoHTML(p) + '</section>' +
        (p.advs.length ? '<section><h3>' + plural(p.advs.length, 'advisory', 'advisories') + '</h3>' + advsHTML(p) + '</section>' : '') +
        (p.lic.status !== 'ok' && p.lic.status !== 'skipped' ? '<section><h3>License</h3><p>' + (p.lic.status === 'denied' ? 'Denied by your policy.' : 'deps.dev has no SPDX license for this version.') + '</p><div><button class="btn btn-sm" type="button" data-review-sheet="' + esc(p.key) + '">Review the license</button></div></section>' : ''),
      wire: (b) => { const r = b.querySelector('[data-review-sheet]'); if (r) r.onclick = () => openReview(r.dataset.reviewSheet); }
    });
  }

  /* ---------------- Licenses ---------------- */
  function renderLicenses() {
    const m = cur.m, pol = m.policy, rv = cur.reviews;
    if (m.skipLicense) { $('panel').innerHTML = '<div class="empty"><b>License checks are off</b><span>Your policy has <span class="mono">skip_license_check: true</span>, so no licenses were looked up. Set it to false and restart the server to check them.</span></div>'; return; }
    const denied = m.list.filter((p) => p.lic.status === 'denied' || p.lic.status === 'unknown-block');
    const unknown = m.list.filter((p) => p.lic.status === 'unknown-warn');
    const flagged = denied.concat(unknown);
    const reviewed = flagged.filter((p) => rv.has(p.key)).length;
    const famKeys = Object.keys(FAM).filter((f) => m.fams[f]).sort((a, b) => FAM[a].rank - FAM[b].rank);
    const C = 2 * Math.PI * 15, frac = flagged.length ? reviewed / flagged.length : 1;

    let h = '<div class="lic-summary">' +
      '<div class="card"><p class="card-title">License mix</p><p class="card-sub">' + plural(m.list.length, 'package') + ' by license family. Family is about obligations: permissive asks for a notice, copyleft can ask for your source.</p>' +
        '<div class="stackbar">' + famKeys.map((f) => '<i style="flex:' + m.fams[f] + ';--c:var(--' + FAM[f].v + ')" title="' + FAM[f].label + ': ' + m.fams[f] + '"></i>').join('') + '</div>' +
        '<div class="legend">' + famKeys.map((f) => '<span title="' + esc(FAM[f].about) + '"><i style="--c:var(--' + FAM[f].v + ')"></i>' + FAM[f].label + ' <b>' + m.fams[f] + '</b></span>').join('') + '</div></div>' +
      '<div class="card"><p class="card-title">Your license rules</p>' +
        (pol ? '<p class="card-sub"><b>' + plural(pol.denied_licenses.length, 'license') + '</b> denied in <span class="mono">denied_licenses</span>. Unknown licenses <b>' + (pol.block_unknown_license ? 'block the build' : 'only warn') + '</b> (<span class="mono">block_unknown_license: ' + pol.block_unknown_license + '</span>).</p>' : '<p class="card-sub">The policy could not be loaded from the server.</p>') +
        (flagged.length ? '<div class="review-progress"><svg class="ring" viewBox="0 0 36 36" aria-hidden="true"><circle class="bg" cx="18" cy="18" r="15"/><circle class="fg" cx="18" cy="18" r="15" stroke-dasharray="' + C.toFixed(2) + '" stroke-dashoffset="' + (C * (1 - frac)).toFixed(2) + '"/></svg><span><b>' + reviewed + ' of ' + flagged.length + '</b> flagged licenses reviewed</span></div>' +
          '<div class="form-actions"><button class="btn btn-sm" type="button" id="revCsv">' + icon.download + 'Review log (CSV)</button><button class="btn btn-sm" type="button" id="revMd">' + icon.copy + 'Copy as Markdown</button></div>' : '<p class="small">Nothing to review.</p>') +
      '</div></div>';

    const lrow = (p) => {
      const r = rv.get(p.key);
      const st = p.lic.status === 'denied' ? chip('Denied, blocks', 'critical') : p.lic.status === 'unknown-block' ? chip('Unknown, blocks', 'critical') : chip('Unknown, warns', 'medium');
      return '<div class="lrow"><span class="pkg-rail" style="--c:var(--' + (p.lic.status === 'unknown-warn' ? 'medium' : 'critical') + ')"></span>' +
        '<div class="pkg-who"><span class="pkg-name">' + pkgName(p.dep) + '</span><span class="pkg-meta">' + esc(ecoName(p.dep.Ecosystem)) + ', ' + scope(p.dep) + ', ' + (p.lic.unknown ? 'no SPDX license on deps.dev' : 'declared <span class="mono">' + esc(p.lic.expr) + '</span>') + '</span></div>' +
        '<div class="lrow-state">' + st + (r ? '<span class="chip ' + RV[r.decision].cls + '">' + RV[r.decision].label + (r.license ? ': ' + esc(r.license) : '') + '</span>' : '<span>Not reviewed</span>') + '</div>' +
        '<button class="btn btn-sm" type="button" data-review="' + esc(p.key) + '">' + (r ? 'Edit review' : 'Review') + '</button></div>';
    };
    if (denied.length) h += '<div class="group"><div class="group-head"><h3><i class="dot" style="--c:var(--critical)"></i>Blocks the build</h3><p>' + (denied.some((p) => p.lic.status === 'denied') ? 'These licenses are on your denied list.' : 'Unknown licenses block under your policy.') + ' Replace the package or change the rule.</p><span class="n">' + plural(denied.length, 'package') + '</span></div>' + denied.map(lrow).join('') + '</div>';
    if (unknown.length) h += '<div class="group"><div class="group-head"><h3><i class="dot" style="--c:var(--medium)"></i>Needs a review</h3><p>deps.dev has no SPDX license for these versions. Find the real license, then record a decision.</p><span class="n">' + plural(unknown.length, 'package') + '</span></div>' + unknown.map(lrow).join('') + '</div>';
    if (!flagged.length) h += '<div class="note" style="--c:var(--clean)"><span class="dot" style="--c:var(--clean)"></span><span><b>Every license is known and allowed by your policy.</b> The full list is below.</span></div>';

    // Every license in the project, the most restrictive first.
    const byLic = new Map();
    m.list.forEach((p) => { const k = p.lic.unknown ? '' : p.lic.expr; if (!byLic.has(k)) byLic.set(k, []); byLic.get(k).push(p); });
    const groups = Array.from(byLic.entries()).sort((a, b) => FAM[licFamily(b[0])].rank - FAM[licFamily(a[0])].rank || b[1].length - a[1].length);
    h += '<div class="group"><div class="group-head"><h3>All licenses in this project</h3><p>Grouped by declared license, most restrictive first. Open one to see its packages.</p><span class="n">' + plural(groups.length, 'license') + '</span></div>' +
      groups.map(([lic, ps]) => { const f = licFamily(lic); return '<details class="lgroup"><summary><i class="dot" style="--c:var(--' + FAM[f].v + ')"></i><b>' + (lic ? esc(lic) : 'Unknown') + '</b><span class="fam">' + FAM[f].label + '</span><span class="n">' + plural(ps.length, 'package') + '</span><span class="chev" aria-hidden="true">' + icon.chev + '</span></summary>' +
        '<div class="lgroup-list">' + ps.sort((a, b) => a.dep.Name.localeCompare(b.dep.Name)).slice(0, 300).map((p) => '<button type="button" data-open-pkg="' + esc(p.key) + '">' + esc(p.dep.Name) + '@' + esc(p.dep.Version) + '</button>').join('') + (ps.length > 300 ? '<span class="small">and ' + (ps.length - 300) + ' more</span>' : '') + '</div></details>'; }).join('') + '</div>';

    $('panel').innerHTML = h;
    $('panel').onclick = null;
    const csv = $('revCsv'); if (csv) csv.onclick = () => download('depscan-license-review-' + slug(cur.entry.label) + '.csv', reviewCSV(flagged), 'text/csv');
    const md = $('revMd'); if (md) md.onclick = () => DS.copy(reviewMD(flagged), 'Copied the review log as Markdown');
  }

  function reviewRows(flagged) {
    return flagged.map((p) => { const r = cur.reviews.get(p.key) || {}; return { pkg: p.dep.Name, version: p.dep.Version, eco: p.dep.Ecosystem, scope: scope(p.dep), declared: p.lic.expr || 'unknown', flag: p.lic.status, decision: r.decision ? RV[r.decision].label : 'Not reviewed', license: r.license || '', note: r.note || '', by: r.by || '', at: r.at ? new Date(r.at).toISOString() : '' }; });
  }
  function reviewCSV(flagged) {
    const q = (s) => '"' + String(s).replace(/"/g, '""') + '"';
    const rows = reviewRows(flagged);
    return ['package,version,ecosystem,scope,declared_license,flag,decision,reviewed_license,note,reviewer,reviewed_at'].concat(rows.map((r) => [r.pkg, r.version, r.eco, r.scope, r.declared, r.flag, r.decision, r.license, r.note, r.by, r.at].map(q).join(','))).join('\n') + '\n';
  }
  function reviewMD(flagged) {
    const cell = (s) => String(s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
    return '### License review: ' + cell(cur.entry.label) + '\n\n| Package | Version | Declared | Decision | License found | Note |\n| --- | --- | --- | --- | --- | --- |\n' +
      reviewRows(flagged).map((r) => '| `' + cell(r.pkg) + '` | ' + cell(r.version) + ' | ' + cell(r.declared) + ' | ' + cell(r.decision) + ' | ' + cell(r.license) + ' | ' + cell(r.note) + ' |').join('\n') + '\n';
  }

  /* ---------------- license review sheet ---------------- */
  function openReview(key) {
    const p = cur.m.pkgs.get(key); if (!p) return;
    const d = p.dep, pol = cur.m.policy, r = cur.reviews.get(key);
    let by = ''; try { by = localStorage.getItem('depscan.reviewer') || ''; } catch (e) { /* storage blocked */ }
    const older = Array.from(cur.reviews.values()).filter((x) => x.key !== key && x.key.startsWith(d.Ecosystem + '|' + d.Name + '@')).sort((a, b) => b.at - a.at)[0];
    const blocks = p.lic.status === 'denied' || p.lic.status === 'unknown-block';

    let why;
    if (p.lic.status === 'denied') {
      why = '<p>deps.dev reports <span class="mono">' + esc(p.lic.expr) + '</span>. ' + (p.lic.denied && p.lic.denied.length ? '<span class="mono">' + esc(p.lic.denied.join(', ')) + '</span> ' + (p.lic.denied.length === 1 ? 'is' : 'are') + ' on your <span class="mono">denied_licenses</span> list, so this <b>blocks the build</b>.' : 'Your policy denies it, so this <b>blocks the build</b>.') + ' ' + esc(FAM[p.lic.fam].about) + '</p>';
    } else {
      why = '<p>deps.dev has no SPDX license for <span class="mono">' + esc(d.Name) + '@' + esc(d.Version) + '</span>. Usual reasons: a private or company-internal module, a license file deps.dev cannot classify, or a version it has not indexed yet.</p>' +
        '<p>Under your policy this ' + (blocks ? '<b>blocks the build</b> (<span class="mono">block_unknown_license: true</span>).' : '<b>only warns</b>: CI still passes (<span class="mono">block_unknown_license: ' + (pol ? pol.block_unknown_license : false) + '</span>).') + '</p>';
    }
    const isGo = d.Ecosystem === 'Go', repo = links.repo(d);
    const steps = '<ol class="checklist">' +
      '<li><span><b>Open the license page.</b> ' + (isGo ? 'pkg.go.dev shows the license files the Go module proxy found for this exact version.' : 'The npm page shows the license field from the package\'s package.json.') + '<span class="linkrow">' + ext(links.license(d), isGo ? 'pkg.go.dev licenses' : 'npm page') + '</span></span></li>' +
      '<li><span><b>Check the source.</b> Look for <span class="mono">LICENSE</span>, <span class="mono">COPYING</span> or a license header in the repository at this version.' + (repo ? '<span class="linkrow">' + ext(repo, 'Repository') + '</span>' : '') + '</span></li>' +
      '<li><span><b>Compare with deps.dev.</b> If it shows a license for a newer version, upgrading may be the simplest fix.<span class="linkrow">' + ext(links.depsdev(d), 'deps.dev') + '</span></span></li>' +
      '<li><span><b>Your own code?</b> If this is your company\'s internal module, its license is whatever your company uses for internal code. Record that.</span></li></ol>';

    const body =
      '<section><h3>Why it is flagged</h3>' + why + '</section>' +
      '<section><h3>Find the real license</h3>' + steps + '</section>' +
      '<section><h3>Who pulls it in</h3><p>' + (d.Direct ? 'You added it directly.' : 'It is transitive. This shows which of your dependencies need it:') + '</p>' + codeBlock(cmd.why(d), 'command') + '</section>' +
      '<section><h3>Record your decision</h3>' +
        (older && !r ? '<p class="note"><span>An older version (<span class="mono">' + esc(older.key.split('@').pop()) + '</span>) was reviewed as <b>' + RV[older.decision].label + (older.license ? ': ' + esc(older.license) : '') + '</b>. Licenses can change between versions, so check again.</span></p>' : '') +
        '<div class="form-row"><label for="rvLic">License you found (SPDX ID)</label><input class="field-in mono" id="rvLic" list="spdxList" placeholder="e.g. Apache-2.0" value="' + esc(r ? r.license : (p.lic.unknown ? '' : p.lic.expr)) + '" autocomplete="off" spellcheck="false"><datalist id="spdxList">' + SPDX_COMMON.map((x) => '<option value="' + x + '">').join('') + '</datalist><div class="lic-eval" id="rvEval"></div></div>' +
        '<div class="decide" role="radiogroup" aria-label="Decision">' +
          decideOpt('approved', 'Approve', 'The license is acceptable to ship.', 'clean', r) +
          decideOpt('rejected', 'Reject', 'Must be replaced or removed.', 'critical', r) +
          decideOpt('legal', 'Needs legal review', 'Ask before it ships.', 'medium', r) +
        '</div>' +
        '<div class="form-row"><label for="rvNote">Note</label><textarea class="field-in" id="rvNote" placeholder="Where you found it, for example: LICENSE file in the repository root at this tag">' + esc(r ? r.note : '') + '</textarea></div>' +
        '<div class="form-row"><label for="rvBy">Reviewed by</label><input class="field-in" id="rvBy" value="' + esc(r ? r.by : by) + '" placeholder="Your name" autocomplete="name"></div>' +
        '<div class="form-actions"><button class="btn btn-primary" type="button" id="rvSave">Save review</button>' + (r ? '<button class="btn" type="button" id="rvDel">Remove review</button>' : '') + '<span class="saved-line" id="rvSaved">' + (r ? 'Saved ' + esc(when(r.at)) + (r.by ? ' by ' + esc(r.by) : '') : '') + '</span></div>' +
      '</section>' +
      '<section><h3>What happens next</h3><ul class="checklist" style="counter-reset:none">' +
        '<li><span>Reviews are saved in this browser and shown on every scan of this exact version. Export the log from the Licenses tab to attach it to a pull request or an audit.</span></li>' +
        '<li><span>depscan itself does not read reviews: <span class="mono">policy.yaml</span> decides what passes, the same way on every machine and in CI. ' + (blocks ? 'To stop this from blocking, replace the package' + (p.lic.status === 'denied' ? ', or remove the license from <span class="mono">denied_licenses</span> if your team agrees it is fine.' : ', or set <span class="mono">block_unknown_license: false</span>.') : 'To make every unknown license fail CI instead, set <span class="mono">block_unknown_license: true</span>.') + '</span></li>' +
        '<li><span>If you reject it, find the package that needs it with the command above, replace or remove that dependency, then scan again.</span></li>' +
      '</ul></section>';

    sheet.open({
      kicker: (blocks ? chip(p.lic.status === 'denied' ? 'Denied, blocks' : 'Unknown, blocks', 'critical') : chip('Unknown, warns', 'medium')) + '<span>License review, ' + esc(ecoName(d.Ecosystem)) + ', ' + scope(d) + '</span>',
      title: pkgName(d),
      body,
      wire: (b) => {
        const lic = b.querySelector('#rvLic'), ev = b.querySelector('#rvEval');
        const evaluate = () => {
          const v = lic.value.trim();
          if (!v) { ev.innerHTML = '<span class="small">Type the SPDX identifier, for example MIT or Apache-2.0. Expressions like <span class="mono">MIT OR Apache-2.0</span> work too.</span>'; return; }
          const c = licCheck(v, pol ? pol.denied_licenses : []), f = licFamily(v);
          const known = f !== 'other' || /^LicenseRef-/i.test(v);
          ev.innerHTML = famChip(f) + (c.ok ? chip(pol ? 'Allowed by your policy' : 'Not on a denied list', 'clean') : chip('Denied by your policy: ' + esc(c.denied.join(', ')), 'critical')) + (known ? '' : '<span class="small">Not a common SPDX ID: check the spelling at spdx.org/licenses.</span>');
        };
        lic.addEventListener('input', evaluate); evaluate();
        b.querySelector('#rvSave').onclick = async () => {
          const dec = b.querySelector('input[name="rvDec"]:checked');
          if (!dec) { DS.toast('Choose Approve, Reject or Needs legal review', 'bad'); return; }
          const rec = { key, eco: d.Ecosystem, name: d.Name, version: d.Version, decision: dec.value, license: lic.value.trim(), note: b.querySelector('#rvNote').value.trim(), by: b.querySelector('#rvBy').value.trim(), at: Date.now() };
          try { localStorage.setItem('depscan.reviewer', rec.by); } catch (e) { /* storage blocked */ }
          await DS.store.putReview(rec);
          cur.reviews.set(key, rec);
          const c = licCheck(rec.license, pol ? pol.denied_licenses : []);
          toast(rec.decision === 'approved' && !c.ok ? 'Saved. Note: your policy still denies ' + c.denied.join(', ') : 'Review saved');
          sheet.close(); refreshAfterReview();
        };
        const del = b.querySelector('#rvDel');
        if (del) del.onclick = async () => { await DS.store.deleteReview(key); cur.reviews.delete(key); toast('Review removed'); sheet.close(); refreshAfterReview(); };
      }
    });
  }
  function decideOpt(v, label, about, c, r) {
    const id = 'rvD' + v;
    return '<span><input type="radio" name="rvDec" id="' + id + '" value="' + v + '"' + (r && r.decision === v ? ' checked' : '') + '><label for="' + id + '" style="--c:var(--' + c + ')"><b><i class="dot" style="--c:var(--' + c + ')"></i>' + label + '</b><span>' + about + '</span></label></span>';
  }
  function refreshAfterReview() {
    if (cur.tab === 'licenses') renderLicenses();
    const pl = $('plan'); if (pl) { const steps = planSteps(cur.m, cur.reviews); pl.innerHTML = steps.slice(0, pl.children.length).map(stepHTML).join(''); }
  }

  /* ---------------- Dependencies ---------------- */
  const statusOf = (p) => (p.status === 'block' || p.lic.status === 'denied' || p.lic.status === 'unknown-block' ? 'block' : p.status === 'warn' ? 'warn' : p.advs.length ? 'info' : p.lic.status === 'unknown-warn' ? 'lic' : 'clean');
  const ST_RANK = { block: 0, warn: 1, info: 2, lic: 3, clean: 4 };
  function depStatusHTML(p) {
    const s = statusOf(p);
    if (s === 'block') return '<i class="dot" style="--c:var(--critical)"></i>' + (p.status === 'block' ? 'Blocks' : 'License blocks');
    if (s === 'warn') return '<i class="dot" style="--c:var(--medium)"></i>Warns';
    if (s === 'info') return '<i class="dot" style="--c:' + sevColor(p.worst) + '"></i>' + plural(p.advs.length, 'advisory', 'advisories');
    if (s === 'lic') return '<i class="dot" style="--c:var(--unknown)"></i>License unknown';
    return '<i class="dot" style="--c:var(--clean)"></i>Clean';
  }
  function renderDeps() {
    const m = cur.m, ui = cur.ui, q = ui.depQ.trim().toLowerCase();
    const ecos = Object.keys(m.eco);
    let rows = m.list.filter((p) =>
      (ui.depScope === 'all' || (ui.depScope === 'direct') === !!p.dep.Direct) &&
      (ui.depEco === 'all' || p.dep.Ecosystem === ui.depEco) &&
      (ui.depStatus === 'any' || (ui.depStatus === 'adv' ? p.advs.length > 0 : ui.depStatus === 'lic' ? p.lic.status !== 'ok' && p.lic.status !== 'skipped' : statusOf(p) === ui.depStatus)) &&
      (!q || p.dep.Name.toLowerCase().includes(q) || (p.lic.expr || '').toLowerCase().includes(q)));
    const [key, dir] = ui.depSort;
    const cmp = {
      name: (a, b) => a.dep.Name.localeCompare(b.dep.Name),
      version: (a, b) => cmpVer(a.dep.Version, b.dep.Version),
      scope: (a, b) => (b.dep.Direct ? 1 : 0) - (a.dep.Direct ? 1 : 0),
      eco: (a, b) => a.dep.Ecosystem.localeCompare(b.dep.Ecosystem),
      license: (a, b) => FAM[b.lic.fam].rank - FAM[a.lic.fam].rank || (a.lic.expr || '').localeCompare(b.lic.expr || ''),
      status: (a, b) => ST_RANK[statusOf(a)] - ST_RANK[statusOf(b)] || sevRank(a.worst) - sevRank(b.worst) || b.advs.length - a.advs.length
    }[key];
    rows.sort((a, b) => cmp(a, b) * dir || a.dep.Name.localeCompare(b.dep.Name));
    const sortBtn = (k, label) => '<button class="sortbtn" type="button" data-sort="' + k + '" aria-sort="' + (key === k ? (dir > 0 ? 'ascending' : 'descending') : 'none') + '">' + label + (key === k ? '<svg viewBox="0 0 10 10" aria-hidden="true"><path d="' + (dir > 0 ? 'M2 6.5 5 3.5l3 3' : 'M2 3.5 5 6.5l3-3') + '" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>' : '') + '</button>';
    const seg = (id, val, opts) => '<div class="seg" id="' + id + '" role="group">' + opts.map(([v, l]) => '<button type="button" data-v="' + v + '" aria-pressed="' + (val === v) + '">' + l + '</button>').join('') + '</div>';

    let h = '<div class="toolbar">' + searchBox('depQ', ui.depQ, 'Filter by name or license') +
      seg('depScope', ui.depScope, [['all', 'All'], ['direct', 'Direct'], ['trans', 'Transitive']]) +
      (ecos.length > 1 ? '<select class="select" id="depEco" aria-label="Ecosystem"><option value="all">All ecosystems</option>' + ecos.map((e) => '<option value="' + esc(e) + '"' + (ui.depEco === e ? ' selected' : '') + '>' + esc(e) + '</option>').join('') + '</select>' : '') +
      '<select class="select" id="depStatus" aria-label="Status">' + [['any', 'Any status'], ['block', 'Blocks'], ['warn', 'Warns'], ['adv', 'Has advisories'], ['lic', 'License issue'], ['clean', 'Clean']].map(([v, l]) => '<option value="' + v + '"' + (ui.depStatus === v ? ' selected' : '') + '>' + l + '</option>').join('') + '</select>' +
      '<span class="grow"></span><span class="count-line">' + (rows.length === m.list.length ? plural(rows.length, 'package') : fmtN(rows.length) + ' of ' + plural(m.list.length, 'package')) + '</span>' +
      '<button class="btn btn-sm" type="button" id="depCsv">' + icon.download + 'CSV</button></div>';
    h += '<div class="dtable" role="table"><div class="drow head" role="row">' + sortBtn('name', 'Package') + sortBtn('version', 'Version') + sortBtn('scope', 'Scope') + '<span class="ec">' + sortBtn('eco', 'Eco.') + '</span>' + sortBtn('license', 'License') + sortBtn('status', 'Status') + '</div>';
    if (!rows.length) h += '<div class="empty"><b>No packages match</b>Clear the search or a filter to see more.</div>';
    h += rows.slice(0, ui.depShown).map((p) => '<button class="drow" type="button" role="row" data-open-pkg="' + esc(p.key) + '">' +
      '<span class="nm" title="' + esc(p.dep.Name) + '">' + esc(p.dep.Name) + '</span><span class="vr" title="' + esc(p.dep.Version) + '">' + esc(p.dep.Version) + '</span>' +
      '<span class="sc">' + (p.dep.Direct ? 'Direct' : 'Transitive') + '</span><span class="ec">' + esc(p.dep.Ecosystem) + '</span>' +
      '<span class="lc"><i class="dot" style="--c:var(--' + FAM[p.lic.fam].v + ')"></i><span>' + (p.lic.unknown ? 'unknown' : esc(p.lic.expr)) + '</span></span>' +
      '<span class="st">' + depStatusHTML(p) + '</span></button>').join('') + '</div>';
    if (rows.length > ui.depShown) h += '<button class="btn btn-sm more" type="button" id="depMore">Show ' + Math.min(100, rows.length - ui.depShown) + ' more of ' + fmtN(rows.length - ui.depShown) + '</button>';
    $('panel').innerHTML = h;
    $('panel').onclick = (e) => { const s = e.target.closest('[data-sort]'); if (s) { const k = s.dataset.sort; ui.depSort = [k, ui.depSort[0] === k ? -ui.depSort[1] : 1]; renderDeps(); } };

    const inp = $('depQ');
    inp.oninput = () => keepFocus('depQ', () => { ui.depQ = inp.value; ui.depShown = 100; renderDeps(); });
    $('depScope').onclick = (e) => { const b = e.target.closest('button'); if (b) { ui.depScope = b.dataset.v; ui.depShown = 100; renderDeps(); } };
    const de = $('depEco'); if (de) de.onchange = (e) => { ui.depEco = e.target.value; ui.depShown = 100; renderDeps(); };
    $('depStatus').onchange = (e) => { ui.depStatus = e.target.value; ui.depShown = 100; renderDeps(); };
    const more = $('depMore'); if (more) more.onclick = () => { ui.depShown += 100; renderDeps(); };
    $('depCsv').onclick = () => download('depscan-dependencies-' + slug(cur.entry.label) + '.csv', depsCSV(rows), 'text/csv');
  }
  function depsCSV(rows) {
    const q = (s) => '"' + String(s == null ? '' : s).replace(/"/g, '""') + '"';
    return ['ecosystem,name,version,scope,license,license_family,advisories,worst_severity,status,fix_version,purl']
      .concat(rows.map((p) => [p.dep.Ecosystem, p.dep.Name, p.dep.Version, scope(p.dep), p.lic.expr || 'unknown', FAM[p.lic.fam].label, p.advs.length, p.advs.length ? SEV[p.worst].label : '', statusOf(p), p.fixTo, purl(p.dep)].map(q).join(','))).join('\n') + '\n';
  }

  /* ---------------- Changes ---------------- */
  function diff(a, b) {
    const pa = a.list, pb = b.list;
    const byName = (list) => { const mm = new Map(); list.forEach((p) => { const k = p.dep.Ecosystem + '|' + p.dep.Name; if (!mm.has(k)) mm.set(k, []); mm.get(k).push(p); }); return mm; };
    const na = byName(pa), nb = byName(pb);
    const added = [], removed = [], changed = [];
    nb.forEach((list, k) => { if (!na.has(k)) added.push(...list); else { const va = na.get(k).map((p) => p.dep.Version).sort().join(','), vb = list.map((p) => p.dep.Version).sort().join(','); if (va !== vb) changed.push({ name: list[0].dep.Name, eco: list[0].dep.Ecosystem, from: va, to: vb, up: cmpVer(list[0].dep.Version, na.get(k)[0].dep.Version) > 0 }); } });
    na.forEach((list, k) => { if (!nb.has(k)) removed.push(...list); });
    const advs = (m) => { const s = new Map(); m.list.forEach((p) => p.advs.forEach((x) => s.set(p.dep.Name + '#' + x.id, { p, a: x }))); return s; };
    const aa = advs(a), ab = advs(b);
    const newA = [], fixedA = [];
    ab.forEach((v, k) => { if (!aa.has(k)) newA.push(v); });
    aa.forEach((v, k) => { if (!ab.has(k)) fixedA.push(v); });
    const licChanged = [];
    pb.forEach((p) => { const o = (na.get(p.dep.Ecosystem + '|' + p.dep.Name) || [])[0]; if (o && (o.lic.expr || '') !== (p.lic.expr || '')) licChanged.push({ p, from: o.lic.expr || 'unknown', to: p.lic.expr || 'unknown' }); });
    return { added, removed, changed, newA, fixedA, licChanged };
  }
  async function renderChanges() {
    const prevs = cur.ctx.prevList || (cur.ctx.prev ? [cur.ctx.prev] : []);
    let prev = cur.ui.prevId ? prevs.find((x) => x.id === cur.ui.prevId) : prevs[0];
    if (!prev) { $('panel').innerHTML = '<div class="empty"><b>No earlier scan of this project</b>Scan it again later to see what changed.</div>'; return; }
    const a = build(prev.record, cur.m.policy), b = cur.m, d = diff(a, b);
    const delta = (x, y, good) => { const n = y - x; return n === 0 ? '<span class="delta">no change</span>' : '<span class="delta ' + ((n > 0) === good ? 'down' : 'up') + '">' + (n > 0 ? '+' : '') + n + '</span>'; };
    const li = (html, small) => '<li><span>' + html + '</span>' + (small ? '<small>' + small + '</small>' : '') + '</li>';
    const capList = (arr, f, n) => arr.slice(0, n || 12).map(f).join('') + (arr.length > (n || 12) ? '<li><small>and ' + (arr.length - (n || 12)) + ' more</small></li>' : '');
    const vw = (x) => VERDICT[x].word === 'Passes' && x === 'warn' ? 'Passes with warnings' : VERDICT[x].word;
    let h = '<div class="toolbar"><span class="count-line">Compared with</span><select class="select" id="prevSel" aria-label="Earlier scan">' + prevs.map((x) => '<option value="' + esc(x.id) + '"' + (x.id === prev.id ? ' selected' : '') + '>' + esc(when(x.at)) + ' (' + esc(ago(x.at)) + ')</option>').join('') + '</select></div>';
    const same = !d.added.length && !d.removed.length && !d.changed.length && !d.newA.length && !d.fixedA.length && !d.licChanged.length && a.verdict === b.verdict;
    h += '<div class="note" style="--c:var(--' + VERDICT[b.verdict].c + ');margin-bottom:22px"><span>' + (same ? '<b>Nothing changed</b> since the scan from ' + esc(ago(prev.at)) + ': same packages, same advisories, same verdict.' : '<b>' + (a.verdict === b.verdict ? 'Still ' + vw(b.verdict).toLowerCase() : 'Was ' + vw(a.verdict).toLowerCase() + ', now ' + vw(b.verdict).toLowerCase()) + '.</b> Blocking packages ' + a.blockPkgs + ' to ' + b.blockPkgs + ' (' + delta(a.blockPkgs, b.blockPkgs, false) + '), advisories ' + a.advCount + ' to ' + b.advCount + ' (' + delta(a.advCount, b.advCount, false) + '), packages ' + fmtN(a.list.length) + ' to ' + fmtN(b.list.length) + '.') + '</span></div>';
    h += '<div class="diff-grid">' +
      '<div class="card"><p class="card-title">Advisories</p><p class="card-sub">' + d.newA.length + ' new, ' + d.fixedA.length + ' gone</p><ul class="diff-list">' +
        capList(d.newA, (x) => li('<span class="delta up">New</span> <span class="mono">' + esc(x.a.id) + '</span>', esc(x.p.dep.Name) + ', ' + SEV[x.a.sev].label.toLowerCase())) +
        capList(d.fixedA, (x) => li('<span class="delta down">Gone</span> <span class="mono">' + esc(x.a.id) + '</span>', esc(x.p.dep.Name))) +
        (d.newA.length + d.fixedA.length ? '' : '<li><small>No change</small></li>') + '</ul></div>' +
      '<div class="card"><p class="card-title">Packages</p><p class="card-sub">' + d.added.length + ' added, ' + d.removed.length + ' removed, ' + d.changed.length + ' changed version</p><ul class="diff-list">' +
        capList(d.changed, (x) => li('<span class="mono">' + esc(x.name) + '</span>', esc(x.from) + ' to ' + esc(x.to) + (x.up ? ', upgraded' : ', downgraded'))) +
        capList(d.added, (p) => li('<span class="delta">Added</span> <span class="mono">' + esc(p.dep.Name) + '@' + esc(p.dep.Version) + '</span>'), 8) +
        capList(d.removed, (p) => li('<span class="delta">Removed</span> <span class="mono">' + esc(p.dep.Name) + '</span>'), 8) +
        (d.added.length + d.removed.length + d.changed.length ? '' : '<li><small>No change</small></li>') + '</ul></div>' +
      '<div class="card"><p class="card-title">Licenses</p><p class="card-sub">' + d.licChanged.length + ' changed</p><ul class="diff-list">' +
        capList(d.licChanged, (x) => li('<span class="mono">' + esc(x.p.dep.Name) + '</span>', esc(x.from) + ' to ' + esc(x.to))) +
        (d.licChanged.length ? '' : '<li><small>No change</small></li>') + '</ul></div></div>';
    $('panel').innerHTML = h;
    $('panel').onclick = null;
    $('prevSel').onchange = (e) => { cur.ui.prevId = e.target.value; renderChanges(); };
  }

  /* ---------------- export ---------------- */
  function toggleExport(btn) {
    const wrap = btn.parentElement, old = wrap.querySelector('.menu');
    if (old) { old.remove(); btn.setAttribute('aria-expanded', 'false'); return; }
    const menu = document.createElement('div');
    menu.className = 'menu'; menu.setAttribute('role', 'menu');
    menu.innerHTML = [
      ['md-copy', 'Copy summary for a pull request', 'Markdown with the verdict and the fixes'],
      ['md', 'Download Markdown report', 'Verdict, plan, advisories and licenses'],
      ['json', 'Download JSON', 'The full scan record from the server'],
      ['csv', 'Download dependencies (CSV)', 'Every package with license and status']
    ].map(([id, b, s]) => '<button type="button" role="menuitem" data-x="' + id + '"><b>' + b + '</b><span>' + s + '</span></button>').join('');
    wrap.appendChild(menu); btn.setAttribute('aria-expanded', 'true');
    menu.querySelector('button').focus();
    const close = () => { menu.remove(); btn.setAttribute('aria-expanded', 'false'); document.removeEventListener('click', away); };
    const away = (e) => { if (!menu.contains(e.target)) close(); };
    setTimeout(() => document.addEventListener('click', away), 0);
    menu.addEventListener('keydown', (e) => { if (e.key === 'Escape') { close(); btn.focus(); } });
    menu.onclick = (e) => {
      const b = e.target.closest('[data-x]'); if (!b) return;
      const name = 'depscan-' + slug(cur.entry.label) + '-' + new Date(cur.entry.at).toISOString().slice(0, 10);
      if (b.dataset.x === 'md-copy') DS.copy(markdown(cur.m, true), 'Copied the summary');
      if (b.dataset.x === 'md') download(name + '.md', markdown(cur.m, false), 'text/markdown');
      if (b.dataset.x === 'json') download(name + '.json', JSON.stringify(cur.entry.record, null, 2), 'application/json');
      if (b.dataset.x === 'csv') download(name + '-dependencies.csv', depsCSV(cur.m.list), 'text/csv');
      close();
    };
  }
  function markdown(m, short) {
    const e = cur.entry, v = VERDICT[m.verdict];
    const cell = (s) => String(s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
    let s = '## depscan: ' + (m.verdict === 'warn' ? 'Passes with warnings' : v.word) + '\n\n';
    s += '**' + cell(e.label) + '**, scanned ' + new Date(e.at).toISOString().replace('T', ' ').slice(0, 16) + ' UTC. ' + m.list.length + ' packages (' + m.direct + ' direct), ' + m.advCount + ' advisories' + (m.policy ? ', policy `' + m.policy.digest.slice(0, 12) + '`' : '') + '.\n\n';
    const rows = m.list.filter((p) => p.status === 'block' || p.status === 'warn').sort((a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status) || b.activeScore - a.activeScore);
    if (rows.length) {
      s += '| | Package | Installed | Advisories | Upgrade to |\n| --- | --- | --- | --- | --- |\n';
      rows.forEach((p) => { s += '| ' + (p.status === 'block' ? 'Blocks' : 'Warns') + ' | `' + cell(p.dep.Name) + '` | ' + cell(p.dep.Version) + ' | ' + p.pool.map((a) => cell(a.id) + ' (' + SEV[a.sev].label.toLowerCase() + ')').join(', ') + ' | ' + (p.fixTo ? '`' + cell(p.fixTo) + '`' : 'no fix yet') + ' |\n'; });
      s += '\n';
    } else s += 'No package breaks the policy.\n\n';
    const lic = m.list.filter((p) => p.lic.status !== 'ok' && p.lic.status !== 'skipped');
    if (lic.length) s += '**Licenses:** ' + lic.slice(0, short ? 8 : 200).map((p) => '`' + cell(p.dep.Name) + '` (' + (p.lic.status === 'denied' ? 'denied: ' + cell(p.lic.expr) : 'unknown') + ')').join(', ') + (short && lic.length > 8 ? ', and ' + (lic.length - 8) + ' more' : '') + '\n\n';
    if (!short) {
      const cmds = allCommands(m);
      if (cmds) s += '### Commands\n\n```sh\n' + cmds + '\n```\n\n';
      const all = m.list.filter((p) => p.advs.length);
      if (all.length) {
        s += '### All advisories\n\n| Package | Advisory | Severity | Outcome | Fixed in | Summary |\n| --- | --- | --- | --- | --- | --- |\n';
        all.forEach((p) => p.advs.forEach((a) => { s += '| `' + cell(p.dep.Name + '@' + p.dep.Version) + '` | [' + cell(a.id) + '](' + links.osv(a.id) + ') | ' + SEV[a.sev].label + ' | ' + STATUS[a.status].long + ' | ' + cell(a.fixed || '—') + ' | ' + cell(a.summary) + ' |\n'; }));
        s += '\n';
      }
    }
    return s + '_Generated by depscan._\n';
  }

  /* ================================================================ risk map
     Every package with advisories is a tower: taller and redder means riskier
     (critical 10, high 6, moderate 3, low or unrated 1). Clean packages are
     the platform the towers stand on. Seen from above it is a flat map; one
     camera swings to the corner view while the towers rise. */
  const YAW_3D = Math.PI / 4, ELEV_3D = 34 * Math.PI / 180;
  const YAW_RANGE = [8 * Math.PI / 180, 82 * Math.PI / 180], ELEV_RANGE = [18 * Math.PI / 180, 62 * Math.PI / 180];
  const c01 = (v) => (v > 0 ? (v < 1 ? v : 1) : 0);
  const lerp = (a, b, t) => a + (b - a) * t;
  const easeIO = (x) => { const t = c01(x); return t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; };
  const easeOut = (x) => 1 - Math.pow(1 - c01(x), 3);
  const LV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'NONE'];
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

  function skyHTML(m) {
    const items = m.list.slice().sort((a, b) => b.score - a.score || sevRank(a.worst) - sevRank(b.worst) || a.dep.Name.localeCompare(b.dep.Name));
    const risky = items.filter((g) => g.score > 0).length, clean = items.length - risky;
    cur.skyItems = items;
    if (!cur.skyModeSet) cur.skyMode = risky > 0 && clean > risky ? 'risk' : 'all';
    const counts = {}; items.forEach((g) => { counts[g.worst] = (counts[g.worst] || 0) + 1; });
    const legend = LV.filter((s) => counts[s]).map((s) => '<button type="button" class="key" data-l="' + LV.indexOf(s) + '" style="--c:' + (s === 'NONE' ? 'var(--flat)' : sevColor(s)) + '" aria-pressed="false"><b>' + counts[s] + '</b> ' + SEV[s].label.toLowerCase() + '</button>').join('');
    const top = items[0];
    const modes = risky > 0 && clean > 0 ? '<div class="seg sky-mode" id="skyMode" role="group" aria-label="Packages shown"><button type="button" data-m="risk" aria-pressed="' + (cur.skyMode === 'risk') + '">At risk <span class="n">' + risky + '</span></button><button type="button" data-m="all" aria-pressed="' + (cur.skyMode === 'all') + '">All <span class="n">' + items.length + '</span></button></div>' : '';
    return '<div class="card sky" id="sky"><div class="sky-top"><p class="sky-title" id="skyTitle"></p><div class="sky-ctl">' + modes +
      '<div class="view-toggle" id="viewToggle" data-v="3d" role="group" aria-label="Map view"><span class="knob" aria-hidden="true"></span>' +
      '<button type="button" data-v="2d" aria-pressed="false" aria-label="Flat map"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1" fill="currentColor"/><rect x="9" y="1.5" width="5.5" height="5.5" rx="1" fill="currentColor"/><rect x="1.5" y="9" width="5.5" height="5.5" rx="1" fill="currentColor"/><rect x="9" y="9" width="5.5" height="5.5" rx="1" fill="currentColor"/></svg></button>' +
      '<button type="button" data-v="3d" aria-pressed="true" aria-label="3D view"><svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M8 1.2 14.2 4.6v6.8L8 14.8 1.8 11.4V4.6Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M1.8 4.6 8 8l6.2-3.4M8 8v6.8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg></button></div></div></div>' +
      '<p class="card-sub">Each tower is a package. Height is risk: critical counts 10, high 6, moderate 3, low or unrated 1. Click one to open it.</p>' +
      '<div class="stage-sky" id="stageSky"><canvas id="skyCanvas" tabindex="0" role="img"></canvas>' +
      '<div class="corner tr"><span class="lbl">Blocking the build</span><span class="big" style="color:' + (m.blockPkgs ? 'var(--critical-t)' : 'var(--clean-t)') + '">' + m.blockPkgs + '</span></div>' +
      (top && top.score ? '<div class="corner bl"><span class="lbl">Riskiest package</span><span class="big mono">' + esc(top.dep.Name) + '</span><span class="lbl">' + plural(top.advs.length, 'advisory', 'advisories') + ', risk ' + top.score + '</span></div>' : '') + '</div>' +
      '<div class="sky-foot"><span class="hint" id="skyHint"></span><div class="keys" id="skyKeys">' + legend + '</div></div><p class="sr" aria-live="polite" id="skyLive"></p></div>';
  }

  function startSky(m, keepState) {
    const prev = cur.sky && keepState ? cur.sky.state() : null;
    if (cur.sky) cur.sky.destroy();
    const all = cur.skyItems, root = $('sky'), stage = $('stageSky'), canvas = $('skyCanvas'), tip = $('tip');
    if (!all || !root) return;
    const ctx = canvas.getContext('2d');
    const ac = new AbortController(), on = (el, ev, fn, o) => el.addEventListener(ev, fn, Object.assign({ signal: ac.signal }, o || {}));
    const rmq = matchMedia('(prefers-reduced-motion: reduce)');
    let reduced = rmq.matches;
    const riskyAll = all.filter((g) => g.score > 0);
    const focus = cur.skyMode === 'risk' && riskyAll.length > 0 && riskyAll.length < all.length;
    const items = focus ? riskyAll : all;
    const cleanCount = all.length - riskyAll.length, plate = focus && cleanCount > 0;
    const n = items.length;
    const C = Math.max(1, Math.ceil(Math.sqrt(n * (focus ? 1.2 : 1.7)))), R = Math.max(1, Math.ceil(n / C));
    const cells = []; for (let x = 0; x < C; x++) for (let y = 0; y < R; y++) cells.push([x, y]);
    cells.sort((a, b) => (a[0] + a[1]) - (b[0] + b[1]) || Math.abs(a[0] - a[1]) - Math.abs(b[0] - b[1]) || a[0] - b[0]);
    const wk = new Float32Array(n), dy = new Float32Array(n), lv = new Uint8Array(n), hgt = new Float32Array(n), zs = new Float32Array(n);
    const hover = new Float32Array(n), dim = new Float32Array(n), polys = new Float32Array(n * 24), faces = new Uint8Array(n);
    const order = Array.from({ length: n }, (_, i) => i), at = new Map();
    const maxScore = Math.max(1, ...items.map((g) => g.score));
    items.forEach((g, i) => { wk[i] = cells[i][0]; dy[i] = cells[i][1]; lv[i] = LV.indexOf(g.worst); hgt[i] = g.score > 0 ? .5 + Math.pow(g.score / maxScore, .8) * 6.4 : .18; at.set(wk[i] + ',' + dy[i], i); });
    const diag = Math.max(1, C + R - 2), PLATE = -2, PAD = .45, PLATE_H = .16, platePoly = new Float32Array(24);
    $('skyTitle').innerHTML = focus ? '<b>' + n + '</b> at-risk ' + (n === 1 ? 'package' : 'packages') + ' on <b>' + cleanCount + '</b> clean ones' : '<b>' + all.length + '</b> packages';
    canvas.setAttribute('aria-label', n + ' packages drawn as towers. Taller and redder means riskier. Use the arrow keys to read each package and Enter to open it.');

    let t = prev ? prev.t : 0, target = prev ? prev.target : 1, yaw = 0, elev = 0, yawGoal = 0, elevGoal = 0, entered = !!prev;
    if (prev && prev.target === 1 && !reduced) t = .35;
    let W = 0, H2 = 0, H3 = 0, Hmax = 0, dpr = 1, lastH = -1, raf = 0, last = 0;
    let col = [], fg = [20, 26, 36], plateCol = [0, 0, 0];
    let hovered = -1, pinned = -1, active = -1, legendLevel = -1, legendSticky = -1;

    const retheme = () => {
      const cs = getComputedStyle(root);
      fg = toRGB(cs.getPropertyValue('--text').trim(), fg);
      const bg = toRGB(cs.getPropertyValue('--panel').trim(), [12, 16, 20]);
      const dark = (0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2]) / 255 < .45;
      const flat = [0, 1, 2].map((k) => bg[k] + (fg[k] - bg[k]) * (dark ? .14 : .1));
      const cleanRGB = toRGB(cs.getPropertyValue('--clean').trim(), fg);
      plateCol = [0, 1, 2].map((k) => flat[k] + (cleanRGB[k] - flat[k]) * (dark ? .22 : .28));
      root.style.setProperty('--flat', rgb(flat[0], flat[1], flat[2]));
      const ck = root.querySelector('.key[data-l="5"]');
      if (ck) ck.style.setProperty('--c', plate ? rgb(plateCol[0], plateCol[1], plateCol[2]) : 'var(--flat)');
      col = ['--critical', '--high', '--medium', '--low', '--unknown'].map((v) => toRGB(cs.getPropertyValue(v).trim(), fg)).concat([flat]);
      if (entered) kick(); else draw();
    };
    const width = (e) => lerp(.78, .86, e);
    const extent = (cam, e, full) => {
      const w = width(e), off = (1 - w) / 2;
      let a = Infinity, b = -Infinity, c = Infinity, d = -Infinity;
      const addp = (x, y, z) => { const px = x * cam.cs - y * cam.sn, py = (x * cam.sn + y * cam.cs) * cam.se - z * cam.ce; if (px < a) a = px; if (px > b) b = px; if (py < c) c = py; if (py > d) d = py; };
      for (let i = 0; i < n; i++) { const x0 = wk[i] + off, y0 = dy[i] + off, z = full ? hgt[i] * e : zs[i]; addp(x0, y0, z); addp(x0 + w, y0, z); addp(x0, y0 + w, z); addp(x0 + w, y0 + w, 0); addp(x0, y0 + w, 0); addp(x0 + w, y0, 0); }
      if (plate) { addp(-PAD, -PAD, 0); addp(C + PAD, -PAD, 0); addp(-PAD, R + PAD, 0); addp(C + PAD, R + PAD, 0); }
      return { minx: a, maxx: b, miny: c, maxy: d };
    };
    const cap2 = n < 40 ? 64 : 44, cap3 = n < 40 ? 104 : 72;
    const relayout = () => {
      const w = Math.round(stage.clientWidth); if (!w) return;
      W = w; dpr = Math.min(2, devicePixelRatio || 1);
      const b2 = extent(camera(0, 0, 0), 0, true), bw2 = b2.maxx - b2.minx, bh2 = b2.maxy - b2.miny;
      H2 = Math.max(80, Math.min(bh2 * Math.min((W - 8) / bw2, cap2) + 8, 440));
      const b3 = extent(camera(1, 0, 0), 1, true), bw3 = b3.maxx - b3.minx, bh3 = b3.maxy - b3.miny;
      H3 = Math.max(Math.min(bh3 * Math.min((W - 40) / bw3, cap3) + 40, W * .66, 520), Math.min(260, W * .75));
      Hmax = Math.ceil(Math.max(H2, H3));
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(Hmax * dpr);
      canvas.style.width = W + 'px'; canvas.style.height = Hmax + 'px';
      lastH = -1; draw();
    };
    const rise = (i) => easeOut((t - ((wk[i] + dy[i]) / diag) * .4) / .58);
    const face = (p, o, r, fill) => { ctx.beginPath(); quad(ctx, p, o, r); ctx.fillStyle = fill; ctx.fill(); };
    const draw = () => {
      if (!W || !col.length) return;
      const e = easeIO(t), cam = camera(e, yaw, elev), Hc = lerp(H2, H3, e);
      if (Math.abs(Hc - lastH) > .2) { stage.style.height = Hc.toFixed(1) + 'px'; lastH = Hc; }
      for (let i = 0; i < n; i++) zs[i] = rise(i) * hgt[i];
      const b = extent(cam, e, false), pad = lerp(6, 24, e);
      const aw = W - 2 * pad, ah = Hc - 2 * pad, bw = Math.max(1e-6, b.maxx - b.minx), bh = Math.max(1e-6, b.maxy - b.miny);
      const s = Math.min(aw / bw, ah / bh, lerp(cap2, cap3, e));
      const ox = pad + (aw - bw * s) / 2 - b.minx * s, oy = pad + (ah - bh * s) / 2 - b.miny * s;
      const { cs, sn, se, ce } = cam;
      const px = (x, y) => ox + (x * cs - y * sn) * s, py = (x, y, z) => oy + ((x * sn + y * cs) * se - z * ce) * s;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, Hmax);
      if (plate) {
        const x0 = -PAD, y0 = -PAD, x1 = C + PAD, y1 = R + PAD, z = PLATE_H * e, p = platePoly;
        p[0] = px(x0, y0); p[1] = py(x0, y0, z); p[2] = px(x1, y0); p[3] = py(x1, y0, z); p[4] = px(x1, y1); p[5] = py(x1, y1, z); p[6] = px(x0, y1); p[7] = py(x0, y1, z);
        p[8] = px(x0, y1); p[9] = py(x0, y1, 0); p[10] = px(x1, y1); p[11] = py(x1, y1, 0); p[12] = p[4]; p[13] = p[5]; p[14] = p[6]; p[15] = p[7];
        p[16] = px(x1, y0); p[17] = py(x1, y0, 0); p[18] = p[10]; p[19] = p[11]; p[20] = p[4]; p[21] = p[5]; p[22] = p[2]; p[23] = p[3];
        const [r, g, bl] = plateCol, hl = active === PLATE ? .12 : 0, mix = (c, k) => c + (fg[k] - c) * hl;
        if (z * ce * s > .5) { face(p, 8, 0, rgb(mix(r, 0) * .82, mix(g, 1) * .82, mix(bl, 2) * .82)); face(p, 16, 0, rgb(mix(r, 0) * .64, mix(g, 1) * .64, mix(bl, 2) * .64)); }
        ctx.beginPath(); quad(ctx, p, 0, lerp(.35, .12, e) * s); ctx.fillStyle = rgb(mix(r, 0), mix(g, 1), mix(bl, 2)); ctx.fill();
        ctx.strokeStyle = 'rgba(' + fg[0] + ',' + fg[1] + ',' + fg[2] + ',' + (active === PLATE ? .7 : .08) + ')'; ctx.lineWidth = active === PLATE ? 1.5 : 1; ctx.stroke();
      }
      order.sort((a, c) => (wk[a] + .5) * sn + (dy[a] + .5) * cs - ((wk[c] + .5) * sn + (dy[c] + .5) * cs));
      const w = width(e), off = (1 - w) / 2, radius = lerp(.17, .03, e) * s, outline = (1 - e) * .06, lift = .7 * e, base = plate ? PLATE_H * e : 0;
      const glow = n <= 150 && e > .5, flat = col[5];
      for (let k = 0; k < n; k++) {
        const i = order[k], x0 = wk[i] + off, y0 = dy[i] + off, x1 = x0 + w, y1 = y0 + w, z = base + zs[i] + hover[i] * lift, o = i * 24;
        polys[o] = px(x0, y0); polys[o + 1] = py(x0, y0, z); polys[o + 2] = px(x1, y0); polys[o + 3] = py(x1, y0, z); polys[o + 4] = px(x1, y1); polys[o + 5] = py(x1, y1, z); polys[o + 6] = px(x0, y1); polys[o + 7] = py(x0, y1, z);
        polys[o + 8] = px(x0, y1); polys[o + 9] = py(x0, y1, base); polys[o + 10] = px(x1, y1); polys[o + 11] = py(x1, y1, base); polys[o + 12] = polys[o + 4]; polys[o + 13] = polys[o + 5]; polys[o + 14] = polys[o + 6]; polys[o + 15] = polys[o + 7];
        polys[o + 16] = px(x1, y0); polys[o + 17] = py(x1, y0, base); polys[o + 18] = polys[o + 10]; polys[o + 19] = polys[o + 11]; polys[o + 20] = polys[o + 4]; polys[o + 21] = polys[o + 5]; polys[o + 22] = polys[o + 2]; polys[o + 23] = polys[o + 3];
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
        if (glow && lv[i] <= 1 && d < .5) { ctx.shadowColor = rgb(c[0], c[1], c[2]); ctx.shadowBlur = 18 * e * (1 - d); }
        ctx.beginPath(); quad(ctx, polys, o, radius); ctx.fillStyle = rgb(r, g, bl); ctx.fill();
        ctx.shadowBlur = 0;
        if (outline > .004) { ctx.strokeStyle = 'rgba(' + fg[0] + ',' + fg[1] + ',' + fg[2] + ',' + outline.toFixed(3) + ')'; ctx.lineWidth = 1; ctx.stroke(); }
        if (hv > .02) { ctx.strokeStyle = 'rgba(' + fg[0] + ',' + fg[1] + ',' + fg[2] + ',' + (.85 * hv).toFixed(3) + ')'; ctx.lineWidth = 1.5; ctx.stroke(); }
      }
      if (active >= 0) {
        const i = active, z = base + zs[i] + hover[i] * lift, rc = canvas.getBoundingClientRect();
        const tx = px(wk[i] + .5, dy[i] + .5), ty = Math.min(py(wk[i] + off, dy[i] + off, z), py(wk[i] + off + w, dy[i] + off, z), py(wk[i] + off, dy[i] + off + w, z));
        tip.style.left = Math.min(Math.max(rc.left + tx, 150), innerWidth - 150) + 'px'; tip.style.top = (rc.top + ty) + 'px';
      } else if (active === PLATE) {
        const rc = canvas.getBoundingClientRect();
        tip.style.left = Math.min(Math.max(rc.left + platePoly[10], 150), innerWidth - 150) + 'px'; tip.style.top = (rc.top + platePoly[11] + 58) + 'px';
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
    const describe = (i) => { const g = items[i]; return g.dep.Name + '@' + g.dep.Version + ': ' + (g.advs.length ? plural(g.advs.length, 'advisory', 'advisories') + ', worst ' + SEV[g.worst].label.toLowerCase() + (g.fixTo ? ', upgrade to ' + g.fixTo : '') : 'no known issues'); };
    const showTip = () => {
      if (active === -1) { tip.classList.remove('on'); return; }
      if (active === PLATE) tip.innerHTML = '<b>' + cleanCount + '</b> ' + (cleanCount === 1 ? 'package' : 'packages') + ' with no known advisories<br><span style="opacity:.7">Click to show every package</span>';
      else { const g = items[active]; tip.innerHTML = '<span class="mono">' + esc(g.dep.Name) + '<span style="opacity:.6">@' + esc(g.dep.Version) + '</span></span><br>' + (g.advs.length ? plural(g.advs.length, 'advisory', 'advisories') + ', worst ' + SEV[g.worst].label.toLowerCase() + (g.fixTo ? '. Upgrade to ' + esc(g.fixTo) : '') : 'No known advisories'); }
      tip.classList.add('on'); draw();
    };
    const refresh = () => { const next = hovered !== -1 ? hovered : pinned; if (next === active) return; active = next; showTip(); kick(); };
    const hit = (x, y) => {
      for (let k = n - 1; k >= 0; k--) { const i = order[k], o = i * 24; if (inQuad(polys, o, x, y) || (faces[i] & 1 && inQuad(polys, o + 8, x, y)) || (faces[i] & 2 && inQuad(polys, o + 16, x, y))) return i; }
      if (plate && (inQuad(platePoly, 0, x, y) || inQuad(platePoly, 8, x, y) || inQuad(platePoly, 16, x, y))) return PLATE;
      return -1;
    };
    const local = (ev) => { const r = canvas.getBoundingClientRect(); return [ev.clientX - r.left, ev.clientY - r.top]; };
    const setMode = (md) => { if (cur.skyMode === md) return; cur.skyMode = md; cur.skyModeSet = true; tip.classList.remove('on'); const mb = $('skyMode'); if (mb) mb.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.m === md))); startSky(m, true); };
    const goTo = (i) => { if (i === PLATE) { setMode('all'); return; } tip.classList.remove('on'); openPkg(items[i].key); };

    let drag = null;
    on(canvas, 'pointerdown', (ev) => { if (ev.button !== 0) return; const can = target === 1; drag = { id: ev.pointerId, x: ev.clientX, y: ev.clientY, yaw: yawGoal, elev: elevGoal, moved: false, orbit: can, mouse: ev.pointerType === 'mouse' }; if (can) try { canvas.setPointerCapture(ev.pointerId); } catch (e) { /* capture is best effort */ } });
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
      if (ev.pointerType === 'mouse' || pinned === i) goTo(i); else { pinned = i; hovered = -1; refresh(); }
    });
    on(canvas, 'pointercancel', () => { drag = null; });
    on(canvas, 'pointerleave', () => { if (!drag) { hovered = -1; refresh(); } });
    on(canvas, 'dblclick', () => { yawGoal = 0; elevGoal = 0; kick(); });
    on(canvas, 'keydown', (ev) => {
      const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End', 'Escape', 'Enter', ' '];
      if (!keys.includes(ev.key) || !n) return;
      ev.preventDefault();
      if (ev.key === 'Escape') { pinned = hovered = -1; refresh(); return; }
      if (ev.key === 'Enter' || ev.key === ' ') { if (active >= 0) goTo(active); return; }
      let i = active >= 0 ? active : 0;
      if (active >= 0) {
        let x = wk[i], y = dy[i];
        if (ev.key === 'ArrowLeft') x--; if (ev.key === 'ArrowRight') x++; if (ev.key === 'ArrowUp') y--; if (ev.key === 'ArrowDown') y++;
        if (ev.key === 'Home') i = 0; else if (ev.key === 'End') i = n - 1; else if (at.has(x + ',' + y)) i = at.get(x + ',' + y);
      }
      pinned = i; hovered = -1; refresh(); $('skyLive').textContent = describe(pinned);
    });
    on(canvas, 'blur', () => { pinned = -1; refresh(); });
    on(window, 'scroll', () => { if (active !== -1) { hovered = -1; pinned = -1; refresh(); } }, { passive: true });
    const toggle = $('viewToggle');
    const setView = (v) => {
      target = v === '3d' ? 1 : 0; if (!target) { yawGoal = 0; elevGoal = 0; }
      toggle.dataset.v = v; toggle.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === v)));
      $('skyHint').textContent = target ? 'Hover a tower for details, click to open it. Drag to orbit.' : 'Hover a block for details. Arrow keys walk the map.';
      canvas.style.cursor = target ? 'grab' : 'default'; kick();
    };
    on(toggle, 'click', (e) => { const b = e.target.closest('button'); if (b) setView(b.dataset.v); });
    const modeBox = $('skyMode'); if (modeBox) on(modeBox, 'click', (e) => { const b = e.target.closest('button'); if (b) setMode(b.dataset.m); });
    const keys = $('skyKeys');
    on(keys, 'mouseover', (e) => { const b = e.target.closest('.key'); if (b) { legendLevel = +b.dataset.l; kick(); } });
    on(keys, 'mouseleave', () => { legendLevel = -1; kick(); });
    on(keys, 'click', (e) => {
      const b = e.target.closest('.key'); if (!b) return;
      if (+b.dataset.l === 5 && focus) { setMode('all'); return; }
      legendSticky = legendSticky === +b.dataset.l ? -1 : +b.dataset.l;
      keys.querySelectorAll('.key').forEach((k) => k.setAttribute('aria-pressed', String(+k.dataset.l === legendSticky))); kick();
    });
    on(rmq, 'change', () => { reduced = rmq.matches; kick(); });
    const mo = new MutationObserver(retheme); mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    on(matchMedia('(prefers-color-scheme: dark)'), 'change', retheme);
    const ro = new ResizeObserver(() => { if (Math.round(stage.clientWidth) !== W) relayout(); }); ro.observe(stage);
    const io = new IntersectionObserver((en) => { if (en.some((x) => x.isIntersecting) && !entered) { entered = true; if (reduced) t = 1; kick(); io.disconnect(); } }, { threshold: .3 });
    const keepTarget = target; target = 0; retheme(); relayout(); target = keepTarget;
    setView(target ? '3d' : '2d');
    if (entered) kick(); else io.observe(stage);
    cur.sky = { state() { return { t, target }; }, destroy() { if (raf) cancelAnimationFrame(raf); ac.abort(); ro.disconnect(); io.disconnect(); mo.disconnect(); tip.classList.remove('on'); cur.sky = null; } };
  }

  function destroy() { if (cur && cur.sky) cur.sky.destroy(); }
  function current() { return cur; }

  DS.model = { build, summarize, VERDICT, STATUS };
  DS.results = { render, destroy, current, openPkg: (k) => openPkg(k), openReview: (k) => openReview(k), setTab: (t) => setTab(t) };
})();
