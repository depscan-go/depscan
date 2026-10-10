/* Learn: a floating panel that explains the terms DepScan uses.
   Any element with data-learn="<topic>" opens it at that topic. */
(function () {
  'use strict';

  /* ---------- SHA-256 (shared with the walkthrough) ----------
     Small, synchronous and dependency-free, so the walkthrough can show the
     real digest of the text on screen and the Learn panel can hash as you
     type, even on plain http where crypto.subtle is not available. */
  const Hash = (() => {
    const K = new Uint32Array(64), H0 = new Uint32Array(8);
    const frac = (x) => ((x - Math.floor(x)) * 4294967296) >>> 0;
    for (let n = 0, c = 2; n < 64; c++) {
      let prime = true;
      for (let d = 2; d * d <= c; d++) if (c % d === 0) { prime = false; break; }
      if (!prime) continue;
      if (n < 8) H0[n] = frac(Math.sqrt(c));
      K[n++] = frac(Math.cbrt(c));
    }
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    // trace, when given, receives the eight working variables after each round of the first block.
    function digest(bytes, trace) {
      const len = bytes.length, total = ((len + 9 + 63) >> 6) << 6;
      const m = new Uint8Array(total); m.set(bytes); m[len] = 0x80;
      const dv = new DataView(m.buffer);
      dv.setUint32(total - 8, Math.floor(len / 0x20000000)); dv.setUint32(total - 4, (len << 3) >>> 0);
      const h = H0.slice(), w = new Uint32Array(64);
      for (let o = 0; o < total; o += 64) {
        for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
        for (let i = 16; i < 64; i++) {
          const a = w[i - 15], b = w[i - 2];
          w[i] = (w[i - 16] + (rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3)) + w[i - 7] + (rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10))) | 0;
        }
        let A = h[0], B = h[1], C = h[2], D = h[3], E = h[4], F = h[5], G = h[6], Hh = h[7];
        for (let i = 0; i < 64; i++) {
          const t1 = (Hh + (rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25)) + ((E & F) ^ (~E & G)) + K[i] + w[i]) | 0;
          const t2 = ((rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + ((A & B) ^ (A & C) ^ (B & C))) | 0;
          Hh = G; G = F; F = E; E = (D + t1) | 0; D = C; C = B; B = A; A = (t1 + t2) | 0;
          if (trace && o === 0) trace.push([A, B, C, D, E, F, G, Hh].map((v) => v >>> 0));
        }
        h[0] += A; h[1] += B; h[2] += C; h[3] += D; h[4] += E; h[5] += F; h[6] += G; h[7] += Hh;
      }
      const out = new Uint8Array(32), ov = new DataView(out.buffer);
      for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i]);
      return out;
    }
    const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
    const utf8 = (s) => new TextEncoder().encode(s);
    function hmac(key, msg) {
      let k = utf8(key); if (k.length > 64) k = digest(k);
      const ip = new Uint8Array(64 + 0), op = new Uint8Array(64);
      for (let i = 0; i < 64; i++) { const b = k[i] || 0; ip[i] = b ^ 0x36; op[i] = b ^ 0x5c; }
      const m = utf8(msg), inner = new Uint8Array(64 + m.length); inner.set(ip); inner.set(m, 64);
      const ih = digest(inner), outer = new Uint8Array(96); outer.set(op); outer.set(ih, 64);
      return hex(digest(outer));
    }
    return { sha256: (s, trace) => hex(digest(utf8(s), trace)), hmac };
  })();
  window.DepscanHash = Hash;

  /* ---------- icons ---------- */
  const I = {
    box: '<path d="M12 2.8 20.5 7.4v9.2L12 21.2 3.5 16.6V7.4Z"/><path d="M3.5 7.4 12 12l8.5-4.6M12 12v9.2"/>',
    tree: '<circle cx="12" cy="4.5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 6.5v10.5M12 11H5.8a.8.8 0 0 0-.8.8V17M12 11h6.2a.8.8 0 0 1 .8.8V17"/>',
    lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2.2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2.5"/>',
    tag: '<path d="M3.5 12.2V4.8a1.3 1.3 0 0 1 1.3-1.3h7.4l8.3 8.3a1.3 1.3 0 0 1 0 1.8l-7.4 7.4a1.3 1.3 0 0 1-1.8 0Z"/><circle cx="8.3" cy="8.3" r="1.5"/>',
    bug: '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 7v13M7 12H3.5M20.5 12H17M7.6 16.5l-3 2.5M16.4 16.5l3 2.5M7.6 8.6 4.8 6M16.4 8.6 19.2 6M9 7.2a3 3 0 0 1 6 0"/>',
    id: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M7 10h4M7 14h7M16 9.5v5"/>',
    gauge: '<path d="M4.2 17.5a9 9 0 1 1 15.6 0"/><path d="m12 13.5 4-5"/><circle cx="12" cy="13.5" r="1.4"/>',
    db: '<ellipse cx="12" cy="5.8" rx="7.5" ry="2.8"/><path d="M4.5 5.8v12.4c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8V5.8M4.5 12c0 1.5 3.4 2.8 7.5 2.8s7.5-1.3 7.5-2.8"/>',
    up: '<path d="M12 20V5M6 11l6-6 6 6"/><path d="M5 20h14"/>',
    merge: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10M6 7c0 3.5 3 5 10 5"/>',
    alert: '<path d="M12 3.5 21.5 20h-19Z"/><path d="M12 10v4.5M12 17.2v.3"/>',
    scale: '<path d="M12 3.5v17M7 20.5h10M5 7.5h14M5 7.5l-3 6.5a3 3 0 0 0 6 0Zm14 0-3 6.5a3 3 0 0 0 6 0Z"/>',
    copy: '<circle cx="12" cy="12" r="8.5"/><path d="M14.6 9.4a3.7 3.7 0 1 0 0 5.2"/>',
    code: '<path d="m8.5 7.5-5 4.5 5 4.5M15.5 7.5l5 4.5-5 4.5"/>',
    shield: '<path d="M12 3 19.5 6v5.6c0 4.4-3.1 8-7.5 9.4-4.4-1.4-7.5-5-7.5-9.4V6Z"/><path d="m8.8 12 2.2 2.2 4.2-4.4"/>',
    clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    doc: '<path d="M6 2.8h8l4.5 4.5v13.9H6Z"/><path d="M14 2.8v4.5h4.5M9 12h6M9 15.5h6"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3.2-3.2a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3.2 3.2a4 4 0 0 0 5.7 5.7l1-1"/>',
    hash: '<path d="M9.5 3.5 7.5 20.5M16.5 3.5l-2 17M4 9h16.5M3.5 15H20"/>',
    chain: '<rect x="2.5" y="8" width="6" height="8" rx="1.5"/><rect x="9" y="8" width="6" height="8" rx="1.5"/><rect x="15.5" y="8" width="6" height="8" rx="1.5"/>',
    hook: '<path d="M18 16.5a4 4 0 1 1-3.5-6M8.5 7.5a4 4 0 1 1 6.5 3M6 16.5a4 4 0 1 1 1-7.8"/>',
    check: '<circle cx="12" cy="12" r="8.5"/><path d="m8.2 12.2 2.6 2.6 5-5.3"/>'
  };
  const icon = (n) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (I[n] || I.box) + '</svg>';
  const chev = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 3.5 4.5 4.5L6 12.5"/></svg>';

  /* ---------- topics ---------- */
  const GROUPS = ['Basics', 'Vulnerabilities', 'Licenses', 'Policy', 'Reports and trust', 'Pull requests'];
  const T = [
    { id: 'dependency', g: 0, icon: 'box', c: 'var(--act)', title: 'Dependency', ch: 1,
      sum: 'Code your project uses that someone else wrote and publishes.',
      body: '<p>When you run <code>go get</code> or <code>npm install</code>, a package is downloaded from a registry such as proxy.golang.org or npmjs.com and becomes part of your build. Its bugs and security holes become yours too.</p><p>A typical service has tens to hundreds of dependencies, and you chose only a few of them directly.</p>',
      dep: 'DepScan reads which packages and exact versions your project uses from its lockfiles, then checks each one.',
      rel: ['transitive', 'lockfile', 'vulnerability'] },
    { id: 'transitive', g: 0, icon: 'tree', c: 'var(--act)', title: 'Direct and transitive', ch: 2,
      sum: 'Direct ones you added. Transitive ones came along with them.',
      body: '<p>A <b>direct</b> dependency is one you asked for. A <b>transitive</b> (or indirect) one is a dependency of a dependency: you add <code>axios</code>, and <code>follow-redirects</code> comes with it.</p><p>Transitive packages usually outnumber direct ones several times over, and they ship in your build all the same.</p>',
      ex: 'require (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/net v0.10.0 // indirect\n)',
      dep: 'In <code>go.mod</code>, transitive modules carry <code>// indirect</code>. In <code>package-lock.json</code>, direct ones are listed by the root entry. With <code>check_transitive: true</code>, both are held to the same rules.',
      rel: ['dependency', 'lockfile', 'policy'] },
    { id: 'lockfile', g: 0, icon: 'lock', c: 'var(--act)', title: 'Lockfile', ch: 1,
      sum: 'The file that pins the exact version of every package.',
      body: '<p>A manifest says what you want (<code>"axios": "^0.21.1"</code>). A lockfile records what you actually got (<code>0.21.1</code>), so every machine builds the same thing.</p><ul><li><code>go.mod</code> lists the version Go selected for every module the build needs (Go 1.17 and later); <code>go.sum</code> holds their checksums.</li><li><code>package-lock.json</code> (npm 7 or newer) records the whole installed tree.</li></ul>',
      dep: 'DepScan walks the folder for <code>go.mod</code> and <code>package-lock.json</code>, skipping <code>.git</code>, <code>vendor</code> and <code>node_modules</code>. An old npm lockfile (version 1) is rejected with a clear error instead of being read as empty.',
      rel: ['transitive', 'semver'] },
    { id: 'semver', g: 0, icon: 'tag', c: 'var(--act)', title: 'Versions and semver', ch: 7,
      sum: 'MAJOR.MINOR.PATCH, and what each part promises.',
      body: '<p>Semantic versioning numbers releases as <code>MAJOR.MINOR.PATCH</code>. A patch fixes bugs, a minor release adds features, a major release may break your code. Security fixes usually ship in a patch or minor release, so the upgrade is often small.</p><p>Go adds two rules: modules at v2 and above change their import path (<code>…/jwt/v4</code>), and untagged commits get pseudo-versions like <code>v0.0.0-20231218163308-9d2ee975ef9f</code>, a timestamp plus a commit hash.</p>',
      dep: 'DepScan compares versions part by part to find the smallest upgrade that clears every advisory.',
      rel: ['fixed', 'lockfile'] },

    { id: 'vulnerability', g: 1, icon: 'bug', c: 'var(--critical)', title: 'Vulnerability', ch: 4,
      sum: 'A flaw an attacker can use to make code do what it should not.',
      body: '<p>Two from the sample project: a regular expression in axios that a crafted input can keep busy for a very long time (denial of service), and an SSH server callback in <code>golang.org/x/crypto</code> whose misuse can let the wrong key in (authorization bypass).</p><p>Having a vulnerable version does not always mean you are exploitable: that depends on whether your code reaches the affected function. DepScan reports by version, which is fast and errs on the safe side. Tools like <code>govulncheck</code> add call-graph analysis on top.</p>',
      dep: 'Every package is checked against OSV.dev, and each match becomes a row with its severity and the version that fixes it.',
      rel: ['advisory', 'severity', 'osv'] },
    { id: 'advisory', g: 1, icon: 'id', c: 'var(--critical)', title: 'Advisory IDs: CVE, GHSA, GO', ch: 5,
      sum: 'One flaw, several names.',
      body: '<p>An advisory is the public record of a vulnerability: what is affected, how bad it is, and which version fixes it. Different databases number the same flaw:</p><ul><li><code>CVE-2023-39325</code>: the CVE list, run by MITRE.</li><li><code>GHSA-4374-p667-p6c8</code>: the GitHub Advisory Database.</li><li><code>GO-2023-2102</code>: the Go vulnerability database.</li></ul><p>Each record lists the others as <b>aliases</b>.</p>',
      dep: 'Each finding links to its OSV.dev page. Aliases are kept, so an exception written against any of the IDs still matches.',
      rel: ['duplicates', 'osv'] },
    { id: 'severity', g: 1, icon: 'gauge', c: 'var(--high)', title: 'Severity and CVSS', ch: 6, tool: 'cvss',
      sum: 'How bad a flaw is, usually from a CVSS score between 0 and 10.',
      body: '<p>The Common Vulnerability Scoring System rates how easy a flaw is to exploit and how much damage it can do. CVSS v3 maps the score to a label. Drag to see where the lines fall:</p>',
      after: '<p>GitHub calls Medium <b>Moderate</b>; DepScan treats them as the same. Some records, including most GO- entries, carry no severity and show as <b>unrated</b>.</p>',
      dep: 'Your policy picks which labels block the build and which only warn. <code>block_unknown_severity</code> decides what happens to unrated ones.',
      rel: ['policy', 'duplicates'] },
    { id: 'osv', g: 1, icon: 'db', c: 'var(--low)', title: 'OSV.dev', ch: 4,
      sum: 'An open database that gathers advisories from many sources.',
      body: '<p>OSV.dev, run by Google, collects advisories from GitHub, the Go team, PyPI, RustSec and others into one format and one API. You ask by package name, ecosystem and version, and it answers with the advisory IDs that match.</p>',
      ex: 'POST https://api.osv.dev/v1/querybatch\n{"queries": [{\n  "package": {"name": "golang.org/x/net", "ecosystem": "Go"},\n  "version": "0.10.0"\n}]}',
      dep: 'Packages go in batches of 100, then 8 workers fetch each advisory\'s details. Failed requests are retried after 500 ms and 1 s; one that still fails stops the scan, so a network error never looks like a clean result.',
      rel: ['advisory', 'duplicates'] },
    { id: 'fixed', g: 1, icon: 'up', c: 'var(--clean)', title: 'Fixed version and upgrade path', ch: 7,
      sum: 'The first release without the flaw, and the smallest safe upgrade.',
      body: '<p>An advisory lists affected ranges, such as introduced at <code>0</code> and fixed in <code>0.31.0</code>. Moving to the fixed version or later clears it.</p><p>With several advisories on one package, the smallest upgrade that clears them all is the highest of their fixed versions. For <code>golang.org/x/crypto v0.14.0</code> in the sample, the fixes are at 0.17.0, 0.31.0 and 0.35.0, so the answer is <code>v0.35.0</code>.</p>',
      dep: 'The Fixes tab shows this path for every package, with a <code>go get</code> or <code>npm install</code> command you can copy.',
      rel: ['semver', 'severity'] },
    { id: 'duplicates', g: 1, icon: 'merge', c: 'var(--low)', title: 'Duplicate advisories', ch: 5,
      sum: 'The same flaw reported twice, merged into one row.',
      body: '<p>Because OSV.dev gathers several databases, one bug in one package often comes back as two records, such as <code>GO-2023-2102</code> and <code>GHSA-4374-p667-p6c8</code>. Counting both inflates every number.</p><p>Worse, the GO- record has no severity. Left alone, it shows up as unrated and slips past a policy that blocks HIGH.</p>',
      dep: 'Records for the same package version that share any ID or alias are merged. The kept record is the one with a severity, then the GHSA one; the other IDs become aliases.',
      rel: ['advisory', 'severity'] },
    { id: 'malicious', g: 1, icon: 'alert', c: 'var(--critical)', title: 'Malicious packages', ch: 4,
      sum: 'Packages published to attack you, not flawed by mistake.',
      body: '<p>Not every risk is an honest bug. Attackers publish look-alike package names, or take over a maintainer account and push a poisoned release. OSV.dev includes these as <code>MAL-</code> records from the OpenSSF Malicious Packages project.</p><p>The fix is different: there is usually no safe version to upgrade to. Remove the package, and rotate any secrets the build could reach.</p>',
      dep: 'MAL- records come back from OSV.dev like any other advisory. A record without a severity counts as unrated, so set <code>block_unknown_severity: true</code> if unrated records should block.',
      rel: ['osv', 'severity'] },

    { id: 'license', g: 2, icon: 'scale', c: 'var(--medium)', title: 'Open source license', ch: 3,
      sum: 'The terms under which you may use someone\'s code.',
      body: '<p>Open source code is free to use under conditions: keep the copyright notice, say what you changed, or share your own source. Those conditions travel with the code into your product.</p><p>They matter most when you ship software to others, so finding a problem license early saves an awkward rewrite later.</p>',
      dep: 'Each package\'s license is looked up on deps.dev and checked against <code>denied_licenses</code>. Packages deps.dev does not know, like private ones, are reported as unknown.',
      rel: ['copyleft', 'spdx'] },
    { id: 'copyleft', g: 2, icon: 'copy', c: 'var(--medium)', title: 'Permissive and copyleft', ch: 3,
      sum: 'Permissive licenses ask for credit. Copyleft ones ask for your source.',
      body: '<ul><li><b>Permissive</b> (MIT, BSD-3-Clause, Apache-2.0): use it anywhere and keep the notice. Apache-2.0 also grants a patent license.</li><li><b>Copyleft</b> (GPL-3.0): if you distribute software that includes it, you must offer the source of the whole work under the GPL.</li><li><b>Network copyleft</b> (AGPL-3.0): the same, even when people only use your software over a network.</li></ul><p>That is why many companies deny GPL and AGPL in products they ship. This is a summary, not legal advice.</p>',
      rel: ['license', 'spdx'] },
    { id: 'spdx', g: 2, icon: 'code', c: 'var(--medium)', title: 'SPDX identifiers', ch: 3,
      sum: 'Exact short names for licenses, like MIT or GPL-3.0-or-later.',
      body: '<p>SPDX gives every common license an exact identifier, so tools can compare them. Expressions combine them:</p><ul><li><code>MIT OR Apache-2.0</code>: you may pick either.</li><li><code>MIT AND BSD-3-Clause</code>: both apply.</li><li><code>GPL-3.0-only</code> or <code>GPL-3.0-or-later</code>: whether later GPL versions may be used.</li></ul>',
      dep: 'An OR expression passes when any option is allowed. An AND expression, or a single ID, fails when any part is denied.',
      rel: ['license', 'copyleft'] },

    { id: 'policy', g: 3, icon: 'shield', c: 'var(--clean)', title: 'Policy file', ch: 6,
      sum: 'One file in your repo that decides what blocks the build.',
      body: '<p><code>policy.yaml</code> lives in your repository, so every scan, on a laptop or in CI, applies the same rules: which severities block, which warn, whether transitive packages count, which licenses are denied, and which exceptions apply.</p>',
      ex: 'block_severities: [CRITICAL, HIGH]\nwarn_severities:  [MODERATE, MEDIUM]\ncheck_transitive: true\ndenied_licenses:  [GPL-3.0-or-later, AGPL-3.0-only]\nblock_unknown_license: false',
      dep: 'A scan with violations exits with code 1, and the API answers 422, so a CI job fails.',
      rel: ['exception', 'severity', 'license'] },
    { id: 'exception', g: 3, icon: 'clock', c: 'var(--clean)', title: 'Exceptions', ch: 6,
      sum: 'A recorded decision to accept one specific risk, for a while.',
      body: '<p>Sometimes an advisory does not apply to you. The sample project never calls gin\'s <code>Context.FileAttachment</code>, so the advisory about it cannot be reached. An exception allows it by ID.</p><p>Each exception needs a <b>reason</b>, so the decision can be reviewed, and can <b>expire</b>, so it comes back for review instead of being forgotten.</p>',
      ex: 'exceptions:\n  - id: GHSA-2c4m-59x9-fr2g\n    reason: FileAttachment is not used\n    expires: 2026-12-31',
      dep: 'An exception without a reason, or with a date that is not YYYY-MM-DD, makes the policy invalid instead of quietly allowing more.',
      rel: ['policy', 'advisory'] },

    { id: 'sbom', g: 4, icon: 'doc', c: 'var(--low)', title: 'SBOM and CycloneDX', ch: 8,
      sum: 'A machine-readable list of everything inside your software.',
      body: '<p>A Software Bill of Materials lists every component with its exact version, the way a food label lists ingredients. When a new vulnerability is announced, an SBOM answers "are we affected?" in seconds.</p><p>CycloneDX is an OWASP standard for SBOMs. It can also carry vulnerabilities and what you decided about them.</p>',
      dep: '<code>depscan -report report.cdx.json</code> writes a CycloneDX 1.5 file with every component, every advisory and its policy outcome, and a hash of the policy that produced it.',
      rel: ['purl', 'sha256'] },
    { id: 'purl', g: 4, icon: 'link', c: 'var(--low)', title: 'Package URL (purl)', ch: 8,
      sum: 'One string that names a package in any ecosystem.',
      body: '<p>A package URL has the form <code>pkg:type/namespace/name@version</code>. SBOMs and advisory databases use it to agree on exactly which package they mean.</p>',
      ex: 'pkg:golang/golang.org/x/crypto@v0.14.0\npkg:npm/axios@0.21.1\npkg:npm/%40shop/ui-kit@2.3.0',
      dep: 'The purl is each component\'s ID in the report. The <code>@</code> of an npm scope is written <code>%40</code>, because a bare <code>@</code> starts the version.',
      rel: ['sbom'] },
    { id: 'sha256', g: 4, icon: 'hash', c: 'var(--act)', title: 'SHA-256 fingerprint', ch: 8, tool: 'sha',
      sum: 'A 64-character fingerprint of a file. Change one byte and it all changes.',
      body: '<p>SHA-256 turns any input into 256 bits, written as 64 hex characters. The same input always gives the same output, and nobody knows how to find two inputs with the same output. Edit the text below and watch the fingerprint:</p>',
      dep: 'Next to each report DepScan writes <code>report.cdx.json.sha256</code>. Run <code>sha256sum -c report.cdx.json.sha256</code> to confirm the report was not changed.',
      rel: ['sbom', 'anchoring'] },
    { id: 'anchoring', g: 4, icon: 'chain', c: 'var(--medium)', title: 'Anchoring a hash (planned)', ch: 9,
      sum: 'Publishing a report\'s fingerprint where nobody can quietly change it.',
      body: '<p>A hash stored next to the report does not stop someone from changing both. Anchoring writes the hash into a public ledger, such as the memo of a Solana transaction, which records it with a timestamp nobody can edit later.</p><p><b>What it proves:</b> this exact report existed, unchanged, at that time. <b>What it does not prove:</b> that the project is still safe. Advisories are published every day, so an old clean report is a fact about the past. Scan again for a current answer.</p>',
      dep: 'Planned: <code>-anchor</code> stores a receipt with the network, transaction and time, and <code>depscan verify</code> re-hashes the report and compares it with the ledger.',
      rel: ['sha256', 'sbom'] },

    { id: 'webhook', g: 5, icon: 'hook', c: 'var(--act)', title: 'Webhooks and signatures', ch: 10,
      sum: 'GitHub calls your server when a pull request changes.',
      body: '<p>A webhook is an HTTP request GitHub sends to a URL you choose when something happens, like a pull request being opened or getting new commits.</p><p>Anyone can send requests to that URL, so GitHub signs each one: the <code>X-Hub-Signature-256</code> header is an HMAC-SHA256 of the body, keyed with a secret only you and GitHub know.</p>',
      dep: 'DepScan checks the signature with a constant-time comparison, answers 202 at once, ignores repeated deliveries, and scans in a background queue. Only the lockfiles at the head commit are downloaded.',
      rel: ['status'] },
    { id: 'status', g: 5, icon: 'check', c: 'var(--clean)', title: 'Commit status checks (planned)', ch: 10,
      sum: 'The tick or cross next to a pull request.',
      body: '<p>A commit status reports a pass or fail for one commit. With branch protection, a repository can require a status to pass before a pull request can be merged.</p>',
      dep: 'Planned: post the scan result as a status on the pull request\'s head commit, with a comment listing what to fix.',
      rel: ['webhook', 'policy'] }
  ];
  const BY = Object.fromEntries(T.map((t) => [t.id, t]));

  /* ---------- panel ---------- */
  const fab = document.getElementById('learnFab'), panel = document.getElementById('learn');
  const list = document.getElementById('learnList'), detail = document.getElementById('learnDetail');
  const q = document.getElementById('learnQ'), closeBtn = document.getElementById('learnClose');
  if (!fab || !panel) return;
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const strip = (s) => String(s).replace(/<[^>]+>/g, ' ');
  let isOpen = false, current = null, returnFocus = null;

  const row = (t) => '<button class="ltopic" type="button" data-topic="' + t.id + '" style="--c:' + t.c + '"><span class="ic">' + icon(t.icon) + '</span><span><b>' + esc(t.title) + '</b><small>' + esc(t.sum) + '</small></span>' + chev + '</button>';
  // Title matches first, then the one-line summary, then the full text.
  function score(t, term) {
    const title = t.title.toLowerCase();
    if (title.startsWith(term)) return 4;
    if (title.includes(term)) return 3;
    if (t.sum.toLowerCase().includes(term)) return 2;
    if ((strip(t.body) + ' ' + strip(t.dep || '') + ' ' + (t.ex || '')).toLowerCase().includes(term)) return 1;
    return 0;
  }
  function renderList() {
    const term = q.value.trim().toLowerCase();
    if (!term) {
      list.innerHTML = GROUPS.map((g, gi) => '<div class="lgroup"><h3>' + g + '</h3>' + T.filter((t) => t.g === gi).map(row).join('') + '</div>').join('');
      return;
    }
    const hits = T.map((t, i) => [t, score(t, term), i]).filter((x) => x[1] > 0).sort((a, b) => b[1] - a[1] || a[2] - b[2]).map((x) => x[0]);
    list.innerHTML = hits.length ? '<div class="lgroup"><h3>' + hits.length + (hits.length === 1 ? ' topic' : ' topics') + '</h3>' + hits.map(row).join('') + '</div>' : '<p class="lempty">Nothing matches “' + esc(term) + '”.</p>';
  }

  function toolHTML(kind) {
    if (kind === 'sha') return '<div class="tool"><label for="shaIn">Text to hash</label><input type="text" id="shaIn" value="depscan:result = fail"><div class="hash" id="shaOut"></div><div class="meta" id="shaMeta"></div></div>';
    if (kind === 'cvss') return '<div class="tool"><label for="cvssIn">CVSS base score</label><input type="range" id="cvssIn" min="0" max="10" step="0.1" value="7.5"><div class="cvss"><b id="cvssN">7.5</b><span id="cvssL"></span></div><div class="bands"><i style="background:var(--low)"></i><i style="background:var(--medium)"></i><i style="background:var(--high)"></i><i style="background:var(--critical)"></i></div><div class="bands-l"><span>Low 0.1</span><span>Medium 4.0</span><span>High 7.0</span><span>Crit. 9.0</span></div></div>';
    return '';
  }
  function wireTool(kind) {
    if (kind === 'sha') {
      const inp = document.getElementById('shaIn'), out = document.getElementById('shaOut'), meta = document.getElementById('shaMeta');
      const base = Hash.sha256(inp.value);
      const upd = () => {
        const h = Hash.sha256(inp.value);
        let diff = 0, html = '';
        for (let i = 0; i < 64; i++) { if (h[i] !== base[i]) { diff++; html += '<i>' + h[i] + '</i>'; } else html += h[i]; }
        out.innerHTML = html;
        meta.textContent = diff ? diff + ' of 64 characters differ from the hash of the original text.' : 'This is the hash of the original text. Change one letter.';
      };
      inp.addEventListener('input', upd); upd();
    } else if (kind === 'cvss') {
      const inp = document.getElementById('cvssIn'), n = document.getElementById('cvssN'), l = document.getElementById('cvssL'), bands = panel.querySelectorAll('.bands i');
      const upd = () => {
        const v = +inp.value, lv = v === 0 ? -1 : v < 4 ? 0 : v < 7 ? 1 : v < 9 ? 2 : 3;
        const names = ['Low', 'Medium', 'High', 'Critical'], vars = ['low', 'medium', 'high', 'critical'];
        n.textContent = v.toFixed(1);
        l.textContent = lv < 0 ? 'None' : names[lv];
        l.style.setProperty('--c', lv < 0 ? 'var(--unknown)' : 'var(--' + vars[lv] + ')');
        l.style.setProperty('--t', lv < 0 ? 'var(--unknown-t)' : 'var(--' + vars[lv] + '-t)');
        bands.forEach((b, i) => b.classList.toggle('on', i === lv));
      };
      inp.addEventListener('input', upd); upd();
    }
  }

  function show(id, focus) {
    const t = BY[id]; if (!t) return;
    current = id;
    detail.innerHTML = '<div class="ldetail" style="--c:' + t.c + '">' +
      '<button class="lback" type="button" data-back><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 3.5 5.5 8l4.5 4.5"/></svg>All topics</button>' +
      '<div class="lhero"><span class="ic">' + icon(t.icon) + '</span><h3>' + esc(t.title) + '</h3></div>' +
      '<p class="lsum">' + esc(t.sum) + '</p>' + t.body + (t.tool ? toolHTML(t.tool) : '') + (t.after || '') +
      (t.ex ? '<pre>' + esc(t.ex) + '</pre>' : '') +
      (t.dep ? '<div class="indep"><b>In DepScan</b>' + t.dep + '</div>' : '') +
      (t.rel && t.rel.length ? '<h4>Related</h4><div class="lrel">' + t.rel.map((r) => '<button type="button" data-topic="' + r + '">' + esc(BY[r].title) + '</button>').join('') + '</div>' : '') +
      (t.ch != null ? '<button class="lwatch" type="button" data-watch="' + t.ch + '"><svg viewBox="0 0 10 10" aria-hidden="true"><path d="M1 0v10l8.5-5z" fill="currentColor"/></svg>See it in the walkthrough</button>' : '') +
      '</div>';
    if (t.tool) wireTool(t.tool);
    detail.scrollTop = 0;
    panel.classList.add('detail');
    if (focus) setTimeout(() => detail.focus({ preventScroll: true }), 60);
  }
  function back() {
    panel.classList.remove('detail'); current = null;
    const b = list.querySelector('.ltopic'); if (b) setTimeout(() => b.focus({ preventScroll: true }), 60);
  }

  function open(id) {
    if (!isOpen) {
      returnFocus = document.activeElement;
      isOpen = true; panel.classList.add('open'); fab.setAttribute('aria-expanded', 'true');
      renderList();
    }
    if (id) show(id, true);
    else { if (q.value) { q.value = ''; renderList(); } back(); if (matchMedia('(pointer: fine)').matches) setTimeout(() => q.focus({ preventScroll: true }), 80); }
  }
  function close() {
    if (!isOpen) return;
    isOpen = false; panel.classList.remove('open'); fab.setAttribute('aria-expanded', 'false');
    if (returnFocus && document.contains(returnFocus) && panel.contains(document.activeElement)) returnFocus.focus({ preventScroll: true });
  }

  fab.addEventListener('click', () => (isOpen ? close() : open()));
  closeBtn.addEventListener('click', close);
  q.addEventListener('input', () => { if (current) panel.classList.remove('detail'); renderList(); });
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { const b = list.querySelector('.ltopic'); if (b) show(b.dataset.topic, true); } });
  panel.addEventListener('click', (e) => {
    const tb = e.target.closest('[data-topic]'); if (tb) { show(tb.dataset.topic, true); return; }
    if (e.target.closest('[data-back]')) { back(); return; }
    const w = e.target.closest('[data-watch]');
    if (w) { close(); document.dispatchEvent(new CustomEvent('depscan:watch', { detail: { chapter: +w.dataset.watch } })); }
  });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-learn]');
    if (t) { e.preventDefault(); open(t.dataset.learn); return; }
    if (isOpen && !panel.contains(e.target) && !fab.contains(e.target)) close();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen) { e.stopPropagation(); close(); return; }
    if (e.key === '?' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); isOpen ? close() : open(); }
  }, true);

  window.Learn = { open, close, topics: BY };
})();
