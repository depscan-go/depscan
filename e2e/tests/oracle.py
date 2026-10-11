#!/usr/bin/env python3
"""Independent check of depscan's numbers.

For every sample project this works out, on its own, what the default policy
should report: it reads the lockfiles, asks OSV.dev for vulnerabilities and
deps.dev for licenses, merges duplicate advisories (GHSA / GO / CVE aliases)
and applies the policy rules. Then it runs depscan and compares the counts.

It shares no code with depscan, so agreement actually means something.
"""
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

PG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.path.join(PG, "policies", "default.yaml")
PROJECTS = ["clean-go", "vuln-go", "gpl-go", "single-critical-npm", "vuln-npm", "gpl-npm",
            "dual-license-npm", "unknown-license-npm", "monorepo", "broken-lockfile"]
RANK = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
BLOCK, WARN = {"CRITICAL", "HIGH"}, {"MODERATE", "MEDIUM"}
UNKNOWN_LICENSES = {"", "non-standard", "noassertion", "unknown"}


def fetch_json(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def denied_licenses():
    """The denied_licenses list from the policy file (no YAML library needed)."""
    denied, inside = set(), False
    for line in open(POLICY):
        if line.startswith("denied_licenses:"):
            inside = True
            continue
        if inside:
            m = re.match(r"\s+-\s+([^\s#]+)", line)
            if m:
                denied.add(m.group(1).upper())
            elif line.strip() and not line.lstrip().startswith("#"):
                break
    return denied


def read_deps(project):
    """(ecosystem, name, version) for every dependency, skipping vendor/ and node_modules/."""
    deps = set()
    for root, dirs, files in os.walk(os.path.join(PG, "projects", project)):
        dirs[:] = [d for d in dirs if d not in ("vendor", "node_modules", ".git")]
        if "go.mod" in files:
            # Drop // comments first: a ")" inside a comment would otherwise end the require block.
            text = re.sub(r"//[^\n]*", "", open(os.path.join(root, "go.mod")).read())
            lines = [l for block in re.findall(r"require\s*\((.*?)\)", text, re.S) for l in block.splitlines()]
            lines += re.findall(r"^require\s+(\S+\s+\S+)", text, re.M)
            for line in lines:
                m = re.match(r"\s*(\S+)\s+(v\S+)", line)
                if m:
                    deps.add(("Go", m.group(1), m.group(2)))
        if "package-lock.json" in files:
            try:
                lock = json.load(open(os.path.join(root, "package-lock.json")))
            except ValueError:
                continue  # unreadable lockfile: skipped
            if lock.get("lockfileVersion") not in (2, 3):
                continue  # v1 lockfiles aren't supported: skipped
            for path, pkg in lock.get("packages", {}).items():
                if path and not pkg.get("link") and "version" in pkg:
                    deps.add(("npm", path.rsplit("node_modules/", 1)[-1], pkg["version"]))
    return sorted(deps)


def vulnerabilities(deps):
    """One entry per (dependency, distinct vulnerability), aliases merged."""
    if not deps:
        return []
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v[1:] if e == "Go" else v} for e, n, v in deps]
    results = fetch_json("https://api.osv.dev/v1/querybatch", {"queries": queries})["results"]
    ids = sorted({v["id"] for r in results for v in r.get("vulns", [])})
    with ThreadPoolExecutor(8) as pool:
        details = dict(zip(ids, pool.map(lambda i: fetch_json(f"https://api.osv.dev/v1/vulns/{i}"), ids)))
    found = []
    for dep, r in zip(deps, results):
        groups = []  # each: {"names": all ids+aliases, "ids": advisories found for this dep}
        for vid in (v["id"] for v in r.get("vulns", [])):
            names, members = {vid, *details[vid].get("aliases", [])}, [vid]
            for g in [g for g in groups if g["names"] & names]:
                groups.remove(g)
                names |= g["names"]
                members += g["ids"]
            groups.append({"names": names, "ids": members})
        for g in groups:
            labels = [((details[i].get("database_specific") or {}).get("severity") or "").upper() for i in g["ids"]]
            known = [l for l in labels if l in RANK]
            found.append((dep, sorted(g["ids"]), max(known, key=RANK.get) if known else "UNKNOWN"))
    return found


def license_list(dep):
    eco, name, version = dep
    system = "go" if eco == "Go" else "npm"
    url = (f"https://api.deps.dev/v3/systems/{system}/packages/{urllib.parse.quote(name, safe='')}"
           f"/versions/{urllib.parse.quote(version, safe='')}")
    try:
        return fetch_json(url).get("licenses") or []
    except Exception:
        return []


def spdx_allowed(expr, denied):
    """Evaluates an SPDX expression: OR = any option allowed, AND = every part allowed."""
    tokens, pos = re.findall(r"\(|\)|[^\s()]+", expr), 0

    def peek():
        return tokens[pos].upper() if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def any_of():
        ok = all_of()
        while peek() == "OR":
            take()
            ok = all_of() or ok
        return ok

    def all_of():
        ok = one()
        while peek() == "AND":
            take()
            ok = one() and ok
        return ok

    def one():
        if peek() == "(":
            take()
            ok = any_of()
            take()
            return ok
        lic = take().upper()
        if peek() == "WITH":  # a license exception doesn't change the base license
            take()
            take()
        lic = lic[:-1] + "-OR-LATER" if lic.endswith("+") else lic
        return lic not in denied

    return any_of()


def oracle(project, denied):
    deps = read_deps(project)
    violations, warnings = [], []
    for dep, ids, severity in vulnerabilities(deps):
        item = f"{dep[1]}@{dep[2]} {'/'.join(ids)} {severity}"
        if severity in BLOCK:
            violations.append(item)
        elif severity in WARN:
            warnings.append(item)
    with ThreadPoolExecutor(8) as pool:
        for dep, lics in zip(deps, pool.map(license_list, deps)):
            if not lics or any(l.strip().lower() in UNKNOWN_LICENSES for l in lics):
                warnings.append(f"{dep[1]}@{dep[2]} license unknown {lics}")
            elif not all(spdx_allowed(l, denied) for l in lics):  # every license file applies
                violations.append(f"{dep[1]}@{dep[2]} license denied {lics}")
    return len(deps), violations, warnings


def depscan(project):
    out = subprocess.run([os.path.join(PG, "bin", "depscan"), "-path", f"projects/{project}", "-policy", POLICY],
                         cwd=PG, capture_output=True, text=True).stdout
    counts = dict(re.findall(r"^(Dependencies|Violations|Warnings):\s+(\d+)", out, re.M))
    items = [l.strip() for l in out.splitlines() if l.strip().startswith(("[BLOCK]", "[WARN]"))]
    return {k: int(v) for k, v in counts.items()}, items


def main():
    denied = denied_licenses()
    print("08 · Independent check against OSV.dev and deps.dev (default policy)\n")
    print(f"  {'project':22} {'expected deps/viol/warn':>24}   {'depscan':>13}")
    mismatches = 0
    for project in PROJECTS:
        deps, viol, warn = oracle(project, denied)
        got, items = depscan(project)
        want = (deps, len(viol), len(warn))
        have = (got.get("Dependencies"), got.get("Violations"), got.get("Warnings"))
        same = want == have
        mismatches += not same
        mark = "\033[32mPASS\033[0m" if same else "\033[31mFAIL\033[0m"
        print(f"  {mark}  {project:22} {'%d / %d / %d' % want:>16}   {'%s / %s / %s' % have:>13}")
        if not same:
            print("        expected violations:", *viol or ["(none)"], sep="\n          ")
            print("        expected warnings:", *warn or ["(none)"], sep="\n          ")
            print("        depscan said:", *items or ["(nothing)"], sep="\n          ")
    print(f"\n08-oracle: {len(PROJECTS) - mismatches} passed, {mismatches} failed")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
