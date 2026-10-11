#!/usr/bin/env bash
# CLI scans of every sample project with the default policy.
# Default policy: blocks CRITICAL/HIGH vulns and GPL/AGPL licenses,
# warns on MODERATE vulns and unknown licenses.
source "$(dirname "$0")/lib.sh"
echo "01 · CLI scans with the default policy"

#           name                 project              policy        exit viol warn
expect_scan clean-go             clean-go             default.yaml  0    0    0
# jwt-go HIGH blocks, gin MODERATE warns. OSV lists each vuln twice (GHSA + GO id); both must be merged.
expect_scan vuln-go              vuln-go              default.yaml  1    1    1
# deps.dev lists several license files for go-ethereum, one is GPL-3.0; all of them apply.
expect_scan gpl-go               gpl-go               default.yaml  1    1    0
expect_scan single-critical-npm  single-critical-npm  default.yaml  1    1    0
# Exact counts move whenever OSV adds advisories; 08-oracle checks them against OSV directly.
expect_scan vuln-npm             vuln-npm             default.yaml  1    -    -
# ffmpeg-static is GPL-3.0-or-later. Its dependencies may add unknown-license warnings.
expect_scan gpl-npm              gpl-npm              default.yaml  1    1    -
# jszip is "GPL-3.0-or-later OR MIT", so MIT can be chosen: must pass.
expect_scan dual-license-npm     dual-license-npm     default.yaml  0    0    0
# highcharts has a non-standard license: a warning, not a failure.
expect_scan unknown-license-npm  unknown-license-npm  default.yaml  0    0    1
# Finds the go.mod and lockfile in subfolders, skips the traps in vendor/ and node_modules/.
expect_scan monorepo             monorepo             default.yaml  1    2    0
deps=$(count Dependencies)
if [ "$deps" = 2 ]; then ok "monorepo: traps in vendor/ and node_modules/ were skipped (2 deps)"; else bad "monorepo: $deps deps scanned" "expected 2: something inside vendor/ or node_modules/ was scanned"; fi

finish
