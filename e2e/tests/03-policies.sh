#!/usr/bin/env bash
# Policy behaviour: exceptions, strict mode, switches, and a bad policy file.
source "$(dirname "$0")/lib.sh"
echo "03 · Policy rules"

#           name                    project              policy                    exit viol warn
expect_scan exception               single-critical-npm  exception.yaml            0    0    0
if grep -q '\[skip\] GHSA-xvch-5gv4-984h' "$LOG"; then ok "the skipped vuln is logged with its reason"; else bad "no [skip] line for the excepted vuln" "log: results/exception.log"; fi
expect_scan exception-by-alias      single-critical-npm  exception-alias.yaml      0    0    0
expect_scan exception-expired       single-critical-npm  exception-expired.yaml    1    1    0
expect_scan exception-no-reason     single-critical-npm  exception-no-reason.yaml  2    -    -
expect_scan exception-bad-date      single-critical-npm  exception-bad-date.yaml   2    -    -
# Strict: MODERATE blocks too (gin), and unknown licenses fail the scan.
expect_scan strict-vuln-go          vuln-go              strict.yaml               1    2    0
expect_scan strict-unknown-license  unknown-license-npm  strict.yaml               1    1    0
expect_scan no-license-check        gpl-npm              no-license-check.yaml     0    0    0

# A typo in block_severities should be rejected. If it's silently accepted,
# HIGH vulns stop blocking without anyone noticing.
scan bad-severity vuln-go bad-severity.yaml
if [ "$RC" = 2 ]; then
  ok "a typo in block_severities is rejected (exit 2)"
else
  gap "typo 'HIHG' in block_severities is accepted (exit $RC): HIGH vulns silently stop blocking" \
    "worth raising with Debjit: policy.Load could reject unknown severity names"
fi

finish
