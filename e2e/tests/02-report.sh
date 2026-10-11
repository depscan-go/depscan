#!/usr/bin/env bash
# SBOM report, its fingerprint, tamper detection and the anchor receipt.
source "$(dirname "$0")/lib.sh"
echo "02 · CycloneDX report, fingerprint and anchor receipt"

R="$OUT/report"
rm -rf "$R"
mkdir -p "$R"

scan report-clean clean-go default.yaml -report results/report/clean.json -commit playground
if [ "$RC" = 0 ]; then ok "report run passes (exit 0)"; else bad "report run exited $RC" "log: results/report-clean.log"; fi
check "it's CycloneDX 1.5 with 3 components" jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5" and (.components | length) == 3' "$R/clean.json"
check "components carry package URLs" jq -e '[.components[].purl] | any(startswith("pkg:golang/github.com/google/uuid@"))' "$R/clean.json"
check "the commit is recorded in the report" jq -e '.metadata.properties[] | select(.name == "depscan:commit" and .value == "playground")' "$R/clean.json"
check "sha256sum -c accepts the fingerprint file" bash -c "cd '$R' && sha256sum -c clean.json.sha256"

# Tamper: change one version number, then check it against the original fingerprint.
sed 's/"1.6.0"/"1.6.1"/' "$R/clean.json" >"$R/tampered.json"
check "the tampered copy really differs" bash -c "! cmp -s '$R/clean.json' '$R/tampered.json'"
if (cd "$R" && sed 's/clean\.json$/tampered.json/' clean.json.sha256 | sha256sum -c) >/dev/null 2>&1; then
  bad "an edited report still matched the fingerprint"
else
  ok "an edited report fails the fingerprint check"
fi

# Deterministic: a second scan of the same input differs only in its timestamp.
sleep 1
scan report-clean-again clean-go default.yaml -report results/report/clean-again.json -commit playground
check "the same input gives the same report (apart from the timestamp)" bash -c \
  "diff <(jq -S 'del(.metadata.timestamp)' '$R/clean.json') <(jq -S 'del(.metadata.timestamp)' '$R/clean-again.json')"

scan report-vuln vuln-go default.yaml -report results/report/vuln.json
check "vuln report lists 2 vulnerabilities (GHSA/GO duplicates merged)" jq -e '(.vulnerabilities | length) == 2' "$R/vuln.json"
check "vuln report records result=fail with 1 violation" jq -e \
  '[.metadata.properties[] | {(.name): .value}] | add | .["depscan:result"] == "fail" and .["depscan:violations"] == "1"' "$R/vuln.json"

scan report-anchor clean-go default.yaml -report results/report/anchored.json -anchor noop
if [ "$RC" = 0 ]; then ok "anchoring with the noop backend passes (exit 0)"; else bad "anchor run exited $RC" "log: results/report-anchor.log"; fi
check "the receipt's digest matches the report's fingerprint" bash -c \
  "[ \"\$(jq -r .digest '$R/anchored.json.anchor.json')\" = \"sha256:\$(cut -d' ' -f1 '$R/anchored.json.sha256')\" ]"

finish
