#!/usr/bin/env bash
# The deployed app on Azure. Change the target with DEPSCAN_URL=...
source "$(dirname "$0")/lib.sh"
URL=${DEPSCAN_URL:-https://depscan-server.thankfulbeach-61661ef7.malaysiawest.azurecontainerapps.io}
echo "07 · Live app: $URL"

start=$(date +%s%N)
expect_http "GET /healthz (may wake the app from zero)" 200 GET "$URL/healthz"
echo "        first response took $((($(date +%s%N) - start) / 1000000)) ms"
check "health says ok" jq -e '.status == "ok"' <<<"$RESP"

expect_http "GET / (dashboard)" 200 GET "$URL/"
if grep -q '<title>DepScan</title>' <<<"$RESP"; then ok "it's the DepScan dashboard, not the Azure placeholder"; else bad "dashboard title not found"; fi
for asset in app.css app.js backdrop.js demo.js learn.js; do
  expect_http "GET /assets/$asset" 200 GET "$URL/assets/$asset"
done

# The container's scan root (/scans) is empty, so this scan finds nothing.
expect_http "POST /scans . (empty scan root)" 200 POST "$URL/scans" '{"path":"."}'
expect_http "POST /scans /etc (outside the scan root)" 400 POST "$URL/scans" '{"path":"/etc"}'
expect_http "GET /scans" 200 GET "$URL/scans"
# Webhooks are on: a delivery without a valid GitHub signature is rejected.
expect_http "webhook rejects an unsigned delivery" 401 POST "$URL/webhooks/github" '{}'

finish
