#!/usr/bin/env bash
# The deployed app on Azure. Change the target with DEPSCAN_URL=...
source "$(dirname "$0")/lib.sh"
URL=${DEPSCAN_URL:-https://depscan-server.thankfulbeach-61661ef7.malaysiawest.azurecontainerapps.io}
echo "07 · Live app: $URL"

start=$(date +%s%N)
expect_http "GET /healthz (may wake the app from zero)" 200 GET "$URL/healthz"
echo "        first response took $((($(date +%s%N) - start) / 1000000)) ms"
check "health says ok" jq -e '.status == "ok"' <<<"$RESP"

check_dashboard "$URL"
expect_http "GET /policy" 200 GET "$URL/policy"
check "it shows the default policy (blocks CRITICAL and HIGH)" jq -e '.block_severities == ["CRITICAL","HIGH"]' <<<"$RESP"

# The folder picker is how people scan their own projects on the live site.
upload_json vuln-go vuln-go >"$OUT/live-upload.json"
expect_http "upload vuln-go" 422 POST "$URL/scans/upload" "@$OUT/live-upload.json"
check "it found 2 deps and blocked 1" jq -e '(.result.Deps | length) == 2 and (.result.Violations | length) == 1' <<<"$RESP"
# The scan is saved, so its link keeps working, even after the app sleeps.
id=$(jq -r .id <<<"$RESP")
expect_http "the upload reads back by its ID" 200 GET "$URL/scans/$id"
check "it is the same scan" jq -e --arg id "$id" '.id == $id and (.result.Deps | length) == 2' <<<"$RESP"
expect_http "upload with ../ in a path" 400 POST "$URL/scans/upload" '{"name":"x","files":[{"path":"../go.mod","content":"module x"}]}'
expect_http "upload from another website" 403 POST "$URL/scans/upload" "@$OUT/live-upload.json" "Sec-Fetch-Site: cross-site"

# The container's scan root (/scans) is empty, so this scan finds nothing.
expect_http "POST /scans . (empty scan root)" 200 POST "$URL/scans" '{"path":"."}'
expect_http "POST /scans /etc (outside the scan root)" 400 POST "$URL/scans" '{"path":"/etc"}'
expect_http "GET /scans is only for local servers" 404 GET "$URL/scans"
# Webhooks are on: a delivery without a valid GitHub signature is rejected.
expect_http "webhook rejects an unsigned delivery" 401 POST "$URL/webhooks/github" '{}'

finish
