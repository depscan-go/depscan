#!/usr/bin/env bash
# The server on your machine: dashboard, scans API, path safety.
source "$(dirname "$0")/lib.sh"
PORT=${PORT:-8099}
URL="http://127.0.0.1:$PORT"
echo "05 · Local server on $URL"

"$BIN/depscan-server" -addr "127.0.0.1:$PORT" -scan-root "$PG/projects" -policy "$PG/policies/default.yaml" >"$OUT/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null' EXIT
wait_for_server "$URL" || { bad "server didn't start" "log: results/server.log"; finish; exit 1; }

expect_http "GET /healthz" 200 GET "$URL/healthz"
expect_http "GET / (dashboard)" 200 GET "$URL/"
if grep -q '<title>DepScan</title>' <<<"$RESP"; then ok "it's the DepScan dashboard"; else bad "dashboard title not found"; fi

expect_http "POST /scans clean-go" 200 POST "$URL/scans" '{"path":"clean-go"}'
# 422 = the scan ran and found violations.
expect_http "POST /scans single-critical-npm" 422 POST "$URL/scans" '{"path":"single-critical-npm"}'
id=$(jq -r .id <<<"$RESP")
expect_http "GET /scans/{id}" 200 GET "$URL/scans/$id"
check "the stored scan has 1 violation" jq -e '(.result.Violations | length) == 1' <<<"$RESP"
expect_http "GET /scans (history)" 200 GET "$URL/scans"
check "history holds both scans" jq -e 'length >= 2' <<<"$RESP"
expect_http "GET /scans/no-such-id" 404 GET "$URL/scans/no-such-id"

# Path safety: nothing outside the scan root may be scanned.
expect_http "POST /scans ../ (outside the scan root)" 400 POST "$URL/scans" '{"path":"../"}'
expect_http "POST /scans /etc (absolute, outside)" 400 POST "$URL/scans" '{"path":"/etc"}'
expect_http "POST /scans without a path" 400 POST "$URL/scans" '{}'
expect_http "POST /scans with broken JSON" 400 POST "$URL/scans" 'not json'

# Without DEPSCAN_WEBHOOK_SECRET the webhook route doesn't exist.
expect_http "POST /webhooks/github while webhooks are off" 405 POST "$URL/webhooks/github" '{}'

finish
