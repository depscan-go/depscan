#!/usr/bin/env bash
# The server on your machine: dashboard, policy, scans API, folder uploads, path safety.
source "$(dirname "$0")/lib.sh"
PORT=${PORT:-8099}
URL="http://127.0.0.1:$PORT"
echo "05 · Local server on $URL"

"$BIN/depscan-server" -addr "127.0.0.1:$PORT" -scan-root "$PG/projects" -policy "$PG/policies/default.yaml" >"$OUT/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null' EXIT
wait_for_server "$URL" || { bad "server didn't start" "log: results/server.log"; finish; exit 1; }

expect_http "GET /healthz" 200 GET "$URL/healthz"
check_dashboard "$URL"
expect_http "GET /policy" 200 GET "$URL/policy"
check "it shows the default policy (blocks CRITICAL and HIGH)" \
  jq -e '.block_severities == ["CRITICAL","HIGH"] and (.digest | test("^[0-9a-f]{64}$"))' <<<"$RESP"

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

# The folder picker: the browser reads the lockfiles and uploads just those.
U="$OUT/upload"
mkdir -p "$U"
upload_json clean-go clean-go >"$U/clean.json"
upload_json vuln-go vuln-go >"$U/vuln.json"
upload_json monorepo monorepo >"$U/monorepo.json"
expect_http "upload clean-go" 200 POST "$URL/scans/upload" "@$U/clean.json"
expect_http "upload vuln-go" 422 POST "$URL/scans/upload" "@$U/vuln.json"
check "it found 2 deps and blocked 1" jq -e '(.result.Deps | length) == 2 and (.result.Violations | length) == 1' <<<"$RESP"
expect_http "upload monorepo (lockfiles in subfolders)" 422 POST "$URL/scans/upload" "@$U/monorepo.json"
check "it scanned both lockfiles (2 violations)" jq -e '(.result.Violations | length) == 2' <<<"$RESP"
gzip -c "$U/clean.json" >"$U/clean.json.gz"
expect_http "upload gzipped" 200 POST "$URL/scans/upload" "@$U/clean.json.gz" "Content-Encoding: gzip"
expect_http "upload with ../ in a path" 400 POST "$URL/scans/upload" '{"name":"x","files":[{"path":"../go.mod","content":"module x"}]}'
expect_http "upload of a file that isn't a lockfile" 400 POST "$URL/scans/upload" '{"name":"x","files":[{"path":"etc/passwd","content":"root:x:0:0"}]}'
expect_http "upload that isn't JSON" 415 POST "$URL/scans/upload" "@$U/clean.json" "Content-Type: text/plain"
expect_http "upload from another website" 403 POST "$URL/scans/upload" "@$U/clean.json" "Sec-Fetch-Site: cross-site"
python3 -c 'import json; print(json.dumps({"name": "big", "files": [{"path": "go.mod", "content": "a" * 1100000}]}))' >"$U/big.json"
expect_http "upload over 1 MB" 413 POST "$URL/scans/upload" "@$U/big.json"

# Without DEPSCAN_WEBHOOK_SECRET the webhook route doesn't exist.
expect_http "POST /webhooks/github while webhooks are off" 405 POST "$URL/webhooks/github" '{}'

finish
