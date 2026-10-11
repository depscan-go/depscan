#!/usr/bin/env bash
# GitHub webhook on your machine: signature check, event filtering, and a
# real background scan of PR #15 in depscan-go/depscan (public repo).
source "$(dirname "$0")/lib.sh"
PORT=${PORT:-8098}
URL="http://127.0.0.1:$PORT"
SECRET=playground-secret
echo "06 · Local webhook on $URL/webhooks/github"

# GitHub allows only 60 anonymous API requests an hour per IP, so use a token when
# there is one: $GITHUB_TOKEN, else your gh login's. It stays on this machine and
# is only sent to api.github.com.
if [ -z "${GITHUB_TOKEN:-}" ] && command -v gh >/dev/null; then GITHUB_TOKEN=$(gh auth token 2>/dev/null); fi
echo "  (GitHub API: $([ -n "${GITHUB_TOKEN:-}" ] && echo "with a token" || echo "anonymous, 60 requests/hour"))"

DEPSCAN_WEBHOOK_SECRET=$SECRET GITHUB_TOKEN="${GITHUB_TOKEN:-}" "$BIN/depscan-server" -addr "127.0.0.1:$PORT" \
  -scan-root "$PG/projects" -policy "$PG/policies/default.yaml" >"$OUT/webhook-server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; wait $SERVER 2>/dev/null' EXIT
wait_for_server "$URL" || { bad "server didn't start" "log: results/webhook-server.log"; finish; exit 1; }

sign() { printf '%s' "$1" | openssl dgst -sha256 -hmac "$SECRET" -r | cut -d' ' -f1; }

# deliver NAME WANT_CODE EVENT BODY [SIGNATURE] [DELIVERY_ID]
deliver() {
  local name=$1 want=$2 event=$3 body=$4 sig=${5-sha256=$(sign "$4")} id=${6:-$RANDOM$RANDOM}
  CODE=$(curl -s -m 30 -o "$OUT/.http-body" -w '%{http_code}' -X POST "$URL/webhooks/github" \
    -H "X-GitHub-Event: $event" -H "X-GitHub-Delivery: $id" -H "X-Hub-Signature-256: $sig" \
    -H 'Content-Type: application/json' --data-binary "$body")
  RESP=$(cat "$OUT/.http-body")
  if [ "$CODE" = "$want" ]; then ok "$name: HTTP $CODE ${RESP:0:40}"; else bad "$name: HTTP $CODE" "expected $want; body: ${RESP:0:200}"; fi
}

SHA=bd21d084b988363d4e02a25e4eedaf7e47a34df6
PR='{"action":"opened","number":15,"pull_request":{"head":{"sha":"'$SHA'","repo":{"full_name":"depscan-go/depscan"}}},"repository":{"full_name":"depscan-go/depscan"}}'

deliver "ping" 200 ping '{"zen":"Keep it logically awesome."}'
deliver "wrong signature" 401 pull_request "$PR" "sha256=$(printf '0%.0s' $(seq 64))"
deliver "no signature" 401 pull_request "$PR" ""
deliver "other events are ignored" 202 issues '{"action":"opened"}'
deliver "closed PRs are ignored" 202 pull_request "${PR/opened/closed}"
deliver "opened PR is queued" 202 pull_request "$PR" "sha256=$(sign "$PR")" delivery-pr15
deliver "the same delivery twice is dropped" 200 pull_request "$PR" "sha256=$(sign "$PR")" delivery-pr15

# The scan runs in the background: wait for its record to show up.
label="github.com/depscan-go/depscan#15@${SHA:0:7}"
for _ in $(seq 45); do
  http GET "$URL/scans"
  rec=$(jq -c --arg l "$label" '.[] | select(.path == $l)' <<<"$RESP" 2>/dev/null)
  [ -n "$rec" ] && break
  grep -qF "webhook: $label failed" "$OUT/webhook-server.log" && break
  sleep 2
done
reason=$(grep -F "webhook: $label failed" "$OUT/webhook-server.log" | sed 's/.*failed/failed/' | head -1)
if [ -n "$rec" ]; then
  ok "PR #15 was scanned in the background: $(jq -r '"\(.result.Deps | length) deps, \(.result.Violations | length) violations"' <<<"$rec")"
  check "it found the PR's lockfiles (more than 0 deps)" jq -e '(.result.Deps | length) > 0' <<<"$rec"
else
  bad "no scan record for $label" "${reason:-nothing after 90s} (log: results/webhook-server.log)"
fi

finish
