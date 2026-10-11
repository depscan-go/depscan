#!/usr/bin/env bash
# Shared helpers. Every test script sources this file.

PG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${DEPSCAN_REPO:-$(cd "$PG/.." && pwd)}"
BIN="$PG/bin"
OUT="$PG/results"
mkdir -p "$OUT"
PASS=0
FAIL=0
GAPS=0

ok()  { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; }
# A known problem in depscan itself: reported, but it doesn't fail the run.
gap() { GAPS=$((GAPS + 1)); printf '  \033[33mGAP\033[0m   %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; }

# scan NAME PROJECT POLICY [FLAGS...]
# Runs the CLI from the playground root and sets RC (exit code) and LOG.
scan() {
  local name=$1 project=$2 policy=$3
  shift 3
  LOG="$OUT/$name.log"
  (cd "$PG" && "$BIN/depscan" -path "projects/$project" -policy "policies/$policy" "$@") >"$LOG" 2>&1
  RC=$?
}

# count FIELD: reads a "Violations: N" style line from the last scan's log.
count() { awk -v f="$1:" '$1 == f { print $2; exit }' "$LOG"; }

# expect_scan NAME PROJECT POLICY EXIT VIOLATIONS WARNINGS [FLAGS...]
# Use "-" for a count that shouldn't be checked.
expect_scan() {
  local name=$1 project=$2 policy=$3 want_rc=$4 want_v=$5 want_w=$6
  shift 6
  scan "$name" "$project" "$policy" "$@"
  local v w got
  v=$(count Violations)
  w=$(count Warnings)
  got="exit $RC, ${v:-?} violations, ${w:-?} warnings"
  if [ "$RC" = "$want_rc" ] &&
    { [ "$want_v" = - ] || [ "$v" = "$want_v" ]; } &&
    { [ "$want_w" = - ] || [ "$w" = "$want_w" ]; }; then
    ok "$name: $got"
  else
    bad "$name: $got" "expected exit $want_rc, $want_v violations, $want_w warnings (log: results/$name.log)"
  fi
}

# expect_exit NAME WANT_RC COMMAND...   (runs from the playground root)
expect_exit() {
  local name=$1 want=$2
  shift 2
  LOG="$OUT/$name.log"
  (cd "$PG" && "$@") >"$LOG" 2>&1
  RC=$?
  if [ "$RC" = "$want" ]; then ok "$name: exit $RC"; else bad "$name: exit $RC" "expected exit $want (log: results/$name.log)"; fi
}

# check NAME COMMAND...: passes if the command succeeds.
check() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}

# http METHOD URL [BODY [HEADER...]]: sets CODE and RESP.
# BODY can be @file. It's sent as JSON unless a Content-Type header is given.
http() {
  local method=$1 url=$2 data=${3:-} h json=1
  shift $(($# < 3 ? $# : 3))
  local args=(-s -m 90 -o "$OUT/.http-body" -w '%{http_code}' -X "$method")
  for h in "$@"; do
    args+=(-H "$h")
    [[ ${h,,} == content-type:* ]] && json=0
  done
  if [ -n "$data" ]; then
    [ "$json" = 0 ] || args+=(-H 'Content-Type: application/json')
    args+=(--data-binary "$data")
  fi
  CODE=$(curl "${args[@]}" "$url")
  RESP=$(cat "$OUT/.http-body" 2>/dev/null)
}

# check_dashboard URL: it's depscan's dashboard, and every asset the page links to loads.
check_dashboard() {
  local url=$1 assets a
  expect_http "GET / (dashboard)" 200 GET "$url/"
  if grep -qi '<title>depscan</title>' <<<"$RESP"; then ok "it's the depscan dashboard"; else bad "dashboard title not found"; fi
  assets=$(grep -oE '/assets/[A-Za-z0-9._-]+' <<<"$RESP" | sort -u)
  [ -n "$assets" ] || { bad "the dashboard links no /assets/ files"; return; }
  for a in $assets; do expect_http "GET $a" 200 GET "$url$a"; done
}

# upload_json NAME PROJECT: the JSON the dashboard's folder picker sends for a sample
# project, which is its lockfiles outside vendor/ and node_modules/.
upload_json() {
  python3 - "$1" "$PG/projects/$2" <<'PY'
import json, os, sys
name, root = sys.argv[1], sys.argv[2]
files = []
for d, dirs, names in os.walk(root):
    dirs[:] = [x for x in dirs if x not in ("vendor", "node_modules", ".git")]
    for n in names:
        if n in ("go.mod", "package-lock.json"):
            p = os.path.join(d, n)
            files.append({"path": os.path.relpath(p, root).replace(os.sep, "/"), "content": open(p).read()})
print(json.dumps({"name": name, "files": sorted(files, key=lambda f: f["path"])}))
PY
}

# expect_http NAME WANT_CODE METHOD URL [BODY]
expect_http() {
  local name=$1 want=$2
  shift 2
  http "$@"
  if [ "$CODE" = "$want" ]; then ok "$name: HTTP $CODE"; else bad "$name: HTTP $CODE" "expected $want; body: ${RESP:0:200}"; fi
}

# wait_for_server URL: waits up to 10s for /healthz.
wait_for_server() {
  for _ in $(seq 50); do
    curl -s -o /dev/null "$1/healthz" && return 0
    sleep 0.2
  done
  return 1
}

finish() {
  echo
  printf '%s: %d passed, %d failed' "$(basename "$0" .sh)" "$PASS" "$FAIL"
  [ "$GAPS" -eq 0 ] || printf ', %d known gap(s)' "$GAPS"
  echo
  [ "$FAIL" -eq 0 ]
}
