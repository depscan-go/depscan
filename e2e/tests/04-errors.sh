#!/usr/bin/env bash
# Tool errors must exit 2. Broken lockfiles only warn.
source "$(dirname "$0")/lib.sh"
echo "04 · Errors and bad input"

expect_exit missing-path      2 "$BIN/depscan" -path projects/does-not-exist -policy policies/default.yaml
expect_exit missing-policy    2 "$BIN/depscan" -path projects/clean-go -policy policies/does-not-exist.yaml
expect_exit anchor-no-report  2 "$BIN/depscan" -path projects/clean-go -policy policies/default.yaml -anchor noop
expect_exit unknown-anchor    2 "$BIN/depscan" -path projects/clean-go -policy policies/default.yaml -report results/x.json -anchor no-such-backend

# A lockfile that isn't valid JSON and an old v1 lockfile: both skipped with a warning.
expect_scan broken-lockfile broken-lockfile default.yaml 0 0 0
warns=$(grep -c '^\[warn\]' "$LOG")
if [ "$warns" = 2 ]; then ok "both broken lockfiles were reported as [warn]"; else bad "$warns [warn] lines" "expected 2 (log: results/broken-lockfile.log)"; fi

# OSV unreachable: a scan must never pass with missing advisories.
start=$(date +%s)
expect_exit osv-unreachable 2 env HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 \
  "$BIN/depscan" -path projects/clean-go -policy policies/default.yaml
echo "        (gave up after $(($(date +%s) - start))s of retries)"

finish
