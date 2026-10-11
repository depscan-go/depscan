#!/usr/bin/env bash
# The repo's own Go unit tests, with the race detector.
source "$(dirname "$0")/lib.sh"
echo "10 · Go unit tests in $REPO"
LOG="$OUT/unit-tests.log"
# Piped through cat: a snap-installed go can't write straight into a redirected file.
(cd "$REPO" && go test -race ./... 2>&1 | cat; exit "${PIPESTATUS[0]}") >"$LOG"
RC=$?
packages=$(grep -c '^ok' "$LOG")
if [ "$RC" = 0 ] && [ "$packages" -gt 0 ]; then
  ok "go test -race ./...: $packages packages ok"
else
  bad "go test: exit $RC, $packages packages ok" "log: results/unit-tests.log"
fi
finish
