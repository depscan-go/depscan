#!/usr/bin/env bash
# Builds the image with the repo's docker-compose file and scans the repo's testdata in a container.
# Slow (builds the image) and uses ports 8080 and 5432.
source "$(dirname "$0")/lib.sh"
COMPOSE=(docker compose -f "$REPO/deploy/docker-compose.yaml" -p depscan-playground)
URL=http://127.0.0.1:8080
echo "09 · docker compose stack from $REPO/deploy"

"${COMPOSE[@]}" up -d --build >"$OUT/docker.log" 2>&1 || { bad "docker compose up failed" "log: results/docker.log"; finish; exit 1; }
trap '"${COMPOSE[@]}" down -v >>"$OUT/docker.log" 2>&1' EXIT
for _ in $(seq 60); do curl -s -o /dev/null "$URL/healthz" && break; sleep 1; done

expect_http "GET /healthz from the container" 200 GET "$URL/healthz"
expect_http "GET / dashboard from the container" 200 GET "$URL/"
# testdata/go.mod pins old gin and x/crypto versions with HIGH vulns.
expect_http "POST /scans testdata (mounted read-only)" 422 POST "$URL/scans" '{"path":"testdata"}'

finish
