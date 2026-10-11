#!/usr/bin/env bash
# Builds depscan from this repo, then runs the end-to-end tests. Logs land in e2e/results/.
#
#   e2e/run.sh            local tests: CLI, reports, policies, errors, server, webhook, independent check
#   e2e/run.sh --live     + the deployed app on Azure
#   e2e/run.sh --docker   + build and run the docker compose stack (slow)
#   e2e/run.sh --unit     + the repo's Go unit tests
#   e2e/run.sh --all      everything (what the nightly job runs)
cd "$(dirname "$0")" || exit 2
tests=(01-scans 02-report 03-policies 04-errors 05-server 06-webhook 08-oracle)
for arg in "$@"; do
  case $arg in
    --live) tests+=(07-live) ;;
    --docker) tests+=(09-docker) ;;
    --unit) tests+=(10-unit) ;;
    --all) tests+=(07-live 09-docker 10-unit) ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

commit=$(git rev-parse --short HEAD)
echo "Building depscan from $commit"
(cd .. && go build -trimpath -ldflags "-X main.version=$commit" -o e2e/bin/depscan ./cmd/depscan &&
  go build -trimpath -o e2e/bin/depscan-server ./cmd/server) || { echo "build failed"; exit 2; }
rm -rf results && mkdir results

failed=()
for t in "${tests[@]}"; do
  echo
  bash "tests/$t.sh" || failed+=("$t")
done
echo
if [ ${#failed[@]} -eq 0 ]; then
  echo "All ${#tests[@]} test files passed."
else
  echo "Failed: ${failed[*]} (details in e2e/results/)"
  exit 1
fi
