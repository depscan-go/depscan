#!/usr/bin/env bash
# Independent check: works out the expected numbers from OSV.dev and deps.dev
# directly (see oracle.py) and compares them with depscan's.
exec python3 "$(dirname "$0")/oracle.py"
