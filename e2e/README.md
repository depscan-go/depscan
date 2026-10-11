# End-to-end tests

Sample projects with real vulnerable, GPL and oddly licensed dependencies, plus tests that run depscan against them the way users do: the CLI, reports, policies, the server, the webhook, Docker and the live app. A nightly GitHub Actions job runs all of it (`.github/workflows/nightly.yaml`).

```bash
e2e/run.sh            # local tests, about 2 minutes
e2e/run.sh --all      # also the live Azure app, docker compose and the Go unit tests
```

Pick extras one at a time with `--live`, `--docker` or `--unit`. Logs and reports land in `e2e/results/`.

| Test | Checks |
|---|---|
| 01-scans | every sample project with the default policy: exit code, violations, warnings |
| 02-report | CycloneDX SBOM, the `sha256sum -c` fingerprint, tampering getting caught, same input giving the same report, the anchor receipt |
| 03-policies | exceptions (by id, by CVE alias, expired, no reason, bad date), strict mode, license check off, a typo in severities |
| 04-errors | exit 2 on tool errors (bad path, policy or anchor, OSV unreachable); broken lockfiles only warn |
| 05-server | local server: dashboard and its assets, policy, scans API (200 and 422), history, folder uploads (gzip, size, path and cross-site checks), path safety |
| 06-webhook | signatures, ignored events, duplicate deliveries, a real background scan of PR #15 |
| 07-live | the deployed app on Azure: dashboard, policy, an upload scan, webhook signature check |
| 08-oracle | recomputes every project's numbers straight from OSV.dev and deps.dev and compares them with depscan |
| 09-docker | the docker compose stack (ports 8080 and 5432) |
| 10-unit | the Go unit tests with `-race` |

## Good to know

- Scans need internet, because they ask OSV.dev and deps.dev. When a new advisory lands, a project's numbers can change and a test goes red. `tests/08-oracle.sh` tells you whether depscan changed or the databases did; if it's the databases, update the expectation in the test.
- The webhook test uses `$GITHUB_TOKEN`, or your `gh` login's token, for GitHub API calls. Without one, GitHub allows 60 requests an hour.
- Known gap, shown as `GAP` rather than a failure: a typo in `block_severities` (like `HIHG`) isn't rejected.
- The sample projects have their own `go.mod` files, so `go test ./...` and the linters skip them, and `.dockerignore` keeps them out of the server image.
