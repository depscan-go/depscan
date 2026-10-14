# depscan

Check a Go or npm project for vulnerable dependencies and denied licenses,
against a policy you keep in the repository. Run it from the command line, in
CI, from a local dashboard, or on every pull request.

```
$ depscan -path ./shop-api -policy policy.yaml
Dependencies: 22
Findings:     9
Violations:   7
Warnings:     3

❌ 7 policy violation(s) — scan failed:

  [BLOCK] [vulnerability] golang.org/x/crypto@0.14.0
          GHSA-v778-237x-gjrc (CRITICAL) — … — upgrade to 0.31.0
```

## What a scan does

1. **Reads the lockfiles.** Every `go.mod` and `package-lock.json` (npm 7 or
   newer) in the folder and its subfolders. `.git`, `vendor` and
   `node_modules` are skipped. depscan never runs `go` or `npm`.
2. **Looks up licenses** for every package version on
   [deps.dev](https://deps.dev).
3. **Checks advisories** for every package version on
   [OSV.dev](https://osv.dev), merging records that describe the same flaw
   under different IDs.
4. **Applies your policy** (`policy.yaml`): what blocks, what warns, which
   licenses are denied, and which advisories you accepted on purpose.

If OSV.dev cannot be reached after retries, the scan fails. It is never
reported as a pass with missing data.

## Quick start

You need Go 1.26 or newer.

### Dashboard

```bash
make run-server          # go run ./cmd/server --policy=./policy.yaml
```

Open http://127.0.0.1:8080 and choose a project folder, or drop one on the
page. The browser finds the lockfiles and sends only those to the server on
your computer. Results, history and license reviews stay in your browser.

Scanning by typed path only works inside the server's scan root
(`-scan-root`, your home folder by default); choosing a folder works for any
folder on any drive.

### Command line

```bash
go run ./cmd/depscan -path ./my-project -policy policy.yaml
```

| Exit status | Meaning |
| --- | --- |
| 0 | No violations (warnings are allowed) |
| 1 | At least one violation: fail the build |
| 2 | The scan could not run (bad policy, unreadable folder, OSV.dev down) |

## Policy

`policy.yaml` is commented; the short version:

| Key | Meaning |
| --- | --- |
| `block_severities` | Advisory severities that fail the scan, e.g. `[CRITICAL, HIGH]` |
| `warn_severities` | Severities that are shown but do not fail it |
| `block_unknown_severity` | Fail on advisories that have no severity |
| `check_transitive` | Hold packages you did not add yourself to the same rules |
| `denied_licenses` | SPDX IDs you cannot ship. `MIT OR GPL-3.0-only` passes; `MIT AND GPL-3.0-only` does not |
| `block_unknown_license` | Fail, instead of warn, when deps.dev has no license |
| `skip_license_check` | No license lookups (offline runs) |
| `exceptions` | Advisories accepted on purpose: `id`, a required `reason`, an optional `expires` date |
| `fail_fast`, `max_violations` | Stop early |

Commit the same file your CI uses, so a laptop and CI give the same answer.

## Reports you can verify

```bash
depscan -path . -report report.cdx.json
```

writes a deterministic [CycloneDX 1.5](https://cyclonedx.org) SBOM and, next
to it, `report.cdx.json.sha256` in the format `sha256sum -c` reads.

### Anchoring on Solana

A checksum file next to the report does not stop someone from changing both.
Anchoring writes the report's SHA-256 into the memo of a Solana transaction,
which the ledger timestamps and nobody can edit later:

```bash
depscan keygen                       # once: creates ~/.config/solana/id.json
# fund the address it prints with free devnet SOL: https://faucet.solana.com
depscan -path . -report report.cdx.json -anchor solana
```

This saves `report.cdx.json.anchor.json` with the network, transaction ID,
signer and time. Only the 64-character fingerprint is published, as the memo
`depscan:v1:sha256:<hex>`; your report and package list are not. One anchor
costs 0.000005 SOL.

| Variable | Default |
| --- | --- |
| `DEPSCAN_SOLANA_RPC` | `devnet`; also `testnet`, `mainnet-beta`, or any RPC URL |
| `DEPSCAN_SOLANA_KEYPAIR` | `~/.config/solana/id.json` (the Solana CLI's keypair works too) |
| `DEPSCAN_SOLANA_KEY` | The secret key itself, for servers: base58 (as Phantom exports it) or the JSON array `solana-keygen` writes. Use this or `DEPSCAN_SOLANA_KEYPAIR`, not both |

### Verifying

```bash
depscan verify report.cdx.json
```

re-hashes the report and checks it against `report.cdx.json.sha256` and, if
it was anchored, against the transaction on the ledger. Verifying needs no
wallet. Add `-json` for CI, or `-offline` to check only the local files.

Lost the receipt? The ledger still has the anchor:
`depscan verify -signer <address> -save report.cdx.json` searches that
address's transactions for the report's fingerprint and writes the receipt
back.

| Exit status | Meaning |
| --- | --- |
| 0 | Verified |
| 1 | The report was changed, or the ledger does not hold its fingerprint |
| 2 | Could not check: no checksum or receipt, or the ledger was unreachable |

A match proves the report has not changed since it was anchored. It does not
prove the project is still safe: advisories are published every day, so scan
again for a current answer.

## Pull request checks

The server can scan every pull request at its latest commit and report back:
a commit status (pending, then success, failure or error) and one comment
listing what blocks the merge and the version that fixes it. A later push
edits that comment instead of adding another.

1. Start the server where GitHub can reach it, with:

   | Variable | Purpose |
   | --- | --- |
   | `DEPSCAN_WEBHOOK_SECRET` | Turns webhooks on; GitHub signs every delivery with it |
   | `GITHUB_TOKEN` | Reads lockfiles of private repositories and posts results |
   | `DEPSCAN_PR_FEEDBACK` | `status` for the status only, `off` for neither (default: both) |
   | `DEPSCAN_PUBLIC_URL` | The dashboard's public address, for the status's Details link |

   A fine-grained token needs **Contents: read**, **Commit statuses: read and
   write** and **Pull requests: read and write** on the repository.
2. In the repository's **Settings → Webhooks**, add
   `https://<your server>/webhooks/github`, content type
   `application/json`, the same secret, and the **Pull requests** event.
3. Optional: in branch protection, require the `depscan` status to pass.

Only the lockfiles at the pull request's head commit are downloaded.

### Anchoring pull request scans

Set `DEPSCAN_ANCHOR=solana` and `DEPSCAN_SOLANA_KEY` (devnet by default) and
the server also builds each pull request scan's CycloneDX report, anchors its
SHA-256, and puts the transaction in the pull request comment. The report is
kept at `GET /scans/{id}/report` (see "Saving scans"). The server logs the
wallet's address and balance at startup.

The proof doesn't depend on the server: GitHub keeps the comment, the ledger
keeps the anchor, and `depscan verify -signer <address>` finds the anchor of
any copy of the report. Anchoring never changes a scan's result; if it fails,
the comment says why.

## Saving scans

Set `DATABASE_URL` to a Postgres connection string and the server keeps every
scan there, so its link keeps working after a restart:

- dashboard uploads and folder scans for 30 days
- pull request scans, with their reports, until the saved scans pass 700 MB;
  then the oldest go first, uploads before pull request scans

Without it, scans are kept in memory until the server restarts. If the
database can't be reached, scans still run and return their result; only
their links won't work, and the log says `store: … failed`.

`GET /scans` lists the newest 300 scans only when the server listens on
`127.0.0.1`, `::1` or `localhost`. Anywhere else, including docker compose
(which listens on `:8080` inside its container), a scan opens only through
its own link.

## HTTP API

| Method and path | |
| --- | --- |
| `GET /` | The dashboard |
| `GET /healthz` | Liveness |
| `POST /scans` | Scan a folder inside the scan root: `{"path": "..."}` |
| `POST /scans/upload` | Scan lockfiles sent by the dashboard (gzip JSON, 1 MB limit) |
| `GET /scans` | The newest 300 scans, on a local server only (see "Saving scans") |
| `GET /scans/{id}` | One scan's result |
| `GET /scans/{id}/report` | The CycloneDX report of an anchored pull request scan |
| `GET /policy` | The loaded policy, read-only |
| `POST /webhooks/github` | GitHub webhook deliveries, when enabled |

A scan answers 200 when it passes and 422 when the policy is violated, with the
same body either way.

## What leaves your machine

- Package names and versions go to OSV.dev and deps.dev.
- With the dashboard, only `go.mod` and `package-lock.json` files go from the
  browser to the depscan server you run.
- With anchoring, only the report's SHA-256 goes to the Solana network.
- The depscan server keeps each scan's result: with `DATABASE_URL`, in its
  database for 30 days (pull request scans until space runs short); otherwise
  in memory until it restarts.

## Development

```bash
make test    # go test -race ./...
make lint    # golangci-lint run ./...
```

The store's Postgres tests run when `DEPSCAN_TEST_DATABASE_URL` points at a
throwaway database (CI starts one):

```bash
docker run -d --rm --name depscan-test-pg -e POSTGRES_PASSWORD=depscan -p 55432:5432 postgres:18-alpine
DEPSCAN_TEST_DATABASE_URL='postgres://postgres:depscan@127.0.0.1:55432/postgres?sslmode=disable' make test
```

| Package | |
| --- | --- |
| `internal/parser` | `go.mod` and `package-lock.json` parsing |
| `internal/license`, `internal/osv` | deps.dev and OSV.dev clients |
| `internal/policy` | Loading and applying `policy.yaml` |
| `internal/scan` | The scan engine that ties them together |
| `internal/report` | CycloneDX reports and their SHA-256 |
| `internal/anchor` | Anchoring backends (`solana`, `noop`) and receipts |
| `internal/github` | Webhooks, lockfile fetching, status and comment |
| `internal/store` | Where scans are kept: memory, or Postgres with `DATABASE_URL` |
| `internal/api` | HTTP handlers and the embedded dashboard |
