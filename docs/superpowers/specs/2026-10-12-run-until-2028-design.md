# Keeping depscan running until 2028

Status: design approved in chat on 2026-10-12. Owner: Sayan (DevOps).

## Goal

depscan has to stay up and ready to demo until the end of 2028. It's a demo now and should grow into something real users rely on later, so the setup must not break during a demo and must leave room to grow.

What we know:

- Sayan stays a student through 2028, so Azure for Students can renew its credit every year.
- We keep the Azure default URL until we buy a domain. When that happens is open.
- Everyone on the team should be able to run and fix the infrastructure.

Chosen approach: **harden what we have** (Azure for Students + GitHub), with a yearly rebuild drill as the escape plan. We rejected keeping a second host ready, because it doubles the upkeep for a low risk. We also rejected a server-light setup, because it gives up the hosted features real users need.

## Where we start (2026-10-12)

- One Container App (Express, `malaysiawest`) at 0.25 vCPU / 0.5 GiB. It scales to zero, with at most one replica.
- CI, CD (deploys by digest, rolls back on failure), nightly end-to-end tests, a 30-minute log Watchdog, and releases.
- Key Vault secrets: `database-url`, `webhook-secret`, `github-token` (fine-grained, sandbox only, can post statuses and comments; expires around 2027-01-12), `solana-key`.
- Since 2026-10-14, every PR on the sandbox gets a `depscan` status and comment, and its report is anchored on Solana devnet. `depscan verify` checks it, and catches a tampered copy.
- A budget of **₹10**: the amount was meant as USD, but the subscription bills in INR.
- Spend in October 2026 so far is about ₹0.02.

## 1. Money

- **Budget: ₹800/month**, about $10. Emails at 50% and 100% of actual spend, and at 100% of forecast, go to the owner and to `alert_emails`.
- **Azure spending check, weekly (it runs on GitHub, which costs nothing for a public repo).** A workflow reads Azure's spend for the month so far through the Cost Management API (OIDC), and opens a GitHub issue if it's over ₹400. Azure's own notification emails never arrived on this subscription, so budget emails count as unproven. The GitHub identity gets the *Cost Management Reader* role on the subscription.
- **Domain**, once bought: about $10 a year. The team decides who pays.
- **Neon free tier** (0.5 GB): enough for demo history. A retention rule comes with the database store (see section 7).

## 2. Things that expire

- **`infra/expiry.yaml`** lists every dated item: what it is, the date, what to do, and who does it.
- **A weekly upkeep workflow** opens a reminder issue once a date is 30 days away or less: one issue per item per date, matched by title, so it doesn't spam. GitHub's issue emails reach people, which Azure's don't. The same workflow runs the cost check and the keepalive.
- Entries:
  - student re-verification (about every October; the exact date comes from the Azure Education hub)
  - GitHub token on 2027-01-12 (until the GitHub App replaces it)
  - the yearly rebuild drill (every October)
  - the yearly upgrade review: azurerm major version, Go version, changes to Express
  - the domain renewal, once a domain is bought
- **Keepalive.** In public repos, GitHub pauses scheduled workflows after 60 days without activity. The upkeep workflow re-enables every scheduled workflow through the API each week. When building it, check that this really resets the timer.
- **Dependabot:** `github-actions`, `gomod` (root module) and `docker` (`deploy/Dockerfile`) weekly, `terraform` (`infra/terraform`) monthly. CI decides whether each update can merge.

## 3. Capacity, abuse and uptime

- **App size 0.5 vCPU / 1 GiB.** The free allowance covers about 100 hours of the app being awake per month at this size. If someone kept it busy 24/7, the one-replica cap holds the bill to about $34/month.
- **Upload limit in code** (an issue for Debjit): cap simultaneous uploads (for example 2), or lower the 64 MB unpacked limit. Each upload can unpack to 64 MB and roughly double in memory, so about 8 at the same time fill 1 GiB (about 4 at today's 0.5 GiB).
- **Uptime check every 2 hours:** `GET /healthz` on the live URL, opening an issue if it doesn't return 200. Logs can't show this: a dead app writes no errors, so the Watchdog stays quiet. Every 30 minutes would keep the app awake past the free allowance, at about ₹90/month.
- Unchanged: the Watchdog (errors, every 30 minutes), the nightly tests (including the live app), and the CD rollback.

## 4. The address

- **The Azure URL stays for now.** Terraform gets `prevent_destroy` on the Container Apps environment and the app. Without a domain, rebuilding either one changes the URL, which breaks the webhooks and every link we've shared.
- **When a domain is bought** (separate plan): Cloudflare DNS plus a small Worker that forwards requests to the Azure app. Express can't bind a custom domain, and Azure routes requests by hostname, so a plain CNAME would get a 404. We'd also add Cloudflare's free rate-limiting rule for scans and uploads. The uptime check and the webhooks then move to the domain.

## 5. People

- Teammates join Sayan's Azure directory as guests and sign in with their own accounts.
- Their roles:
  - *Owner* on `rg-depscan`
  - *Key Vault Secrets Officer* on the vault
  - *Contributor* on `rg-depscan-tfstate`, so they can run Terraform against the state
  - *Cost Management Reader* on the subscription
- Nobody else gets owner or billing rights on the subscription.
- The list lives in Terraform (`team_object_ids`). The IDs go in the gitignored `terraform.tfvars`, so the public repo never contains them.

## 6. Recovery

- **`infra/RUNBOOK.md`** covers:
  - **rebuilding from scratch**, in this order: state storage → Key Vault secrets → `terraform apply` → GitHub repo variables → webhook URLs
  - **rotating each secret**
  - **what to do when:** the site is down, a deploy was rolled back, the credit lapsed, a token expired, the URL changed, or Solana devnet was reset
- **Terraform state backups:** turn on blob versioning and soft delete for `depscantf16049`. That storage account sits outside Terraform, so the steps go in the runbook.
- **Yearly drill:** rebuild a full copy with `prefix = "depscandr"` in `eastasia`, using its own state key. Run the live end-to-end tests against it, write down how long it took and what broke, then destroy it.

## 7. Real users, later, in this order

1. **A GitHub App instead of the personal token**, due before 2027-01-12. Today's comments show up as Sayan, because they're posted with his token; with the App they come from `depscan[bot]`. It gets read-only contents access plus permission for checks and PR comments. The server uses installation tokens, which never need manual renewal. This is also what lets us comment on other people's PRs.
2. **Database store** (team): scan history survives restarts, with a retention rule to stay within 0.5 GB.
3. **Solana mainnet anchoring:** anchoring already works on devnet. Moving to mainnet means funding a mainnet keypair in Key Vault and setting `solana_rpc = "mainnet-beta"`. Devnet can be reset, so its anchors are only good for demos.
4. **Domain + Cloudflare**, as in section 4.

## How we verify each piece

- Terraform changes: predict the plan, then apply.
- Every new check gets a deliberate failure test:
  - **uptime:** probe a path that fails
  - **cost check:** run it once with a ₹0 threshold
  - **reminders:** run the workflow once with a date 29 days away
  - **keepalive:** read each workflow's state through the API afterwards
- The nightly tests keep checking the live app.
- The yearly drill tests the runbook itself.

## What it costs

Azure: about ₹0 a month at today's traffic, covered by the student credit. GitHub: nothing while the repo is public. A domain: about $10 a year, once bought.

## Out of scope

Moving off Azure, paid plans, and a public status page.

## Open questions

- The exact student re-verification date: check the Azure Education hub.
- Who pays for the domain, and when we buy it.
- Whether budget emails arrive at all. The weekly Azure spending check covers us either way.

## Phases

**Phase 1 (this plan):** sections 1, 2, 3, 5 and 6, plus `prevent_destroy` from section 4.

**Later, each with its own plan:** the domain and Cloudflare (section 4), and each "real users" step (section 7). The GitHub App's plan has to start soon enough to ship before 2027-01-12, because it needs code from the team.
