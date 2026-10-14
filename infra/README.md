# Infrastructure

The live app runs on Azure Container Apps, set up with Terraform in `infra/terraform/`. GitHub Actions builds and deploys it.

## What runs where

| Piece | Where |
|---|---|
| depscan-server | Container App `depscan-server` (Express environment, Malaysia West). Scales to zero when idle |
| Images | `ghcr.io/depscan-go/depscan`, public |
| Database | Neon Postgres (AWS Singapore). Its URL is wired in, but the server doesn't read it yet |
| Secrets | Key Vault `kv-depscan-50385a`: `database-url`, `webhook-secret`, `github-token`, `solana-key` |
| Anchoring | Solana devnet. Reports are signed by `4TnT5hvYUEkfAPxznU7LpVVbfj3EsLunY6jJ8Djj7oRj`, which needs devnet SOL for fees (one anchor is 0.000005 SOL) |
| Logs and alerts | Log Analytics (0.1 GB/day cap) and a $10/month budget. Every 30 minutes the Watchdog workflow checks the logs for errors and opens a GitHub issue if it finds any |
| Terraform state | Storage account `depscantf16049` |

## How a change reaches production

Merge to `main` → CI (test, lint, docker) → CD builds the image → pushes it to GHCR → deploys it by digest → smoke test → rolls back if anything fails.

Changes only under `infra/`, `e2e/` or `*.md` don't deploy. Every night, `e2e/run.sh --all` tests the code and the live app.

## Running Terraform

You need access to the Azure for Students subscription.

```bash
cd infra/terraform
cp backend.hcl.example backend.hcl            # storage account: depscantf16049
cp terraform.tfvars.example terraform.tfvars  # subscription id and region
az login
terraform init -backend-config=backend.hcl
terraform plan -out tfplan                    # read it before applying
terraform apply tfplan
```

Terraform sets the image only when the app is first created, and CD deploys after that. So `apply` never rolls back a deploy.

## Secrets

Set or rotate a secret in Key Vault, then run plan and apply to copy it into the app:

```bash
read -rsp 'Value: ' V; echo
az keyvault secret set --vault-name kv-depscan-50385a -n <name> --value "$V" -o none
unset V
```

| Secret | Becomes | Notes |
|---|---|---|
| `database-url` | `DATABASE_URL` | Neon's direct URL, not the pooled one |
| `webhook-secret` | `DEPSCAN_WEBHOOK_SECRET` | Must match the secret in each GitHub webhook |
| `github-token` | `GITHUB_TOKEN` | Fine-grained, for the watched repos only: Contents read, Commit statuses and Pull requests read and write. **Expires around 2027-01-12**, so renew it (or move to a GitHub App) before then |
| `solana-key` | `DEPSCAN_SOLANA_KEY` | Devnet keypair made with `depscan keygen`. Top it up at faucet.solana.com |

## Webhooks

The live app watches `sayanx64/depscan-sandbox`. To add a repo, open its Settings → Webhooks and add:

- Payload URL: `https://depscan-server.thankfulbeach-61661ef7.malaysiawest.azurecontainerapps.io/webhooks/github`
- Content type: `application/json`
- Secret: the `webhook-secret` value
- Events: Pull requests

Each pull request then gets a `depscan` commit status and one comment, which is updated on every push. Both are posted as the owner of `github-token`, so that token must include the repo. The report is anchored on Solana, and anyone can check it: download it from the dashboard (`/scans/<id>/report`) and run `depscan verify`.

## Azure for Students quirks

- Container Apps run in **Express** mode. It can't use Key Vault references (Terraform copies secrets in instead), and it has no Container Apps Jobs.
- Express can't pull private images, so the GHCR package has to stay public.
- Express remembers a failed image reference and never retries it. That's why CD deploys by digest, not by tag.
- Express doesn't report request metrics, so errors are found in the server's logs.
- Azure alert emails never arrive on this (free) subscription: alerts fire, but nobody gets notified. That's why the Watchdog workflow reports errors as a GitHub issue instead.
- Only these regions are allowed: `malaysiawest`, `eastasia`, `koreacentral`, `uaenorth` and `indiasouthcentral` (which has no Container Apps).
- GitHub's OIDC subject includes the repo's IDs. If the repo is ever recreated, update `github_oidc_subject_prefix` in `variables.tf`.
