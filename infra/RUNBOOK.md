# Runbook

What to do when something breaks, how to rotate secrets, and how to rebuild everything. `README.md` says what runs where. Only Sayan runs Terraform, from `infra/terraform`; anyone on the team can do the other fixes here.

## The site is down

The Uptime workflow opens a "Live site is down" issue when `/healthz` doesn't answer 3 times in a row. The issue closes itself on the next check that passes.

1. Check it yourself: `curl -s https://depscan-server.thankfulbeach-61661ef7.malaysiawest.azurecontainerapps.io/healthz`
2. Is the subscription still active? `az account show --query state -o tsv` should print `Enabled`. If it doesn't, see "The credit lapsed".
3. Look at the revisions: `az containerapp revision list -g rg-depscan -n depscan-server --query "[].{name:name, active:properties.active, health:properties.healthState, running:properties.runningState}" -o table`
4. If a deploy broke it, CD normally rolls back by itself. To roll back by hand, deploy the image of the last good CD run (its "Deploy" step log shows the digest): `az containerapp update -g rg-depscan -n depscan-server --image ghcr.io/depscan-go/depscan@sha256:<digest> -o none`
5. Read the logs: Log Analytics workspace `log-depscan`, table `ContainerAppConsoleLogs_CL`, column `Log_s`.

## A deploy was rolled back

The CD run is red, but its "Roll back on failure" step is green, so the site still runs the previous image. Read the run's "Deploy" and "Smoke test" logs:

- An error about pulling the image (for example `unauthorized`) means the GHCR package went private. Make it public again under the org's Packages → depscan → Package settings.
- For anything else, fix the code and merge again. Express remembers a failed image reference, which is why CD deploys by digest.

## Azure spending is high

The Upkeep workflow opens an "Azure spending is high" issue when the month's spend passes ₹400.

1. Find what costs money: Azure portal → Cost Management → Cost analysis, grouped by resource.
2. If the app was awake far more than usual, something is sending it traffic. An open dashboard tab is enough: while it's visible, it calls `/healthz` every minute. Check the request logs in `ContainerAppConsoleLogs_CL`.
3. To stop the app's spending at once, turn off its public endpoint: `az containerapp ingress disable -g rg-depscan -n depscan-server`. The site stays down until Sayan runs `terraform apply` again.

If the Upkeep run itself is red with `429 Too many requests`, Azure's cost API was busy. Run Upkeep again later.

## The credit lapsed

Azure for Students gives credit for 12 months and can be renewed while Sayan is a student. Upkeep reminds about it a month before the date in `infra/expiry.yaml`. Renew in the Azure portal's Education hub. If the subscription is already disabled, try renewing first; if that doesn't bring it back, follow "Rebuild from scratch" in a new subscription.

## A token expired

`github-token` is the server's GitHub token. Make a new fine-grained token. Its resource owner is the owner of the watched repos, and it covers only those repos, with Contents read, Commit statuses read and write, and Pull requests read and write. Store it in Key Vault, then Sayan copies it into the app:

```bash
read -rsp 'Value: ' V; echo
az keyvault secret set --vault-name kv-depscan-50385a -n github-token --value "$V" -o none; unset V
terraform plan -out tfplan    # expect 1 to change: the app's secret
terraform apply tfplan
```

Then move its date in `infra/expiry.yaml`, and delete the old token on GitHub.

## Rotating a secret

Store the new value with `read -rsp` and `az keyvault secret set`, as in "A token expired". Then Sayan runs `terraform plan` and `apply` so the app gets it.

| Secret | Where the new value comes from | Also do |
|---|---|---|
| `database-url` | Neon console: the direct (not pooled) connection string | nothing |
| `webhook-secret` | `openssl rand -hex 32` | put the same value in each watched repo's webhook settings |
| `github-token` | see "A token expired" | move its date in `infra/expiry.yaml` |
| `solana-key` | `go run ./cmd/depscan keygen -out <file>`, then `az keyvault secret set --vault-name kv-depscan-50385a -n solana-key --file <file> -o none`, then `shred -u <file>` | send devnet SOL to the new address (faucet.solana.com) and update the address in `README.md` |

## Solana devnet was reset

Old anchors can't be verified any more, and nothing in Azure needs fixing. If the key's balance is 0, send devnet SOL to its address again. The address is in `README.md`.

## The URL changed

Rebuilding the Container Apps environment or the app, or moving to a domain, changes the address. Update it in:

- each watched repo's webhook (Settings → Webhooks)
- `LIVE_URL` in `.github/workflows/uptime.yaml`
- the default URL in `e2e/tests/07-live.sh`
- `README.md` and this file

The app's own `DEPSCAN_PUBLIC_URL`, used for links in PR comments, follows by itself on the next `terraform apply`.

## Restore an old Terraform state

The state storage keeps every version of the state for good, and deleted blobs for 14 days. If an apply went badly wrong, open the storage account in the Azure portal → Containers → `tfstate` → `depscan.tfstate` → Versions, pick the last good one, and make it the current version. Then run `terraform plan` to see what differs from Azure.

## Rebuild from scratch

Use this for a new subscription. It takes about an hour.

1. Log in: `az login`, then `az account set -s <subscription id>`.
2. Register the resource providers: `for ns in Microsoft.App Microsoft.OperationalInsights Microsoft.KeyVault Microsoft.ManagedIdentity Microsoft.Storage Microsoft.Consumption Microsoft.CostManagement; do az provider register -n $ns --wait; done`
3. Make the state storage, and turn on its backups:
   ```bash
   az group create -n rg-depscan-tfstate -l malaysiawest -o none
   SA=depscantf$RANDOM
   az storage account create -g rg-depscan-tfstate -n $SA -l malaysiawest --sku Standard_LRS --min-tls-version TLS1_2 --allow-blob-public-access false -o none
   az storage container create --account-name $SA -n tfstate --auth-mode key -o none
   az storage account blob-service-properties update -g rg-depscan-tfstate --account-name $SA --enable-versioning true --enable-delete-retention true --delete-retention-days 14 --enable-container-delete-retention true --container-delete-retention-days 14 -o none
   echo $SA
   ```
   Then write `backend.hcl` from `backend.hcl.example` with that storage account's name.
4. Write `terraform.tfvars` from `terraform.tfvars.example`. Set `budget_start` to the 1st of the current month, because Azure only accepts a new budget that starts this month or later.
5. Key Vault secrets have to exist before a full plan, but Terraform creates the vault. So build without them first:
   ```bash
   terraform init -backend-config=backend.hcl
   terraform plan -out tfplan -var wire_database_url=false -var enable_webhooks=false -var enable_anchoring=false
   terraform apply tfplan
   ```
6. Store the four secrets in the new vault (see "Rotating a secret"; `terraform output key_vault_name` gives the vault's name). If `az` says Forbidden, wait a few minutes: your role on the new vault takes a while to apply.
7. Run `terraform plan -out tfplan` and `terraform apply tfplan` again, without the `-var` flags. Expect `0 to add, 1 to change`: the app gets its secrets.
8. In GitHub (repo Settings → Secrets and variables → Actions → Variables), set `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID` from `terraform output github_oidc_variables`.
9. The URL has changed, so follow "The URL changed".
10. Run CD once (Actions → CD → Run workflow) to deploy the current image by digest.

## Yearly drill

Once a year, rebuild a full copy next to the real one to prove this runbook still works. The copy uses the prefix `depscandr` and the region `eastasia`. It keeps its state in the same storage under its own key, and gets throwaway secrets. Never point GitHub or a webhook at it. The drill covers steps 5–7 of "Rebuild from scratch" plus the live tests, and takes about an hour.

1. Copy the Terraform outside the repo, so the real folder and state are never touched. From the repo root:
   ```bash
   REPO=$PWD
   DRILL=$(mktemp -d)/terraform
   cp -r infra/terraform "$DRILL" && rm -rf "$DRILL/.terraform" "$DRILL"/*tfplan*
   cd "$DRILL"
   terraform init -backend-config=backend.hcl -backend-config=key=depscan-drill.tfstate
   VARS=(-var prefix=depscandr -var location=eastasia -var 'team_object_ids=[]' -var "budget_start=$(date -u +%Y-%m-01T00:00:00Z)")
   date -u +%H:%M   # start time
   ```
2. Build it without secrets:
   ```bash
   terraform plan -out tfplan "${VARS[@]}" -var wire_database_url=false -var enable_webhooks=false -var enable_anchoring=false
   ```
   The plan must only add resources: `0 to change, 0 to destroy`. Anything else means it's pointing at the real state, so stop. Also check that nothing in it names the real setup: `terraform show -no-color tfplan | grep -cE 'rg-depscan[/"]|depscan-server|kv-depscan-'` must print `0`. Then run `terraform apply tfplan`.
3. Store throwaway secrets. While the server doesn't read `DATABASE_URL`, a placeholder is fine; once it does, use a Neon branch's URL.
   ```bash
   KV=$(terraform output -raw key_vault_name)
   for s in database-url github-token; do az keyvault secret set --vault-name "$KV" -n "$s" --value drill-placeholder -o none; done
   V=$(openssl rand -hex 32); az keyvault secret set --vault-name "$KV" -n webhook-secret --value "$V" -o none; unset V
   (cd "$REPO" && go run ./cmd/depscan keygen -out "$DRILL/drill-key.json" >/dev/null)
   az keyvault secret set --vault-name "$KV" -n solana-key --file "$DRILL/drill-key.json" -o none && shred -u "$DRILL/drill-key.json"
   ```
   If `az` says Forbidden, wait a few minutes and run the command again.
4. Give the app its secrets: `terraform plan -out tfplan "${VARS[@]}"` should say `0 to add, 1 to change, 0 to destroy`. Then run `terraform apply tfplan`.
5. Run the live tests against it: `cd "$REPO" && DEPSCAN_URL=$(terraform -chdir="$DRILL" output -raw app_url) bash e2e/tests/07-live.sh`. Every check should pass.
6. Tear it down. `prevent_destroy` guards the environment and the app, so remove it, but only in the copy:
   ```bash
   cd "$DRILL"
   sed -i '/prevent_destroy = true/d' main.tf
   terraform plan -destroy -out tfplan "${VARS[@]}"
   terraform apply tfplan
   az group exists -n rg-depscandr   # false
   cd "$REPO" && rm -rf "$(dirname "$DRILL")"
   date -u +%H:%M   # end time
   ```
   Never run the `sed` line in `infra/terraform`. If destroying `rg-depscandr` fails because it still holds resources, run `az group delete -n rg-depscandr --yes`, then plan and apply the destroy again.
7. Add a row to the drill log below, and fix any step in this runbook that was wrong.

### Drill log

| Date | Took | What broke | Fix |
|---|---|---|---|
