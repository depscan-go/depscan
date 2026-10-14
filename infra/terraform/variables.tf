variable "subscription_id" {
  description = "Azure for Students subscription ID (az account list -o table)."
  type        = string
}

variable "location" {
  description = "Azure region. Must be allowed by the subscription's sys.regionrestriction policy."
  type        = string
}

variable "prefix" {
  description = "Short name used in every resource name."
  type        = string
  default     = "depscan"

  validation {
    # Key Vault names are capped at 24 chars: "kv-" + prefix + "-" + 6-char suffix.
    condition     = can(regex("^[a-z][a-z0-9]{1,13}$", var.prefix))
    error_message = "prefix must be 2-14 lowercase letters/digits, starting with a letter."
  }
}

variable "github_oidc_subject_prefix" {
  description = "OIDC subject prefix of the repo allowed to deploy. The repo uses immutable subjects (owner/repo IDs included), so recreating it changes this. Get it with: gh api repos/OWNER/REPO/actions/oidc/customization/sub --jq .sub_claim_prefix"
  type        = string
  default     = "repo:depscan-go@336174858/depscan@1404590227"
}

variable "app_image" {
  description = "Image used when the container app is first created. Later images are deployed by CI (cd.yaml), and Terraform ignores changes to this."
  type        = string
  default     = "ghcr.io/depscan-go/depscan:latest"
}

variable "app_port" {
  description = "Port the container listens on (deploy/Dockerfile runs the server with -addr :8080)."
  type        = number
  default     = 8080
}

variable "wire_database_url" {
  description = "Copy the Key Vault secret 'database-url' into the app as DATABASE_URL. The secret must exist before plan."
  type        = bool
  default     = true
}

variable "enable_webhooks" {
  description = "Copy the Key Vault secrets 'webhook-secret' and 'github-token' into the app as DEPSCAN_WEBHOOK_SECRET and GITHUB_TOKEN, which turns on GitHub webhooks. Both secrets must exist before plan."
  type        = bool
  default     = true
}

variable "monthly_budget" {
  description = "Monthly spend (in the billing currency, USD for Azure for Students) that triggers budget emails."
  type        = number
  default     = 10
}

variable "budget_start" {
  description = "First day of the first budget month (Azure needs the 1st of a month)."
  type        = string
  default     = "2026-10-01T00:00:00Z"
}

variable "alert_emails" {
  description = "Addresses for budget and error alerts. Set this in terraform.tfvars (gitignored) so no address ends up in the repo."
  type        = list(string)
  default     = []
}

variable "enable_anchoring" {
  description = "Anchor PR scan reports on Solana: sets DEPSCAN_ANCHOR=solana and copies the Key Vault secret 'solana-key' into the app as DEPSCAN_SOLANA_KEY. The secret must exist before plan, and its address needs SOL for fees."
  type        = bool
  default     = true
}

variable "solana_rpc" {
  description = "Solana network for anchoring: devnet, testnet, mainnet-beta or an RPC URL. Devnet is free but can be reset, so its anchors are for demos."
  type        = string
  default     = "devnet"
}
