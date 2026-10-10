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
  description = "Copy the Key Vault secret 'database-url' into the app as DATABASE_URL. Set true only after that secret exists."
  type        = bool
  default     = false
}
