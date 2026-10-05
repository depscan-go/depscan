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

variable "github_repo" {
  description = "owner/repo whose main branch may deploy via OIDC."
  type        = string
  default     = "depscan-go/depscan"
}

variable "app_image" {
  description = "Image used when the container app is first created. Later images are deployed by CI, and Terraform ignores changes to this."
  type        = string
  default     = "mcr.microsoft.com/k8se/quickstart:latest"
}

variable "app_port" {
  description = "Port the container listens on (quickstart image: 80; depscan server: whatever cmd/server binds)."
  type        = number
  default     = 80
}

variable "wire_database_url" {
  description = "Copy the Key Vault secret 'database-url' into the app as DATABASE_URL. Set true only after that secret exists."
  type        = bool
  default     = false
}
