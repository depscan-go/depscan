locals {
  tags = {
    project    = var.prefix
    managed_by = "terraform"
  }

  # Key Vault names are global; a stable suffix avoids pulling in the random provider.
  suffix = substr(sha1(var.subscription_id), 0, 6)

  # Env var => Key Vault secret name, for every secret the app gets.
  app_secrets = merge(
    var.wire_database_url ? { DATABASE_URL = "database-url" } : {},
    var.enable_webhooks ? { DEPSCAN_WEBHOOK_SECRET = "webhook-secret", GITHUB_TOKEN = "github-token" } : {},
    var.enable_anchoring ? { DEPSCAN_SOLANA_KEY = "solana-key" } : {},
  )

  # Plain settings (not secret). The public URL is built from the environment's domain,
  # because the app can't refer to its own address.
  app_env = merge(
    { DEPSCAN_PUBLIC_URL = "https://${var.prefix}-server.${azurerm_container_app_environment.main.default_domain}" },
    var.enable_anchoring ? { DEPSCAN_ANCHOR = "solana", DEPSCAN_SOLANA_RPC = var.solana_rpc } : {},
  )
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.prefix}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${var.prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  # Ingestion cap: log volume is the usual surprise cost on a student budget.
  daily_quota_gb = 0.1
  tags           = local.tags
}

resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${var.prefix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  logs_destination           = "log-analytics"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  tags                       = local.tags

  # Azure creates every new environment with this profile; without it here, Terraform tries to remove it.
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }
}

resource "azurerm_container_app" "server" {
  name                         = "${var.prefix}-server"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  # Azure for Students only gets Express environments, which reject Key Vault references,
  # so Terraform copies the values in. Key Vault stays the source of truth: rotate there, then apply.
  dynamic "secret" {
    for_each = local.app_secrets
    content {
      name  = secret.value
      value = data.azurerm_key_vault_secret.app[secret.key].value
    }
  }

  template {
    # Scale to zero when idle: the free grant only bills running replicas.
    min_replicas = 0
    max_replicas = 1

    # Azure's default rule for apps with ingress; declared so Terraform doesn't try to delete it.
    http_scale_rule {
      name                = "http-scaler"
      concurrent_requests = "10"
    }

    container {
      name  = "server"
      image = var.app_image
      # Container Apps pairs 2 GiB with each vCPU. At this size the free allowance covers
      # about 100 awake hours a month, far more than our traffic needs.
      cpu    = 0.5
      memory = "1Gi"

      dynamic "env" {
        for_each = local.app_secrets
        content {
          name        = env.key
          secret_name = env.value
        }
      }

      dynamic "env" {
        for_each = local.app_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = var.app_port
    # Azure stores "auto" as "Http", so "auto" would show a diff on every plan.
    transport = "http"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  lifecycle {
    ignore_changes = [
      # CI deploys new images; without this, every apply would roll back to var.app_image.
      template[0].container[0].image,
      # Azure stores its defaults (300s / 30s) as null, which the provider reads back as 0.
      template[0].cooldown_period_in_seconds,
      template[0].polling_interval_in_seconds,
      # Single-revision apps don't store traffic weights, so this would be re-added on every plan.
      ingress[0].traffic_weight,
    ]
  }
}
