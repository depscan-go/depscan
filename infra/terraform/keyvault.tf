resource "azurerm_key_vault" "main" {
  name                       = "kv-${var.prefix}-${local.suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  # Student project: keep destroy/re-create cheap. Turn purge protection on for anything real.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  tags                       = local.tags
}

# Whoever runs Terraform can write secrets (e.g. the Neon URL via `az keyvault secret set`).
resource "azurerm_role_assignment" "me_kv_secrets_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

data "azurerm_key_vault_secret" "database_url" {
  count        = var.wire_database_url ? 1 : 0
  name         = "database-url"
  key_vault_id = azurerm_key_vault.main.id
}

# Unused while the app gets DATABASE_URL as a copied secret; lets the server read Key Vault itself later.
resource "azurerm_role_assignment" "app_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}
