# Runtime identity: the server uses it to read secrets from Key Vault, nothing else.
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${var.prefix}-app"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

# Deploy identity: GitHub Actions logs in as this via OIDC, so no Azure password is stored in GitHub.
resource "azurerm_user_assigned_identity" "gha" {
  name                = "id-${var.prefix}-gha"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "gha_main" {
  name                      = "github-main"
  user_assigned_identity_id = azurerm_user_assigned_identity.gha.id
  issuer                    = "https://token.actions.githubusercontent.com"
  # Only workflow runs on this repo's main branch can exchange their token for this identity.
  subject  = "repo:${var.github_repo}:ref:refs/heads/main"
  audience = ["api://AzureADTokenExchange"]
}

# CI only rolls out new images, so it gets write access to the container app and nothing wider.
resource "azurerm_role_assignment" "gha_app_contributor" {
  scope                = azurerm_container_app.server.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.gha.principal_id
  principal_type       = "ServicePrincipal"
}
