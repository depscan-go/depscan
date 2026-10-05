output "app_url" {
  value = "https://${azurerm_container_app.server.ingress[0].fqdn}"
}

output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "container_app_name" {
  value = azurerm_container_app.server.name
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

# Set these as GitHub repo variables (not secrets; none of them grant access by themselves).
output "github_oidc_variables" {
  value = {
    AZURE_CLIENT_ID       = azurerm_user_assigned_identity.gha.client_id
    AZURE_TENANT_ID       = data.azurerm_client_config.current.tenant_id
    AZURE_SUBSCRIPTION_ID = var.subscription_id
  }
}
