provider "azurerm" {
  subscription_id = var.subscription_id

  features {
    key_vault {
      # Lets `terraform destroy` fully remove the vault so its name can be reused.
      purge_soft_delete_on_destroy = true
    }
  }
}

data "azurerm_client_config" "current" {}
