terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.8"
    }
  }

  # Partial config: the values live in backend.hcl (see backend.hcl.example).
  backend "azurerm" {}
}
