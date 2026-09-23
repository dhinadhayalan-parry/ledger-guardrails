terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.6"
    }
  }

  # Partial configuration: resource_group_name, storage_account_name,
  # container_name and key are supplied with -backend-config at init time, so
  # no environment-specific names are committed. State access uses Entra ID
  # (no storage account keys) and OIDC from GitHub Actions.
  backend "azurerm" {
    use_oidc         = true
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }

  use_oidc = true

  # Shared keys are disabled on every storage account (LG-DATA-02), so the
  # provider must use Entra ID for data-plane operations.
  storage_use_azuread = true

  # Resource provider registration is handled once per subscription by the
  # landing zone, not by every workload pipeline.
  resource_provider_registrations = "none"
}
