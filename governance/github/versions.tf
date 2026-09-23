terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.6"
    }
  }

  # Same state backend as the workload, separate key. Supplied at init time:
  #   -backend-config="resource_group_name=..." -backend-config="storage_account_name=..."
  #   -backend-config="container_name=..." -backend-config="key=ledger/github.tfstate"
  # The state holds no secrets, only rule and environment IDs.
  backend "azurerm" {
    use_azuread_auth = true
  }
}

# Authenticates with GITHUB_TOKEN from the environment: a fine-grained token
# scoped to this one repository with "Administration: read and write" and
# "Environments: read and write", short-lived, never committed.
provider "github" {
  owner = var.owner
}
