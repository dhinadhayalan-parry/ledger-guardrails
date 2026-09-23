# A deliberately non-compliant change: the kind of "quick fix" PR the gate
# exists to stop. CI plans this module offline and asserts that the gate
# rejects it with the expected control IDs (see expected-denies.txt next to this file).
#
# Never apply this module.

terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.6"
    }
  }
}

provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
}

data "azurerm_client_config" "current" {}

# LG-GOV-01: no cost-center or data-class tag.
resource "azurerm_resource_group" "hotfix" {
  name     = "rg-ledger-hotfix"
  location = "germanywestcentral"
  tags     = { owner = "someone" }
}

# LG-DATA-02: public, shared keys, anonymous blob access. LG-DATA-01: payment data without CMK.
resource "azurerm_storage_account" "export" {
  name                            = "stledgerexport01"
  resource_group_name             = azurerm_resource_group.hotfix.name
  location                        = azurerm_resource_group.hotfix.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  public_network_access           = "Enabled"
  shared_access_key_enabled       = true
  allow_nested_items_to_be_public = true

  tags = {
    owner         = "someone"
    "cost-center" = "cc-1001"
    "data-class"  = "payment"
  }
}

# LG-NET-01: SSH open to the internet "just for debugging".
resource "azurerm_network_security_group" "debug" {
  name                = "nsg-ledger-debug"
  resource_group_name = azurerm_resource_group.hotfix.name
  location            = azurerm_resource_group.hotfix.location

  security_rule {
    name                       = "allow-ssh-debug"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = "*"
    source_port_range          = "*"
    destination_address_prefix = "*"
    destination_port_range     = "22"
  }

  tags = {
    owner         = "someone"
    "cost-center" = "cc-1001"
    "data-class"  = "internal"
  }
}

# LG-KEY-01: purgeable vault reachable from the internet.
resource "azurerm_key_vault" "hotfix" {
  name                       = "kv-ledger-hotfix01"
  resource_group_name        = azurerm_resource_group.hotfix.name
  location                   = azurerm_resource_group.hotfix.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = {
    owner         = "someone"
    "cost-center" = "cc-1001"
    "data-class"  = "confidential"
  }
}
