data "azurerm_client_config" "current" {}

locals {
  base_tags = {
    owner         = var.owner
    "cost-center" = var.cost_center
    environment   = "sandbox"
    "managed-by"  = "terraform"
    repository    = "ledger-guardrails"
  }

  # data-class drives which controls apply (LG-GOV-01, LG-DATA-01, LG-BCP-01).
  tags_internal = merge(local.base_tags, { "data-class" = "internal" })
  tags_payment  = merge(local.base_tags, { "data-class" = "payment" })

  # Subnet layout inside the /16.
  subnet_aks = cidrsubnet(var.vnet_address_space, 6, 0)  # /22 for nodes (Azure CNI Overlay)
  subnet_pe  = cidrsubnet(var.vnet_address_space, 8, 16) # /24 for private endpoints

  private_dns_zones = {
    blob     = "privatelink.blob.core.windows.net"
    vault    = "privatelink.vaultcore.azure.net"
    postgres = "privatelink.postgres.database.azure.com"
  }
}

resource "azurerm_resource_group" "ledger" {
  name     = "rg-${var.name_prefix}-sandbox"
  location = var.location
  tags     = local.tags_payment
}

# Identity that storage and PostgreSQL use to unwrap their customer-managed
# keys. One identity per workload keeps the Key Vault role assignment auditable.
resource "azurerm_user_assigned_identity" "cmk" {
  name                = "id-${var.name_prefix}-cmk"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  tags                = local.tags_payment
}
