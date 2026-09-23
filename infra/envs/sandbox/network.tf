resource "azurerm_virtual_network" "ledger" {
  name                = "vnet-${var.name_prefix}-sandbox"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  address_space       = [var.vnet_address_space]
  tags                = local.tags_internal
}

resource "azurerm_subnet" "aks" {
  name                 = "snet-aks"
  resource_group_name  = azurerm_resource_group.ledger.name
  virtual_network_name = azurerm_virtual_network.ledger.name
  address_prefixes     = [local.subnet_aks]
}

resource "azurerm_subnet" "private_endpoints" {
  name                              = "snet-private-endpoints"
  resource_group_name               = azurerm_resource_group.ledger.name
  virtual_network_name              = azurerm_virtual_network.ledger.name
  address_prefixes                  = [local.subnet_pe]
  private_endpoint_network_policies = "Enabled"
}

resource "azurerm_network_security_group" "aks" {
  name                = "nsg-${var.name_prefix}-aks"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  tags                = local.tags_internal
}

# Explicit deny for management ports from the internet (LG-NET-01). The Rego
# gate prevents an allow rule from being merged; this rule is defence in depth
# against a rule added outside Terraform.
resource "azurerm_network_security_rule" "deny_internet_management" {
  name                        = "deny-internet-management"
  resource_group_name         = azurerm_resource_group.ledger.name
  network_security_group_name = azurerm_network_security_group.aks.name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Tcp"
  source_address_prefix       = "Internet"
  source_port_range           = "*"
  destination_address_prefix  = "*"
  destination_port_ranges     = ["22", "3389"]
}

resource "azurerm_subnet_network_security_group_association" "aks" {
  subnet_id                 = azurerm_subnet.aks.id
  network_security_group_id = azurerm_network_security_group.aks.id
}

resource "azurerm_private_dns_zone" "this" {
  for_each = local.private_dns_zones

  name                = each.value
  resource_group_name = azurerm_resource_group.ledger.name
  tags                = local.tags_internal
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each = local.private_dns_zones

  name                 = "link-${each.key}"
  private_dns_zone_id  = azurerm_private_dns_zone.this[each.key].id
  virtual_network_id   = azurerm_virtual_network.ledger.id
  registration_enabled = false
  tags                 = local.tags_internal
}

locals {
  private_endpoints = {
    blob = {
      resource_id = azurerm_storage_account.payments.id
      subresource = "blob"
    }
    vault = {
      resource_id = azurerm_key_vault.ledger.id
      subresource = "vault"
    }
    postgres = {
      resource_id = azurerm_postgresql_flexible_server.ledger.id
      subresource = "postgresqlServer"
    }
  }
}

resource "azurerm_private_endpoint" "this" {
  for_each = local.private_endpoints

  name                = "pe-${var.name_prefix}-${each.key}"
  resource_group_name = azurerm_resource_group.ledger.name
  location            = azurerm_resource_group.ledger.location
  subnet_id           = azurerm_subnet.private_endpoints.id
  tags                = local.tags_payment

  private_service_connection {
    name                           = "psc-${each.key}"
    private_connection_resource_id = each.value.resource_id
    subresource_names              = [each.value.subresource]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.this[each.key].id]
  }
}
