# Ledger database (LG-DB-01, LG-DATA-01, LG-BCP-01).
resource "azurerm_postgresql_flexible_server" "ledger" {
  name                          = "psql-${var.name_prefix}-${var.name_suffix}"
  resource_group_name           = azurerm_resource_group.ledger.name
  location                      = azurerm_resource_group.ledger.location
  version                       = "16"
  sku_name                      = "B_Standard_B1ms"
  storage_mb                    = 32768
  auto_grow_enabled             = true
  backup_retention_days         = 14
  geo_redundant_backup_enabled  = var.postgres_geo_redundant_backup
  public_network_access_enabled = false
  tags                          = local.tags_payment

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.cmk.id]
  }

  customer_managed_key {
    key_vault_key_id                  = azurerm_key_vault_key.cmk.versionless_id
    primary_user_assigned_identity_id = azurerm_user_assigned_identity.cmk.id
  }

  lifecycle {
    # Zone is chosen by Azure on create; changing it later forces a failover.
    ignore_changes = [zone]
  }

  depends_on = [azurerm_role_assignment.cmk_crypto_user]
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "ledger" {
  server_name         = azurerm_postgresql_flexible_server.ledger.name
  resource_group_name = azurerm_resource_group.ledger.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = var.postgres_entra_admin.object_id
  principal_name      = var.postgres_entra_admin.principal_name
  principal_type      = var.postgres_entra_admin.principal_type
}
