# Settlement file storage (LG-DATA-01, LG-DATA-02).
resource "azurerm_storage_account" "payments" {
  name                              = "st${var.name_prefix}${var.name_suffix}"
  resource_group_name               = azurerm_resource_group.ledger.name
  location                          = azurerm_resource_group.ledger.location
  account_kind                      = "StorageV2"
  account_tier                      = "Standard"
  account_replication_type          = "ZRS"
  public_network_access             = "Disabled"
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  infrastructure_encryption_enabled = true
  cross_tenant_replication_enabled  = false
  tags                              = local.tags_payment

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.cmk.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.cmk.versionless_id
    user_assigned_identity_id = azurerm_user_assigned_identity.cmk.id
  }

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  depends_on = [azurerm_role_assignment.cmk_crypto_user]
}
