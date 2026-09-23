# Key Vault holding the customer-managed keys (LG-KEY-01, LG-DATA-01).
#
# Public network access is disabled, so creating or rotating keys requires a
# runner with private connectivity to the vault (self-hosted runner in the VNet,
# Phase 1). GitHub-hosted runners can still run `terraform plan`, because the
# plan for a new key does not touch the Key Vault data plane.
resource "azurerm_key_vault" "ledger" {
  name                          = "kv-${var.name_prefix}-${var.name_suffix}"
  resource_group_name           = azurerm_resource_group.ledger.name
  location                      = azurerm_resource_group.ledger.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false
  tags                          = local.tags_payment

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault_key" "cmk" {
  name         = "cmk-ledger-data"
  key_vault_id = azurerm_key_vault.ledger.id
  key_type     = "RSA-HSM"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]
  tags         = local.tags_payment

  rotation_policy {
    expire_after         = "P2Y"
    notify_before_expiry = "P30D"

    automatic {
      time_before_expiry = "P60D"
    }
  }
}

# The CMK identity may only wrap and unwrap keys in this vault. The apply
# identity is allowed to create this assignment through a constrained
# "Role Based Access Control Administrator" grant (see README, "Pipeline identities").
resource "azurerm_role_assignment" "cmk_crypto_user" {
  scope                            = azurerm_key_vault.ledger.id
  role_definition_name             = "Key Vault Crypto Service Encryption User"
  principal_id                     = azurerm_user_assigned_identity.cmk.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
