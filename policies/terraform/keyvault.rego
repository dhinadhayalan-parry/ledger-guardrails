# METADATA
# title: Key Vault hardening
# description: >-
#   Vaults cannot be purged, use Azure RBAC for the data plane, keep the maximum
#   soft-delete window, and are not reachable from the public internet.
# custom:
#   controls: [LG-KEY-01]
package ledger.terraform.keyvault

import rego.v1

import data.ledger.lib

vaults := lib.changes({"azurerm_key_vault"})

required_soft_delete_days := 90

findings contains lib.finding("LG-KEY-01", rc, msg) if {
	some rc in vaults
	not rc.change.after.purge_protection_enabled == true
	msg := "purge_protection_enabled must be true"
}

findings contains lib.finding("LG-KEY-01", rc, msg) if {
	some rc in vaults
	not rc.change.after.rbac_authorization_enabled == true
	msg := "rbac_authorization_enabled must be true (no legacy access policies)"
}

findings contains lib.finding("LG-KEY-01", rc, msg) if {
	some rc in vaults
	not rc.change.after.public_network_access_enabled == false
	msg := "public_network_access_enabled must be set explicitly to false"
}

findings contains lib.finding("LG-KEY-01", rc, msg) if {
	some rc in vaults
	not rc.change.after.soft_delete_retention_days == required_soft_delete_days
	msg := sprintf("soft_delete_retention_days must be %d", [required_soft_delete_days])
}
