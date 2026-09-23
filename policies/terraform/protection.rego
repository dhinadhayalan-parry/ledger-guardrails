# METADATA
# title: Protected resources are not destroyed
# description: >-
#   Plans must not destroy or replace resources whose loss is irreversible or
#   loses data: Key Vaults, keys and managed HSMs always, and databases and
#   storage accounts unless their current data-class is explicitly public or
#   internal. Replacement counts as destruction. The class is read from the
#   resource's current state (`before`), so an unclassified resource is
#   protected. A legitimate teardown needs an approved exemption in
#   config/exemptions.yaml, merged before the change (gate.rego).
# custom:
#   controls: [LG-BCP-02]
package ledger.terraform.protection

import rego.v1

import data.ledger.lib

always_protected := {
	"azurerm_key_vault",
	"azurerm_key_vault_key",
	"azurerm_key_vault_managed_hardware_security_module",
}

protected_unless_non_sensitive := {
	"azurerm_postgresql_flexible_server",
	"azurerm_storage_account",
}

non_sensitive_classes := {"public", "internal"}

destroyed := {rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	"delete" in rc.change.actions
}

protected(rc) if rc.type in always_protected

protected(rc) if {
	rc.type in protected_unless_non_sensitive
	not object.get(rc.change, ["before", "tags", "data-class"], "") in non_sensitive_classes
}

outcome(rc) := "replaced (destroyed and re-created)" if "create" in rc.change.actions

outcome(rc) := "destroyed" if not "create" in rc.change.actions

findings contains lib.finding("LG-BCP-02", rc, msg) if {
	some rc in destroyed
	protected(rc)
	msg := sprintf(
		"protected resource would be %s; add an approved exemption to config/exemptions.yaml first",
		[outcome(rc)],
	)
}
