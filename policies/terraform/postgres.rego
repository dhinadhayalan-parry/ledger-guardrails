# METADATA
# title: PostgreSQL Flexible Server hardening
# description: >-
#   Servers are private and Entra ID only. Sensitive data uses a customer-managed
#   key, and payment data keeps geo-redundant backups.
# custom:
#   controls: [LG-DATA-01, LG-DB-01, LG-BCP-01]
package ledger.terraform.postgres

import rego.v1

import data.ledger.lib

servers := lib.changes({"azurerm_postgresql_flexible_server"})

findings contains lib.finding("LG-DB-01", rc, msg) if {
	some rc in servers
	not rc.change.after.public_network_access_enabled == false
	msg := "public_network_access_enabled must be set explicitly to false"
}

findings contains lib.finding("LG-DB-01", rc, msg) if {
	some rc in servers
	not lib.nested_is(rc.change.after, "authentication", "active_directory_auth_enabled", true)
	msg := "authentication.active_directory_auth_enabled must be true"
}

findings contains lib.finding("LG-DB-01", rc, msg) if {
	some rc in servers
	not lib.nested_is(rc.change.after, "authentication", "password_auth_enabled", false)
	msg := "authentication.password_auth_enabled must be false (Entra ID only)"
}

findings contains lib.finding("LG-DATA-01", rc, msg) if {
	some rc in servers
	lib.is_sensitive(rc)
	not lib.has_block(rc.change.after, "customer_managed_key")
	msg := sprintf(
		"data-class %q requires a customer_managed_key block",
		[lib.data_class(rc)],
	)
}

findings contains lib.finding("LG-BCP-01", rc, msg) if {
	some rc in servers
	lib.is_payment(rc)
	not rc.change.after.geo_redundant_backup_enabled == true
	msg := "data-class \"payment\" requires geo_redundant_backup_enabled = true"
}
