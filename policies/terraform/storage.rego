# METADATA
# title: Storage account hardening
# description: >-
#   Storage accounts are private, HTTPS-only, TLS 1.2+, Entra ID authenticated,
#   and encrypted with a customer-managed key when they hold sensitive data.
# custom:
#   controls: [LG-DATA-01, LG-DATA-02]
package ledger.terraform.storage

import rego.v1

import data.ledger.lib

accounts := lib.changes({"azurerm_storage_account"})

allowed_tls := {"TLS1_2", "TLS1_3"}

findings contains lib.finding("LG-DATA-02", rc, msg) if {
	some rc in accounts
	rc.change.after.public_network_access != "Disabled"
	msg := "public_network_access must be \"Disabled\"; expose the account through a private endpoint"
}

# public_network_access is optional and computed. When it is omitted the value
# is unknown at plan time and the key is absent from `after`, so the check
# above cannot fire. Require it to be set explicitly.
findings contains lib.finding("LG-DATA-02", rc, msg) if {
	some rc in accounts
	not "public_network_access" in object.keys(rc.change.after)
	msg := "public_network_access must be set explicitly to \"Disabled\""
}

findings contains lib.finding("LG-DATA-02", rc, msg) if {
	some rc in accounts
	not rc.change.after.allow_nested_items_to_be_public == false
	msg := "allow_nested_items_to_be_public must be false (no anonymous blob access)"
}

findings contains lib.finding("LG-DATA-02", rc, msg) if {
	some rc in accounts
	not rc.change.after.shared_access_key_enabled == false
	msg := "shared_access_key_enabled must be false; use Entra ID authentication"
}

findings contains lib.finding("LG-DATA-02", rc, msg) if {
	some rc in accounts
	not rc.change.after.https_traffic_only_enabled == true
	msg := "https_traffic_only_enabled must be true"
}

findings contains lib.finding("LG-DATA-02", rc, msg) if {
	some rc in accounts
	not rc.change.after.min_tls_version in allowed_tls
	msg := sprintf("min_tls_version must be one of %v", [sort(allowed_tls)])
}

# Only the inline customer_managed_key block is recognised. The standalone
# azurerm_storage_account_customer_managed_key resource cannot be linked to its
# account at plan time for new accounts (the account ID is unknown), so this
# repository standardises on the inline block. See docs/adr/0002.
findings contains lib.finding("LG-DATA-01", rc, msg) if {
	some rc in accounts
	lib.is_sensitive(rc)
	not lib.has_block(rc.change.after, "customer_managed_key")
	msg := sprintf(
		"data-class %q requires an inline customer_managed_key block",
		[lib.data_class(rc)],
	)
}
