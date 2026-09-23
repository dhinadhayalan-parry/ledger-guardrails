package ledger.terraform.postgres_test

import rego.v1

import data.ledger.terraform.postgres
import data.ledger.testing as t

compliant := {
	"public_network_access_enabled": false,
	"geo_redundant_backup_enabled": false,
	"authentication": [{"active_directory_auth_enabled": true, "password_auth_enabled": false}],
	"tags": t.tags("internal"),
}

compliant_payment := t.with_attrs(compliant, {
	"geo_redundant_backup_enabled": true,
	"customer_managed_key": [{"primary_user_assigned_identity_id": "/subscriptions/x/id"}],
	"tags": t.tags("payment"),
})

findings_for(after) := f if {
	f := postgres.findings with input as t.plan([t.create("azurerm_postgresql_flexible_server", after)])
}

test_compliant_internal_server if {
	count(findings_for(compliant)) == 0
}

test_compliant_payment_server if {
	count(findings_for(compliant_payment)) == 0
}

test_public_access_unknown_is_flagged if {
	t.controls(findings_for(t.without_attr(compliant, "public_network_access_enabled"))) == {"LG-DB-01"}
}

test_password_auth_enabled if {
	after := t.with_attrs(compliant, {"authentication": [{"active_directory_auth_enabled": true, "password_auth_enabled": true}]})
	count(findings_for(after)) == 1
}

test_missing_authentication_block_flags_both_settings if {
	count(findings_for(t.without_attr(compliant, "authentication"))) == 2
}

test_payment_without_cmk_or_geo_backup if {
	after := t.with_attrs(t.without_attr(compliant_payment, "customer_managed_key"), {"geo_redundant_backup_enabled": false})
	t.controls(findings_for(after)) == {"LG-DATA-01", "LG-BCP-01"}
}

test_confidential_does_not_require_geo_backup if {
	after := t.with_attrs(compliant_payment, {"tags": t.tags("confidential"), "geo_redundant_backup_enabled": false})
	count(findings_for(after)) == 0
}
