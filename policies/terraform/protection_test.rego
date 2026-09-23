package ledger.terraform.protection_test

import rego.v1

import data.ledger.terraform.protection
import data.ledger.testing as t

destroy(type, before) := object.union(
	t.change(type, ["delete"], null),
	{"change": {"before": before}},
)

replace(type, before) := object.union(
	t.change(type, ["delete", "create"], before),
	{"change": {"before": before}},
)

findings_for(rcs) := f if {
	f := protection.findings with input as t.plan(rcs)
}

test_key_vault_destroy_is_flagged if {
	f := findings_for([destroy("azurerm_key_vault", {"tags": t.tags("internal")})])
	count(f) == 1
	some finding in f
	contains(finding.msg, "would be destroyed")
}

test_key_replacement_is_flagged if {
	f := findings_for([replace("azurerm_key_vault_key", {"name": "cmk"})])
	count(f) == 1
	some finding in f
	contains(finding.msg, "replaced")
}

test_payment_database_destroy_is_flagged if {
	count(findings_for([destroy("azurerm_postgresql_flexible_server", {"tags": t.tags("payment")})])) == 1
}

test_unclassified_storage_destroy_is_flagged if {
	count(findings_for([destroy("azurerm_storage_account", {"tags": null})])) == 1
}

test_internal_storage_destroy_is_allowed if {
	count(findings_for([destroy("azurerm_storage_account", {"tags": t.tags("internal")})])) == 0
}

test_unprotected_type_destroy_is_allowed if {
	count(findings_for([destroy("azurerm_resource_group", {"tags": t.tags("payment")})])) == 0
}

test_create_and_update_are_ignored if {
	count(findings_for([
		t.create("azurerm_key_vault", {}),
		t.change("azurerm_key_vault", ["update"], {}),
	])) == 0
}

test_data_sources_are_ignored if {
	count(findings_for([object.union(destroy("azurerm_key_vault", {}), {"mode": "data"})])) == 0
}
