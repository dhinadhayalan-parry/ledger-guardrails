package ledger.terraform.storage_test

import rego.v1

import data.ledger.terraform.storage
import data.ledger.testing as t

compliant := {
	"public_network_access": "Disabled",
	"allow_nested_items_to_be_public": false,
	"shared_access_key_enabled": false,
	"https_traffic_only_enabled": true,
	"min_tls_version": "TLS1_2",
	"tags": t.tags("internal"),
}

compliant_payment := object.union(compliant, {
	"tags": t.tags("payment"),
	"customer_managed_key": [{"user_assigned_identity_id": "/subscriptions/x/id"}],
})

findings_for(after) := f if {
	f := storage.findings with input as t.plan([t.create("azurerm_storage_account", after)])
}

test_compliant_internal_account_has_no_findings if {
	count(findings_for(compliant)) == 0
}

test_compliant_payment_account_with_cmk_has_no_findings if {
	count(findings_for(compliant_payment)) == 0
}

test_public_network_access_enabled if {
	f := findings_for(t.with_attrs(compliant, {"public_network_access": "Enabled"}))
	t.controls(f) == {"LG-DATA-02"}
	count(f) == 1
}

test_public_network_access_omitted_is_flagged if {
	f := findings_for(t.without_attr(compliant, "public_network_access"))
	count(f) == 1
	some finding in f
	contains(finding.msg, "explicitly")
}

test_anonymous_blob_access if {
	count(findings_for(t.with_attrs(compliant, {"allow_nested_items_to_be_public": true}))) == 1
}

test_shared_keys if {
	count(findings_for(t.with_attrs(compliant, {"shared_access_key_enabled": true}))) == 1
}

test_http_allowed if {
	count(findings_for(t.with_attrs(compliant, {"https_traffic_only_enabled": false}))) == 1
}

test_old_tls if {
	count(findings_for(t.with_attrs(compliant, {"min_tls_version": "TLS1_0"}))) == 1
}

test_tls13_allowed if {
	count(findings_for(t.with_attrs(compliant, {"min_tls_version": "TLS1_3"}))) == 0
}

test_payment_without_cmk if {
	f := findings_for(t.without_attr(compliant_payment, "customer_managed_key"))
	t.controls(f) == {"LG-DATA-01"}
}

test_confidential_with_empty_cmk_list if {
	after := t.with_attrs(compliant, {"tags": t.tags("confidential"), "customer_managed_key": []})
	t.controls(findings_for(after)) == {"LG-DATA-01"}
}

test_deleted_account_is_ignored if {
	plan := t.plan([t.change("azurerm_storage_account", ["delete"], null)])
	count(storage.findings) == 0 with input as plan
}

test_unknown_data_class_requires_cmk if {
	known := object.remove(t.tags("internal"), {"data-class"})
	rc := t.create_unknown("azurerm_storage_account", object.union(compliant, {"tags": known}), {"tags": {"data-class": true}})
	f := storage.findings with input as t.plan([rc])
	t.controls(f) == {"LG-DATA-01"}
}
