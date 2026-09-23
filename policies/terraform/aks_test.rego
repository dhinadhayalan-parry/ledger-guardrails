package ledger.terraform.aks_test

import rego.v1

import data.ledger.terraform.aks
import data.ledger.testing as t

compliant := {
	"private_cluster_enabled": true,
	"local_account_disabled": true,
	"azure_policy_enabled": true,
	"oidc_issuer_enabled": true,
	"workload_identity_enabled": true,
	"azure_active_directory_role_based_access_control": [{"azure_rbac_enabled": true}],
	"default_node_pool": [{"name": "system", "node_public_ip_enabled": false}],
	"tags": t.tags("internal"),
}

findings_for(after) := f if {
	f := aks.findings with input as t.plan([t.create("azurerm_kubernetes_cluster", after)])
}

test_compliant_cluster if {
	count(findings_for(compliant)) == 0
}

test_each_required_flag if {
	every attr, _ in aks.required_true {
		count(findings_for(t.with_attrs(compliant, {attr: false}))) == 1
	}
}

test_missing_flags_are_flagged if {
	stripped := object.remove(compliant, object.keys(aks.required_true))
	count(findings_for(stripped)) == count(aks.required_true)
}

test_kubernetes_rbac_without_azure_rbac if {
	after := t.with_attrs(compliant, {"azure_active_directory_role_based_access_control": []})
	count(findings_for(after)) == 1
}

test_public_node_ips_in_default_pool if {
	after := t.with_attrs(compliant, {"default_node_pool": [{"name": "system", "node_public_ip_enabled": true}]})
	count(findings_for(after)) == 1
}

test_public_node_ips_in_extra_pool if {
	plan := t.plan([t.create("azurerm_kubernetes_cluster_node_pool", {"node_public_ip_enabled": true})])
	count(aks.findings) == 1 with input as plan
}
