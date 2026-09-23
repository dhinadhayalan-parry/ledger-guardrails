# METADATA
# title: AKS control plane hardening
# description: >-
#   Clusters have a private API server, no local accounts, Entra ID with Azure
#   RBAC, the Azure Policy add-on, workload identity, and no public node IPs.
# custom:
#   controls: [LG-K8S-01]
package ledger.terraform.aks

import rego.v1

import data.ledger.lib

clusters := lib.changes({"azurerm_kubernetes_cluster"})

required_true := {
	"private_cluster_enabled": "API server must be private",
	"local_account_disabled": "local accounts must be disabled; authenticate through Entra ID",
	"azure_policy_enabled": "the Azure Policy add-on must be enabled so admission policies are enforced",
	"oidc_issuer_enabled": "the OIDC issuer must be enabled for workload identity",
	"workload_identity_enabled": "workload identity must be enabled; no secrets for Azure access in pods",
}

findings contains lib.finding("LG-K8S-01", rc, msg) if {
	some rc in clusters
	some attr, reason in required_true
	not rc.change.after[attr] == true
	msg := sprintf("%s must be true: %s", [attr, reason])
}

findings contains lib.finding("LG-K8S-01", rc, msg) if {
	some rc in clusters
	not lib.nested_is(rc.change.after, "azure_active_directory_role_based_access_control", "azure_rbac_enabled", true)
	msg := "azure_active_directory_role_based_access_control.azure_rbac_enabled must be true"
}

findings contains lib.finding("LG-K8S-01", rc, msg) if {
	some rc in clusters
	lib.nested_is(rc.change.after, "default_node_pool", "node_public_ip_enabled", true)
	msg := "default_node_pool.node_public_ip_enabled must not be true"
}

findings contains lib.finding("LG-K8S-01", rc, msg) if {
	some rc in lib.changes({"azurerm_kubernetes_cluster_node_pool"})
	rc.change.after.node_public_ip_enabled == true
	msg := "node_public_ip_enabled must not be true"
}
