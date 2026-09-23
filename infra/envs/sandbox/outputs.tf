output "resource_group_name" {
  description = "Resource group holding the sandbox workload."
  value       = azurerm_resource_group.ledger.name
}

output "aks_cluster_name" {
  description = "AKS cluster name, for `az aks get-credentials`."
  value       = azurerm_kubernetes_cluster.ledger.name
}

output "aks_oidc_issuer_url" {
  description = "OIDC issuer used to federate workload identities."
  value       = azurerm_kubernetes_cluster.ledger.oidc_issuer_url
}

output "key_vault_uri" {
  description = "Key Vault URI (reachable only over the private endpoint)."
  value       = azurerm_key_vault.ledger.vault_uri
}

output "postgres_fqdn" {
  description = "PostgreSQL FQDN (resolves to the private endpoint inside the VNet)."
  value       = azurerm_postgresql_flexible_server.ledger.fqdn
}
