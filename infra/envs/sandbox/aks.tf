# Private AKS cluster (LG-K8S-01). Admission controls LG-K8S-02 and LG-K8S-03
# are enforced inside the cluster by the Azure Policy add-on.
resource "azurerm_kubernetes_cluster" "ledger" {
  name                         = "aks-${var.name_prefix}-sandbox"
  resource_group_name          = azurerm_resource_group.ledger.name
  location                     = azurerm_resource_group.ledger.location
  dns_prefix_private_cluster   = "${var.name_prefix}-sandbox"
  sku_tier                     = "Free"
  private_cluster_enabled      = true
  private_dns_zone_id          = "System"
  local_account_disabled       = true
  azure_policy_enabled         = true
  oidc_issuer_enabled          = true
  workload_identity_enabled    = true
  automatic_upgrade_channel    = "patch"
  node_os_upgrade_channel      = "NodeImage"
  image_cleaner_enabled        = true
  image_cleaner_interval_hours = 48
  run_command_enabled          = false
  tags                         = local.tags_internal

  default_node_pool {
    name                         = "system"
    vm_size                      = var.aks_node_vm_size
    vnet_subnet_id               = azurerm_subnet.aks.id
    auto_scaling_enabled         = true
    min_count                    = 1
    max_count                    = 3
    os_sku                       = "AzureLinux"
    only_critical_addons_enabled = false
    node_public_ip_enabled       = false
    host_encryption_enabled      = false
    temporary_name_for_rotation  = "systemtmp"
    tags                         = local.tags_internal

    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  # Node auto-provisioning (Karpenter) stays off in the sandbox; the fixed
  # system pool with the cluster autoscaler is cheaper at this size.
  node_provisioning_profile {
    mode = "Manual"
  }

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled     = true
    tenant_id              = data.azurerm_client_config.current.tenant_id
    admin_group_object_ids = var.aks_admin_group_object_ids
  }

  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    network_policy      = "cilium"
    load_balancer_sku   = "standard"
    outbound_type       = "loadBalancer"
    pod_cidr            = "192.168.0.0/16"
    service_cidr        = "172.16.0.0/16"
    dns_service_ip      = "172.16.0.10"
  }

  lifecycle {
    ignore_changes = [default_node_pool[0].node_count]
  }

  depends_on = [azurerm_subnet_network_security_group_association.aks]
}
