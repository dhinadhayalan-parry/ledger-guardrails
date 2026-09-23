variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "germanywestcentral"

  validation {
    condition     = can(regex("^[a-z0-9]+$", var.location))
    error_message = "location must be an Azure region name such as germanywestcentral."
  }
}

variable "name_prefix" {
  description = "Short lowercase prefix used in resource names."
  type        = string
  default     = "ledger"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,9}$", var.name_prefix))
    error_message = "name_prefix must be 3-10 lowercase alphanumeric characters starting with a letter."
  }
}

variable "name_suffix" {
  description = "Short suffix that makes globally unique names (Key Vault, Storage, PostgreSQL) unique."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{4,6}$", var.name_suffix))
    error_message = "name_suffix must be 4-6 lowercase alphanumeric characters."
  }
}

variable "owner" {
  description = "Owning team, written to the owner tag (LG-GOV-01)."
  type        = string

  validation {
    condition     = length(trimspace(var.owner)) > 0
    error_message = "owner must not be empty."
  }
}

variable "cost_center" {
  description = "Cost center, written to the cost-center tag (LG-GOV-01)."
  type        = string

  validation {
    condition     = can(regex("^cc-[0-9]{4}$", var.cost_center))
    error_message = "cost_center must look like cc-1234."
  }
}

variable "vnet_address_space" {
  description = "Address space of the workload virtual network (/16)."
  type        = string
  default     = "10.40.0.0/16"

  validation {
    condition     = can(cidrhost(var.vnet_address_space, 0)) && endswith(var.vnet_address_space, "/16")
    error_message = "vnet_address_space must be a valid /16 CIDR block."
  }
}

variable "postgres_entra_admin" {
  description = "Entra ID principal that administers PostgreSQL. Password authentication is disabled (LG-DB-01)."
  type = object({
    object_id      = string
    principal_name = string
    principal_type = string
  })

  validation {
    condition     = contains(["Group", "ServicePrincipal", "User"], var.postgres_entra_admin.principal_type)
    error_message = "principal_type must be Group, ServicePrincipal or User."
  }

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.postgres_entra_admin.object_id))
    error_message = "object_id must be a GUID."
  }
}

variable "aks_admin_group_object_ids" {
  description = "Entra ID groups granted cluster-admin through Azure RBAC."
  type        = list(string)

  validation {
    condition = length(var.aks_admin_group_object_ids) > 0 && alltrue([
      for id in var.aks_admin_group_object_ids :
      can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", id))
    ])
    error_message = "Provide at least one admin group object ID, each a GUID."
  }
}

variable "aks_node_vm_size" {
  description = "VM size for the AKS system node pool."
  type        = string
  default     = "Standard_D2s_v5"
}

variable "postgres_geo_redundant_backup" {
  description = "Geo-redundant backups for PostgreSQL. Required in prod (LG-BCP-01); off in sandbox to save cost, which the gate reports as a warning."
  type        = bool
  default     = false
}
