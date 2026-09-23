# Inputs for the offline plan in CI (scripts/offline_plan.sh). The object IDs
# are fake; real deployments pass these as TF_VAR_* from the pipeline.
name_suffix = "a1b2"
owner       = "platform"
cost_center = "cc-1001"

postgres_entra_admin = {
  object_id      = "00000000-0000-0000-0000-000000000001"
  principal_name = "sg-ledger-db-admins"
  principal_type = "Group"
}

aks_admin_group_object_ids = ["00000000-0000-0000-0000-000000000002"]
