package main_test

import rego.v1

import data.ledger.testing as t
import data.main

catalog := {
	"LG-KEY-01": {"mode": {"sandbox": "enforce", "prod": "enforce"}},
	"LG-BCP-01": {"mode": {"sandbox": "warn", "prod": "enforce"}},
}

# A payment database without geo backups (LG-BCP-01) inside an otherwise
# compliant plan, plus a Key Vault without purge protection (LG-KEY-01).
plan := t.plan([
	t.create("azurerm_postgresql_flexible_server", {
		"public_network_access_enabled": false,
		"geo_redundant_backup_enabled": false,
		"authentication": [{"active_directory_auth_enabled": true, "password_auth_enabled": false}],
		"customer_managed_key": [{}],
		"tags": t.tags("payment"),
	}),
	t.create("azurerm_key_vault", {
		"purge_protection_enabled": false,
		"rbac_authorization_enabled": true,
		"public_network_access_enabled": false,
		"soft_delete_retention_days": 90,
		"tags": t.tags("payment"),
	}),
])

test_sandbox_warns_on_warn_mode_controls if {
	main.warn == {"[LG-BCP-01] azurerm_postgresql_flexible_server.test: data-class \"payment\" requires geo_redundant_backup_enabled = true"} with input as plan
		with data.controls as catalog
		with data.ledger_env as "sandbox"
	count(main.deny) == 1 with input as plan
		with data.controls as catalog
		with data.ledger_env as "sandbox"
}

test_prod_blocks_the_same_finding if {
	count(main.warn) == 0 with input as plan
		with data.controls as catalog
		with data.ledger_env as "prod"
	count(main.deny) == 2 with input as plan
		with data.controls as catalog
		with data.ledger_env as "prod"
}

test_unknown_environment_fails_safe_to_prod if {
	count(main.deny) == 2 with input as plan
		with data.controls as catalog
		with data.ledger_env as "staging-typo"
}

test_missing_environment_fails_safe_to_prod if {
	main.environment == "prod" with data.controls as catalog
}

test_control_missing_from_catalog_is_enforced if {
	count(main.deny) == 2 with input as plan
		with data.controls as {}
		with data.ledger_env as "sandbox"
}
