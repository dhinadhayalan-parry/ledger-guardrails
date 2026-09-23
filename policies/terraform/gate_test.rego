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

# Exemptions: a destroyed Key Vault (LG-BCP-02) in prod.
exemption_catalog := {"LG-BCP-02": {"mode": {"sandbox": "warn", "prod": "enforce"}, "exemptible": true}}

vault_destroy_plan := t.plan([object.union(
	t.change("azurerm_key_vault", ["delete"], null),
	{"address": "azurerm_key_vault.main", "change": {"before": {}}},
)])

exemption := {
	"control": "LG-BCP-02",
	"env": "prod",
	"resource": "azurerm_key_vault.main",
	"reason": "decommission",
	"ticket": "CHG-1",
	"expires_on": "2026-10-31",
}

# 2026-10-01T00:00:00Z and 2026-11-01T00:00:00Z
before_expiry := 1790812800000000000

after_expiry := 1793491200000000000

gate(exemptions, catalog, now) := {"deny": d, "warn": w} if {
	d := main.deny with input as vault_destroy_plan
		with data.controls as catalog
		with data.ledger_env as "prod"
		with data.exemptions as exemptions
		with time.now_ns as now
	w := main.warn with input as vault_destroy_plan
		with data.controls as catalog
		with data.ledger_env as "prod"
		with data.exemptions as exemptions
		with time.now_ns as now
}

test_destroy_without_exemption_is_denied if {
	r := gate([], exemption_catalog, before_expiry)
	count(r.deny) == 1
	count(r.warn) == 0
}

test_active_exemption_downgrades_to_visible_warning if {
	r := gate([exemption], exemption_catalog, before_expiry)
	count(r.deny) == 0
	r.warn == {"[LG-BCP-02] azurerm_key_vault.main: protected resource would be destroyed; add an approved exemption to config/exemptions.yaml first (exempted until 2026-10-31: CHG-1)"}
}

test_expired_exemption_is_ignored if {
	count(gate([exemption], exemption_catalog, after_expiry).deny) == 1
}

test_malformed_expiry_is_ignored if {
	count(gate([object.union(exemption, {"expires_on": "31/10/2026"})], exemption_catalog, before_expiry).deny) == 1
}

test_exemption_for_other_env_is_ignored if {
	count(gate([object.union(exemption, {"env": "sandbox"})], exemption_catalog, before_expiry).deny) == 1
}

test_exemption_for_other_resource_is_ignored if {
	count(gate([object.union(exemption, {"resource": "azurerm_key_vault.other"})], exemption_catalog, before_expiry).deny) == 1
}

test_exemption_without_ticket_is_ignored if {
	count(gate([object.remove(exemption, {"ticket"})], exemption_catalog, before_expiry).deny) == 1
}

test_non_exemptible_control_cannot_be_exempted if {
	catalog := {"LG-BCP-02": {"mode": {"sandbox": "warn", "prod": "enforce"}}}
	count(gate([exemption], catalog, before_expiry).deny) == 1
}
