package ledger.terraform.keyvault_test

import rego.v1

import data.ledger.terraform.keyvault
import data.ledger.testing as t

compliant := {
	"purge_protection_enabled": true,
	"rbac_authorization_enabled": true,
	"public_network_access_enabled": false,
	"soft_delete_retention_days": 90,
	"tags": t.tags("confidential"),
}

findings_for(after) := f if {
	f := keyvault.findings with input as t.plan([t.create("azurerm_key_vault", after)])
}

test_compliant_vault if {
	count(findings_for(compliant)) == 0
}

test_each_setting_is_enforced if {
	cases := [
		{"purge_protection_enabled": false},
		{"rbac_authorization_enabled": false},
		{"public_network_access_enabled": true},
		{"soft_delete_retention_days": 7},
	]
	every override in cases {
		count(findings_for(t.with_attrs(compliant, override))) == 1
	}
}

test_unknown_public_access_is_flagged if {
	count(findings_for(t.without_attr(compliant, "public_network_access_enabled"))) == 1
}
