# Test helpers that build minimal `terraform show -json` documents.
package ledger.testing

import rego.v1

change(type, actions, after) := {
	"address": sprintf("%s.test", [type]),
	"mode": "managed",
	"type": type,
	"name": "test",
	"change": {"actions": actions, "after": after},
}

create(type, after) := change(type, ["create"], after)

plan(resource_changes) := {"format_version": "1.2", "resource_changes": resource_changes}

tags(class) := {"owner": "platform", "cost-center": "cc-1001", "data-class": class}

# Merge overrides into a base object (shallow).
with_attrs(base, overrides) := object.union(base, overrides)

without_attr(base, key) := object.remove(base, {key})

controls(findings) := {f.control | some f in findings}

test_lib_changes_ignores_deletes_and_data_sources if {
	input_plan := plan([
		change("azurerm_key_vault", ["delete"], null),
		change("azurerm_key_vault", ["no-op"], {}),
		object.union(create("azurerm_key_vault", {}), {"mode": "data"}),
		create("azurerm_key_vault", {}),
		change("azurerm_key_vault", ["delete", "create"], {}),
	])
	count(data.ledger.lib.changes({"azurerm_key_vault"})) == 2 with input as input_plan
}
