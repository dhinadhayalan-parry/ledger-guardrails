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

# A create whose `after_unknown` marks values that are only known after apply.
create_unknown(type, after, after_unknown) := object.union(
	create(type, after),
	{"change": {"after_unknown": after_unknown}},
)

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

test_lib_data_class_known if {
	data.ledger.lib.data_class(create("azurerm_storage_account", {"tags": tags("internal")})) == "internal"
}

test_lib_data_class_whole_tag_map_unknown_is_strictest if {
	rc := create_unknown("azurerm_storage_account", {}, {"tags": true})
	data.ledger.lib.data_class(rc) == "payment"
}

test_lib_data_class_value_unknown_is_strictest if {
	known := object.remove(tags("internal"), {"data-class"})
	rc := create_unknown("azurerm_storage_account", {"tags": known}, {"tags": {"data-class": true}})
	data.ledger.lib.data_class(rc) == "payment"
}

test_lib_other_unknown_tag_keeps_known_class if {
	rc := create_unknown("azurerm_storage_account", {"tags": tags("internal")}, {"tags": {"owner": true}})
	data.ledger.lib.data_class(rc) == "internal"
}
