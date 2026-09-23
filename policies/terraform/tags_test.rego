package ledger.terraform.tags_test

import rego.v1

import data.ledger.terraform.tags
import data.ledger.testing as t

findings_for(after) := f if {
	f := tags.findings with input as t.plan([t.create("azurerm_resource_group", after)])
}

test_complete_tags if {
	count(findings_for({"tags": t.tags("internal")})) == 0
}

test_null_tags if {
	f := findings_for({"tags": null})
	count(f) == 1
}

test_missing_owner_and_empty_cost_center if {
	f := findings_for({"tags": {"data-class": "public", "cost-center": ""}})
	count(f) == 1
	some finding in f
	contains(finding.msg, "cost-center")
	contains(finding.msg, "owner")
}

test_unknown_data_class if {
	f := findings_for({"tags": t.tags("secret")})
	count(f) == 1
	some finding in f
	contains(finding.msg, "\"secret\"")
}

test_resource_without_tags_attribute_is_skipped if {
	count(findings_for({"name": "role-assignment"})) == 0
}

test_tag_value_unknown_at_plan_counts_as_present if {
	known := object.remove(t.tags("internal"), {"data-class"})
	rc := t.create_unknown("azurerm_resource_group", {"tags": known}, {"tags": {"data-class": true}})
	count(tags.findings) == 0 with input as t.plan([rc])
}

test_unknown_marks_do_not_hide_missing_tags if {
	rc := t.create_unknown("azurerm_resource_group", {"tags": {"owner": "platform"}}, {"tags": {"data-class": true}})
	f := tags.findings with input as t.plan([rc])
	count(f) == 1
	some finding in f
	contains(finding.msg, "cost-center")
}
