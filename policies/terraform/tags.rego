# METADATA
# title: Ownership and data classification tags
# description: >-
#   Every taggable resource carries owner, cost-center and data-class tags, and
#   data-class uses the approved vocabulary. A resource is treated as taggable
#   when its planned values contain a `tags` attribute. Tags that are unknown
#   until apply cannot be evaluated here; the Azure Policy layer covers them.
# custom:
#   controls: [LG-GOV-01]
package ledger.terraform.tags

import rego.v1

import data.ledger.lib

required_tags := {"owner", "cost-center", "data-class"}

data_classes := {"public", "internal", "confidential", "payment"}

taggable := {rc |
	some rc in lib.all_changes
	"tags" in object.keys(rc.change.after)
}

present_tags(after) := {k | some k, v in after.tags; is_string(v); v != ""}

findings contains lib.finding("LG-GOV-01", rc, msg) if {
	some rc in taggable
	missing := required_tags - present_tags(rc.change.after)
	count(missing) > 0
	msg := sprintf("missing required tags %v", [sort(missing)])
}

findings contains lib.finding("LG-GOV-01", rc, msg) if {
	some rc in taggable
	class := lib.data_class(rc.change.after)
	not class in data_classes
	msg := sprintf("data-class %q is not one of %v", [class, sort(data_classes)])
}
