# METADATA
# title: Ownership and data classification tags
# description: >-
#   Every taggable resource carries owner, cost-center and data-class tags, and
#   data-class uses the approved vocabulary. A resource is treated as taggable
#   when its planned values contain a `tags` attribute. A tag whose value is
#   only known after apply counts as present; if it is data-class, the data
#   controls assume the strictest class (lib.data_class). A tag map that is
#   entirely unknown cannot be checked here; the Azure Policy layer covers it.
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

present_tags(rc) := known | unknown if {
	known := {k | some k, v in rc.change.after.tags; is_string(v); v != ""}
	unknown := {k |
		marks := object.get(rc.change, ["after_unknown", "tags"], {})
		is_object(marks)
		some k, v in marks
		v == true
	}
}

findings contains lib.finding("LG-GOV-01", rc, msg) if {
	some rc in taggable
	missing := required_tags - present_tags(rc)
	count(missing) > 0
	msg := sprintf("missing required tags %v", [sort(missing)])
}

findings contains lib.finding("LG-GOV-01", rc, msg) if {
	some rc in taggable
	class := lib.data_class(rc)
	not class in data_classes
	msg := sprintf("data-class %q is not one of %v", [class, sort(data_classes)])
}
