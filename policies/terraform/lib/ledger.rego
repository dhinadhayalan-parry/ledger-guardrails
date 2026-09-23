# METADATA
# title: Shared helpers for Terraform plan policies
# description: >-
#   Helpers that operate on the JSON produced by `terraform show -json <planfile>`.
#   Policies only evaluate resources that are being created or updated, so a PR
#   that deletes a non-compliant resource is never blocked by it.
package ledger.lib

import rego.v1

# Managed resource changes of the given types that create or update a resource.
# Replacements ("delete" + "create") are included because the new resource is
# created from the planned configuration.
changes(types) := {rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type in types
	creates_or_updates(rc)
}

# All managed resource changes that create or update a resource.
all_changes := {rc |
	some rc in input.resource_changes
	rc.mode == "managed"
	creates_or_updates(rc)
}

creates_or_updates(rc) if {
	some action in rc.change.actions
	action in {"create", "update"}
}

# A finding is the unit every policy emits. The gate in package main decides
# whether it blocks (enforce) or only reports (warn) based on the catalog.
finding(control, rc, msg) := {
	"control": control,
	"resource": rc.address,
	"msg": msg,
}

# First element of a nested block. Terraform renders nested blocks as lists in
# plan JSON, even when the provider schema allows at most one.
block(after, name) := after[name][0]

has_block(after, name) if block(after, name)

# True when attribute `attr` of nested block `name` equals `value`. Use this
# inside `not` rather than `not block(...)[attr] == value`: OPA hoists the
# function call out of the negation, so the negated form is undefined (and never
# fires) when the block is missing.
nested_is(after, name, attr, value) if block(after, name)[attr] == value

# Data classes that require customer-managed keys and stricter handling.
sensitive_classes := {"confidential", "payment"}

# The strictest class, assumed when the real class is unknown at plan time.
strictest_class := "payment"

# Planned data class of a resource change. A data-class tag whose value is only
# known after apply (for example built from another resource's attribute) is
# treated as the strictest class, so a computed tag cannot switch the data
# controls off. A fully hardened resource still passes.
data_class(rc) := strictest_class if class_unknown(rc)

data_class(rc) := rc.change.after.tags["data-class"] if not class_unknown(rc)

# Terraform marks unknown values in `after_unknown`: `tags: true` when the whole
# map is unknown, `tags: {"data-class": true}` when only that element is.
class_unknown(rc) if rc.change.after_unknown.tags == true

class_unknown(rc) if rc.change.after_unknown.tags["data-class"] == true

is_sensitive(rc) if data_class(rc) in sensitive_classes

is_payment(rc) if data_class(rc) == strictest_class
