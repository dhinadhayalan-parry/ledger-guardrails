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

data_class(after) := after.tags["data-class"]

is_sensitive(after) if data_class(after) in sensitive_classes

is_payment(after) if data_class(after) == "payment"
