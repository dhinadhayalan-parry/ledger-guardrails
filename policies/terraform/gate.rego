# METADATA
# title: Policy gate
# description: >-
#   Collects findings from every ledger.terraform.* package and turns them into
#   conftest `deny` (blocking) or `warn` (reporting) results, according to the
#   control's mode for the current environment in controls/catalog.yaml.
#
#   Required data (passed with conftest --data):
#     controls    controls/catalog.yaml
#     ledger_env  config/envs/<env>.yaml
package main

import rego.v1

default environment := "prod"

# Fail safe: an unset or unknown environment is treated as production.
environment := data.ledger_env if data.ledger_env in {"sandbox", "prod"}

findings contains f if {
	some pkg
	some f in data.ledger.terraform[pkg].findings
}

# A control that is missing from the catalog, or has no mode for this
# environment, is enforced. Traceability CI prevents this, but the gate must
# never fail open.
default mode(_) := "enforce"

mode(control) := data.controls[control].mode[environment]

message(f) := sprintf("[%s] %s: %s", [f.control, f.resource, f.msg])

deny contains message(f) if {
	some f in findings
	mode(f.control) != "warn"
}

warn contains message(f) if {
	some f in findings
	mode(f.control) == "warn"
}
