# METADATA
# title: Policy gate
# description: >-
#   Collects findings from every ledger.terraform.* package and turns them into
#   conftest `deny` (blocking) or `warn` (reporting) results, according to the
#   control's mode for the current environment in controls/catalog.yaml.
#
#   A blocking finding is downgraded to a warning only by an active exemption
#   in config/exemptions.yaml for the same control, resource and environment,
#   and only for controls the catalog marks `exemptible: true`. The exemption
#   stays visible in the output. An exemption that is expired, malformed, or
#   for a non-exemptible control is ignored, so the gate never fails open.
#
#   Required data (passed with conftest --data):
#     controls    controls/catalog.yaml
#     ledger_env  config/envs/<env>.yaml
#     exemptions  config/exemptions.yaml
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
	not exempted(f)
}

warn contains message(f) if {
	some f in findings
	mode(f.control) == "warn"
}

warn contains sprintf("%s (exempted until %s: %s)", [message(f), e.expires_on, e.ticket]) if {
	some f in findings
	mode(f.control) != "warn"
	some e in exemptions_for(f)
}

exempted(f) if count(exemptions_for(f)) > 0

exemptions_for(f) := {e |
	some e in data.exemptions
	data.controls[f.control].exemptible == true
	e.control == f.control
	e.resource == f.resource
	e.env == environment
	is_string(e.ticket)
	active(e)
}

# Valid through the end of the expiry day (UTC). A date that does not parse
# leaves the exemption inactive.
active(e) if {
	expires_ns := time.parse_rfc3339_ns(sprintf("%sT23:59:59Z", [e.expires_on]))
	time.now_ns() <= expires_ns
}
