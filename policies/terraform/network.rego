# METADATA
# title: No internet-exposed management ports
# description: >-
#   Inbound allow rules from the internet must not cover SSH (22) or RDP (3389).
#   Covers standalone azurerm_network_security_rule resources and rules defined
#   inline on azurerm_network_security_group.
# custom:
#   controls: [LG-NET-01]
package ledger.terraform.network

import rego.v1

import data.ledger.lib

management_ports := {22, 3389}

internet_sources := {"*", "0.0.0.0/0", "internet", "any"}

tcp_protocols := {"tcp", "*"}

# Standalone rules.
findings contains lib.finding("LG-NET-01", rc, msg) if {
	some rc in lib.changes({"azurerm_network_security_rule"})
	some port in exposed_ports(rc.change.after)
	msg := sprintf("rule %q allows port %d from the internet", [rc.change.after.name, port])
}

# Inline rules on a network security group.
findings contains lib.finding("LG-NET-01", rc, msg) if {
	some rc in lib.changes({"azurerm_network_security_group"})
	some rule in rc.change.after.security_rule
	some port in exposed_ports(rule)
	msg := sprintf("inline rule %q allows port %d from the internet", [rule.name, port])
}

exposed_ports(rule) := {port |
	lower(rule.direction) == "inbound"
	lower(rule.access) == "allow"
	lower(rule.protocol) in tcp_protocols
	from_internet(rule)
	some port in management_ports
	some range in destination_ranges(rule)
	covers(range, port)
}

from_internet(rule) if lower(rule.source_address_prefix) in internet_sources

from_internet(rule) if {
	some prefix in rule.source_address_prefixes
	lower(prefix) in internet_sources
}

destination_ranges(rule) := ranges if {
	single := {r | r := rule.destination_port_range; is_string(r); r != ""}
	multiple := {r | some r in object.get(rule, "destination_port_ranges", [])}
	ranges := single | multiple
}

covers("*", _)

covers(range, port) if to_number(range) == port

covers(range, port) if {
	parts := split(range, "-")
	count(parts) == 2
	to_number(parts[0]) <= port
	port <= to_number(parts[1])
}
