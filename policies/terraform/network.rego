# METADATA
# title: No internet-exposed management ports
# description: >-
#   Inbound allow rules from the internet must not cover SSH (22) or RDP (3389),
#   over TCP or UDP (RDP also uses UDP 3389). The internet is the Internet
#   service tag, wildcards, and any IPv4 range wider than /8 or IPv6 range wider
#   than /7: no private range is that wide, so splitting 0.0.0.0/0 into two /1
#   rules does not get through. Covers standalone azurerm_network_security_rule
#   resources and rules defined inline on azurerm_network_security_group.
# custom:
#   controls: [LG-NET-01]
package ledger.terraform.network

import rego.v1

import data.ledger.lib

management_ports := {22, 3389}

internet_tags := {"*", "internet", "any"}

# Narrowest prefix length that still counts as the internet. 10.0.0.0/8 and
# fc00::/7 (unique local) are the widest private ranges.
min_private_prefix := {"ipv4": 8, "ipv6": 7}

management_protocols := {"tcp", "udp", "*"}

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
	lower(rule.protocol) in management_protocols
	from_internet(rule)
	some port in management_ports
	some range in destination_ranges(rule)
	covers(range, port)
}

from_internet(rule) if internet_prefix(rule.source_address_prefix)

from_internet(rule) if {
	some prefix in rule.source_address_prefixes
	internet_prefix(prefix)
}

internet_prefix(prefix) if lower(prefix) in internet_tags

internet_prefix(prefix) if {
	parts := split(prefix, "/")
	count(parts) == 2
	to_number(parts[1]) < min_private_prefix[ip_family(parts[0])]
}

ip_family(address) := "ipv6" if contains(address, ":")

ip_family(address) := "ipv4" if not contains(address, ":")

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
