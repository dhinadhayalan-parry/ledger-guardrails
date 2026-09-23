package ledger.terraform.network_test

import rego.v1

import data.ledger.terraform.network
import data.ledger.testing as t

base_rule := {
	"name": "allow-https",
	"direction": "Inbound",
	"access": "Allow",
	"protocol": "Tcp",
	"source_address_prefix": "Internet",
	"source_address_prefixes": [],
	"destination_port_range": "443",
	"destination_port_ranges": [],
}

rule_findings(rule) := f if {
	f := network.findings with input as t.plan([t.create("azurerm_network_security_rule", rule)])
}

nsg_findings(rules) := f if {
	nsg := t.create("azurerm_network_security_group", {"name": "nsg", "security_rule": rules, "tags": t.tags("internal")})
	f := network.findings with input as t.plan([nsg])
}

test_https_from_internet_is_allowed if {
	count(rule_findings(base_rule)) == 0
}

test_ssh_from_internet if {
	count(rule_findings(t.with_attrs(base_rule, {"destination_port_range": "22"}))) == 1
}

test_rdp_inside_port_range if {
	count(rule_findings(t.with_attrs(base_rule, {"destination_port_range": "3000-4000"}))) == 1
}

test_wildcard_port_exposes_both if {
	count(rule_findings(t.with_attrs(base_rule, {"destination_port_range": "*"}))) == 2
}

test_port_ranges_list if {
	rule := t.with_attrs(base_rule, {"destination_port_range": null, "destination_port_ranges": ["443", "20-23"]})
	count(rule_findings(rule)) == 1
}

test_source_prefixes_list if {
	rule := t.with_attrs(base_rule, {
		"source_address_prefix": null,
		"source_address_prefixes": ["10.0.0.0/8", "0.0.0.0/0"],
		"destination_port_range": "22",
	})
	count(rule_findings(rule)) == 1
}

test_private_source_is_allowed if {
	count(rule_findings(t.with_attrs(base_rule, {"source_address_prefix": "10.20.0.0/16", "destination_port_range": "22"}))) == 0
}

test_deny_rule_is_allowed if {
	count(rule_findings(t.with_attrs(base_rule, {"access": "Deny", "destination_port_range": "*"}))) == 0
}

test_outbound_rule_is_allowed if {
	count(rule_findings(t.with_attrs(base_rule, {"direction": "Outbound", "destination_port_range": "22"}))) == 0
}

test_rdp_over_udp if {
	count(rule_findings(t.with_attrs(base_rule, {"protocol": "Udp", "destination_port_range": "3389"}))) == 1
}

test_icmp_is_not_management if {
	count(rule_findings(t.with_attrs(base_rule, {"protocol": "Icmp", "destination_port_range": "*"}))) == 0
}

test_ssh_from_ipv6_any if {
	count(rule_findings(t.with_attrs(base_rule, {"source_address_prefix": "::/0", "destination_port_range": "22"}))) == 1
}

test_ipv4_any_written_as_zero_prefix_on_other_address if {
	count(rule_findings(t.with_attrs(base_rule, {"source_address_prefix": "1.2.3.4/0", "destination_port_range": "22"}))) == 1
}

test_internet_split_into_two_halves if {
	rule := t.with_attrs(base_rule, {
		"source_address_prefix": null,
		"source_address_prefixes": ["0.0.0.0/1", "128.0.0.0/1"],
		"destination_port_range": "3389",
	})
	count(rule_findings(rule)) == 1
}

test_widest_private_ranges_are_allowed if {
	rule := t.with_attrs(base_rule, {
		"source_address_prefix": null,
		"source_address_prefixes": ["10.0.0.0/8", "fc00::/7", "203.0.113.10/32", "VirtualNetwork"],
		"destination_port_range": "22",
	})
	count(rule_findings(rule)) == 0
}

test_inline_nsg_rule if {
	rules := [base_rule, t.with_attrs(base_rule, {"name": "rdp", "source_address_prefix": "*", "destination_port_range": "3389"})]
	f := nsg_findings(rules)
	count(f) == 1
	some finding in f
	contains(finding.msg, "\"rdp\"")
}
