# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Sections 3.1/3.2/3.3: Network Configuration"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 25
#     cited: 16
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package cis_ubuntu_20_04.network

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Sections 3.1/3.2/3.3: Network Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in sysctl_violations], [v | some v in ip_forwarding_violations]),
	array.concat([v | some v in ipv6_violations], [v | some v in network_interface_violations]),
)

# Missing evidence must not pass: absent collector sections are violations.
sysctl_violations contains msg if {
	not is_array(object.get(input, ["sysctl_parameters", "analysis"], null))
	msg := "CIS 3.x: evidence missing — sysctl_parameters.analysis not collected"
}

ip_forwarding_violations contains msg if {
	is_null(object.get(input, ["ip_forwarding", "ipv4_forwarding"], null))
	msg := "CIS 3.1.1: evidence missing — ip_forwarding.ipv4_forwarding not collected"
}

network_interface_violations contains msg if {
	not is_object(object.get(input, "wireless_interfaces", null))
	msg := "CIS 3.3.2: evidence missing — wireless_interfaces not collected"
}

network_interface_violations contains msg if {
	not is_object(object.get(input, "firewall", null))
	msg := "CIS 3.5.x: evidence missing — firewall not collected"
}

# CIS 3.x: Kernel sysctl parameters
sysctl_violations contains msg if {
	some param in input.sysctl_parameters.non_compliant_params
	msg := sprintf("CIS 3.x: Kernel parameter '%s' has incorrect value (current: %s, expected: %s) - %s", [param.parameter, param.current_value, param.expected_value, param.description])
}

sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.tcp_syncookies"
	param.current_value != "1"
	msg := "CIS 3.2.8: TCP SYN cookies not enabled (vulnerable to SYN flood attacks)"
}

sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.all.rp_filter"
	param.current_value != "1"
	msg := "CIS 3.2.7: Reverse path filtering not enabled (vulnerable to IP spoofing)"
}

sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.all.log_martians"
	param.current_value != "1"
	msg := "CIS 3.2.4: Martian packet logging not enabled (won't detect spoofing attempts)"
}

sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.icmp_echo_ignore_broadcasts"
	param.current_value != "1"
	msg := "CIS 3.2.5: Broadcast ICMP not ignored (vulnerable to Smurf attacks)"
}

# CIS 3.1.1: IP forwarding disabled
ip_forwarding_violations contains msg if {
	is_number(input.ip_forwarding.ipv4_forwarding)
	input.ip_forwarding.ipv4_forwarding != 0
	not input.ip_forwarding.ipv4_compliant == true
	msg := sprintf("CIS 3.1.1: IPv4 forwarding is enabled (value: %v, expected: 0)", [input.ip_forwarding.ipv4_forwarding])
}

ip_forwarding_violations contains msg if {
	is_number(input.ip_forwarding.ipv6_forwarding)
	input.ip_forwarding.ipv6_forwarding != 0
	not input.ip_forwarding.ipv6_compliant == true
	msg := sprintf("CIS 3.1.1: IPv6 forwarding is enabled (value: %v, expected: 0)", [input.ip_forwarding.ipv6_forwarding])
}

# CIS 3.1.2: Packet redirect sending disabled
sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.all.send_redirects"
	param.current_value != "0"
	msg := "CIS 3.1.2: Sending ICMP redirects is enabled (man-in-the-middle risk)"
}

sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.default.send_redirects"
	param.current_value != "0"
	msg := "CIS 3.1.2: Sending ICMP redirects enabled on default interface"
}

# CIS 3.2.1: Source routed packets rejected
sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	startswith(param.parameter, "net.ipv4.conf.")
	endswith(param.parameter, ".accept_source_route")
	param.current_value != "0"
	msg := sprintf("CIS 3.2.1: Source routed packets accepted on %s (firewall bypass risk)", [param.parameter])
}

# CIS 3.2.2: ICMP redirects not accepted
sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "accept_redirects")
	param.current_value != "0"
	msg := sprintf("CIS 3.2.2: ICMP redirects accepted on %s (man-in-the-middle risk)", [param.parameter])
}

# CIS 3.2.3: Secure ICMP redirects not accepted
sysctl_violations contains msg if {
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "secure_redirects")
	param.current_value != "0"
	msg := sprintf("CIS 3.2.3: Secure ICMP redirects accepted on %s", [param.parameter])
}

# CIS 3.3.1: IPv6 disabled if required
ipv6_violations contains msg if {
	input.require_ipv6_disabled == true
	input.ipv6.disabled == false
	is_number(input.ipv6.address_count)
	input.ipv6.address_count > 0
	msg := sprintf("CIS 3.3.1: IPv6 is enabled but should be disabled (status: %s, addresses: %d)", [input.ipv6.status, input.ipv6.address_count])
}

ipv6_violations contains msg if {
	input.require_ipv6_disabled == true
	input.ipv6.disabled == false
	not is_number(object.get(input, ["ipv6", "address_count"], 0))
	msg := "CIS 3.3.1: evidence missing — ipv6.address_count is not a number"
}

ipv6_violations contains msg if {
	input.require_ipv6_disabled == true
	input.ipv6.disabled == false
	number_missing(["ipv6", "address_count"])
	msg := "CIS 3.3.1: evidence missing — ipv6.address_count not collected"
}

# CIS 3.2.9: IPv6 router advertisements disabled
ipv6_violations contains msg if {
	not input.ipv6.disabled == true
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "ipv6.conf.")
	contains(param.parameter, ".accept_ra")
	param.current_value != "0"
	msg := sprintf("CIS 3.2.9: IPv6 router advertisements accepted on %s (rogue router risk)", [param.parameter])
}

# CIS 3.3.2: Wireless interfaces on servers
network_interface_violations contains msg if {
	input.wireless_interfaces.has_wireless == true
	some iface in input.wireless_interfaces.interfaces
	msg := sprintf("CIS 3.3.2: Wireless interface detected on server: %s", [iface])
}

network_interface_violations contains msg if {
	input.wireless_interfaces.compliant == false
	msg := sprintf("CIS 3.3.2: %v wireless interfaces found on server (should have 0)", [object.get(input, ["wireless_interfaces", "count"], "unknown number of")])
}

# CIS 3.5.x: Firewall (Ubuntu uses ufw or nftables)
network_interface_violations contains msg if {
	input.firewall.active == false
	msg := sprintf("CIS 3.5.x: No active firewall detected (type: %s)", [object.get(input, ["firewall", "type"], "unknown")])
}

network_interface_violations contains msg if {
	input.firewall.type == "iptables"
	input.firewall.type != "ufw"
	input.firewall.type != "nftables"
	msg := "CIS 3.5.x: Using legacy iptables instead of ufw or nftables"
}

# UFW-specific: default deny incoming
network_interface_violations contains msg if {
	input.firewall.type == "ufw"
	input.firewall.default_incoming != "deny"
	input.firewall.default_incoming != "reject"
	msg := sprintf("CIS 3.5.1.1: UFW default incoming policy is '%s', should be deny or reject", [input.firewall.default_incoming])
}

# Risk assessment
risk_level := "critical" if {
	input.ip_forwarding.ipv4_forwarding != 0
} else := "critical" if {
	not input.firewall.active == true
} else := "high" if {
	is_number(input.sysctl_parameters.non_compliant_count)
	input.sysctl_parameters.non_compliant_count > 5
} else := "medium" if {
	input.wireless_interfaces.has_wireless == true
} else := "low"

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# a number that must be collected: missing and null are "not collected" (a wrong type is reported by the rule that reads it)
number_missing(path) if is_null(object.get(input, path, null))

# yes/no facts read unconditionally. require_ipv6_disabled is the site's switch for 3.3.1 and must say
# so either way; ipv6.disabled decides whether the IPv6 checks apply, so it must be an answer too.
required_flags_ipv6 := [
	["CIS 3.3.1", ["require_ipv6_disabled"]],
	["CIS 3.3.1", ["ipv6", "disabled"]],
]

ipv6_violations contains msg if {
	some [prefix, path] in required_flags_ipv6
	msg := flag_evidence(prefix, path)
}

# (a section that was not collected at all is reported once, by the rules at the top)
required_flags_interfaces := [
	["CIS 3.3.2", ["wireless_interfaces", "has_wireless"]],
	["CIS 3.3.2", ["wireless_interfaces", "compliant"]],
	["CIS 3.5.x", ["firewall", "active"]],
]

network_interface_violations contains msg if {
	some [prefix, path] in required_flags_interfaces
	is_object(input[path[0]])
	msg := flag_evidence(prefix, path)
}

# forwarding values are numbers (0 or 1); the collector's own verdict is optional, but a boolean when sent
ip_forwarding_violations contains msg if {
	some key in ["ipv4_forwarding", "ipv6_forwarding"]
	v := object.get(input, ["ip_forwarding", key], null)
	not is_null(v)
	not is_number(v)
	msg := sprintf("CIS 3.1.1: evidence missing — ip_forwarding.%s is not a number (got %s)", [key, type_name(v)])
}

ip_forwarding_violations contains msg if {
	some key in ["ipv4_compliant", "ipv6_compliant"]
	v := object.get(input, ["ip_forwarding", key], null)
	not is_null(v)
	not is_boolean(v)
	msg := sprintf("CIS 3.1.1: evidence missing — ip_forwarding.%s is not a boolean (got %s)", [key, type_name(v)])
}

# the IPv6 forwarding value may be left out (the key absent, not null) only on a host that states IPv6 is disabled
ipv6_forwarding_exempt if {
	input.ipv6.disabled == true
	not "ipv6_forwarding" in object.keys(object.get(input, "ip_forwarding", {}))
}

ip_forwarding_violations contains msg if {
	number_missing(["ip_forwarding", "ipv6_forwarding"])
	not ipv6_forwarding_exempt
	msg := "CIS 3.1.1: evidence missing — ip_forwarding.ipv6_forwarding not collected"
}

report := {
	"compliant": compliant,
	"risk_level": risk_level,
	"total_violations": count(violations),
	"violations": violations,
	"sysctl_violations": count(sysctl_violations),
	"ip_forwarding_violations": count(ip_forwarding_violations),
	"ipv6_violations": count(ipv6_violations),
	"network_interface_violations": count(network_interface_violations),
	"firewall": {"type": object.get(input, ["firewall", "type"], null), "active": object.get(input, ["firewall", "active"], null)},
	"section": "3.1-3.3 Network Configuration",
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
