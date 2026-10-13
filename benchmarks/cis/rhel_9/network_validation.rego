# METADATA
# title: "CIS RHEL 9 Sections 3.1.x, 3.2.x, 3.3.x - Network Configuration"
# custom:
#   class: security
#   framework: cis_rhel_9
#   source: cis
#   domains: [linux, rhel]
#   coverage:
#     checks: 19
#     cited: 14
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.3.6
package cis_rhel9.network

# CIS RHEL 9 Sections 3.1.x, 3.2.x, 3.3.x - Network Configuration
# Validates kernel network parameters, IP forwarding, ICMP settings, and IPv6

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat(
		array.concat(
			[v | some v in sysctl_violations],
			[v | some v in ip_forwarding_violations],
		),
		array.concat(
			[v | some v in ipv6_violations],
			[v | some v in network_interface_violations],
		),
	),
	missing_facts_violations,
)

# =============================================================================
# FAIL-CLOSED: REQUIRED FACTS
# =============================================================================
# See filesystem_validation.rego: absent facts must not read as compliant.
required_fact_keys := [
	"sysctl_parameters",
	"ip_forwarding",
	"ipv6",
	"firewall",
	"wireless_interfaces",
]

missing_facts_violations := [msg |
	some key in required_fact_keys
	not input[key]
	msg := sprintf("CIS 3.x: FAIL-CLOSED - network facts '%s' were not supplied; the section cannot be evaluated and is reported non-compliant", [key])
]

# =============================================================================
# CIS 3.1.x, 3.2.x - KERNEL NETWORK PARAMETERS (SYSCTL)
# =============================================================================

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.non_compliant_params
	violation := sprintf("CIS 3.x: Kernel parameter '%s' has incorrect value (current: %s, expected: %s) - %s", [
		param.parameter,
		param.current_value,
		param.expected_value,
		param.description,
	])
}

# Specific high-priority parameter violations
sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.tcp_syncookies"
	param.current_value != "1"
	violation := "CIS 3.2.8: TCP SYN cookies not enabled (vulnerable to SYN flood attacks)"
}

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.all.rp_filter"
	param.current_value != "1"
	violation := "CIS 3.2.7: Reverse path filtering not enabled (vulnerable to IP spoofing)"
}

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.all.log_martians"
	param.current_value != "1"
	violation := "CIS 3.2.4: Martian packet logging not enabled (won't detect spoofing attempts)"
}

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.icmp_echo_ignore_broadcasts"
	param.current_value != "1"
	violation := "CIS 3.2.5: Broadcast ICMP not ignored (vulnerable to Smurf attacks)"
}

# =============================================================================
# CIS 3.1.1 - IP FORWARDING
# =============================================================================

ip_forwarding_violations contains violation if {
	input.ip_forwarding.ipv4_forwarding != 0
	not input.ip_forwarding.ipv4_compliant
	violation := sprintf("CIS 3.1.1: IPv4 forwarding is enabled (value: %v, expected: 0)", [
		input.ip_forwarding.ipv4_forwarding,
	])
}

ip_forwarding_violations contains violation if {
	input.ip_forwarding.ipv6_forwarding != 0
	not input.ip_forwarding.ipv6_compliant
	violation := sprintf("CIS 3.1.1: IPv6 forwarding is enabled (value: %v, expected: 0)", [
		input.ip_forwarding.ipv6_forwarding,
	])
}

# =============================================================================
# CIS 3.1.2 - PACKET REDIRECT SENDING
# =============================================================================

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.all.send_redirects"
	param.current_value != "0"
	violation := "CIS 3.1.2: Sending ICMP redirects is enabled (man-in-the-middle risk)"
}

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	param.parameter == "net.ipv4.conf.default.send_redirects"
	param.current_value != "0"
	violation := "CIS 3.1.2: Sending ICMP redirects is enabled (default interface)"
}

# =============================================================================
# CIS 3.2.1 - SOURCE ROUTED PACKETS
# =============================================================================

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	startswith(param.parameter, "net.ipv4.conf.")
	endswith(param.parameter, ".accept_source_route")
	param.current_value != "0"
	violation := sprintf("CIS 3.2.1: Source routed packets accepted on %s (firewall bypass risk)", [
		param.parameter,
	])
}

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	startswith(param.parameter, "net.ipv6.conf.")
	endswith(param.parameter, ".accept_source_route")
	param.current_value != "0"
	violation := sprintf("CIS 3.2.1: IPv6 source routed packets accepted on %s", [
		param.parameter,
	])
}

# =============================================================================
# CIS 3.2.2 - ICMP REDIRECTS
# =============================================================================

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "accept_redirects")
	param.current_value != "0"
	violation := sprintf("CIS 3.2.2: ICMP redirects accepted on %s (man-in-the-middle risk)", [
		param.parameter,
	])
}

# =============================================================================
# CIS 3.2.3 - SECURE ICMP REDIRECTS
# =============================================================================

sysctl_violations contains violation if {
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "secure_redirects")
	param.current_value != "0"
	violation := sprintf("CIS 3.2.3: Secure ICMP redirects accepted on %s", [
		param.parameter,
	])
}

# =============================================================================
# CIS 3.3.x - IPv6 CONFIGURATION
# =============================================================================

ipv6_violations contains violation if {
	# Only flag if IPv6 should be disabled but isn't
	input.require_ipv6_disabled == true
	not input.ipv6.disabled
	input.ipv6.address_count > 0
	violation := sprintf("CIS 3.3.1: IPv6 is enabled but should be disabled (status: %s, addresses: %d)", [
		input.ipv6.status,
		input.ipv6.address_count,
	])
}

# If IPv6 is enabled, ensure router advertisements are disabled
ipv6_violations contains violation if {
	not input.ipv6.disabled
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "ipv6.conf.")
	contains(param.parameter, ".accept_ra")
	param.current_value != "0"
	violation := sprintf("CIS 3.2.9: IPv6 router advertisements accepted on %s (rogue router risk)", [
		param.parameter,
	])
}

# =============================================================================
# WIRELESS INTERFACES (SHOULD NOT EXIST ON SERVERS)
# =============================================================================

network_interface_violations contains violation if {
	input.wireless_interfaces.has_wireless
	some iface in input.wireless_interfaces.interfaces
	violation := sprintf("CIS 3.3.2: Wireless interface detected on server: %s", [iface])
}

network_interface_violations contains violation if {
	not input.wireless_interfaces.compliant
	violation := sprintf("CIS 3.3.2: %d wireless interfaces found on server (should have 0)", [
		input.wireless_interfaces.count,
	])
}

# =============================================================================
# FIREWALL STATUS
# =============================================================================

network_interface_violations contains violation if {
	not input.firewall.active
	violation := sprintf("CIS 3.5.x: No active firewall detected (type: %s)", [
		input.firewall.type,
	])
}

network_interface_violations contains violation if {
	input.firewall.type == "iptables"
	violation := "CIS 3.5.x: Using legacy iptables instead of firewalld or nftables"
}

# =============================================================================
# COMPLIANCE CHECKS
# =============================================================================

compliance_summary := {
	"all_sysctl_compliant": object.get(input, ["compliance_checks", "all_sysctl_compliant"], null),
	"ip_forwarding_disabled": object.get(input, ["compliance_checks", "ip_forwarding_disabled"], null),
	"ipv6_compliant": object.get(input, ["compliance_checks", "ipv6_compliant"], null),
	"no_wireless_interfaces": object.get(input, ["compliance_checks", "no_wireless_interfaces"], null),
	"firewall_active": object.get(input, ["compliance_checks", "firewall_active"], null),
	"overall_compliant": count(violations) == 0,
}

# =============================================================================
# DETAILED REPORTING
# =============================================================================

# Non-compliant sysctl parameters grouped by severity
critical_sysctl_issues contains param if {
	some p in input.sysctl_parameters.non_compliant_params
	p.severity == "high"
	p.parameter in [
		"net.ipv4.tcp_syncookies",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.ip_forward",
		"net.ipv6.conf.all.forwarding",
	]
	param := {
		"parameter": p.parameter,
		"current_value": p.current_value,
		"expected_value": p.expected_value,
		"description": p.description,
	}
}

# IP forwarding status
ip_forwarding_status := {
	"ipv4_forwarding": object.get(input, ["ip_forwarding", "ipv4_forwarding"], null),
	"ipv6_forwarding": object.get(input, ["ip_forwarding", "ipv6_forwarding"], null),
	"ipv4_compliant": object.get(input, ["ip_forwarding", "ipv4_compliant"], null),
	"ipv6_compliant": object.get(input, ["ip_forwarding", "ipv6_compliant"], null),
	"fully_compliant": object.get(input, ["ip_forwarding", "fully_compliant"], null),
}

# IPv6 status
ipv6_status := {
	"status": object.get(input, ["ipv6", "status"], null),
	"disabled": object.get(input, ["ipv6", "disabled"], null),
	"address_count": object.get(input, ["ipv6", "address_count"], null),
	"compliant": object.get(input, ["ipv6", "compliant"], null),
}

# Network interface summary
interface_summary := {
	"total_interfaces": object.get(input, ["network_interfaces", "interface_count"], null),
	"wireless_interfaces": object.get(input, ["wireless_interfaces", "count"], null),
	"has_wireless": object.get(input, ["wireless_interfaces", "has_wireless"], null),
}

# Firewall status
firewall_status := {
	"type": object.get(input, ["firewall", "type"], null),
	"active": object.get(input, ["firewall", "active"], null),
	"compliant": object.get(input, ["firewall", "compliant"], null),
}

# Sysctl parameter summary
sysctl_summary := {
	"total_parameters_checked": count(object.get(input, ["sysctl_parameters", "expected_parameters"], [])),
	"compliant_count": object.get(input, ["sysctl_parameters", "compliant_count"], null),
	"non_compliant_count": object.get(input, ["sysctl_parameters", "non_compliant_count"], null),
	"all_compliant": object.get(input, ["sysctl_parameters", "all_compliant"], null),
}

# Risk assessment based on violations
risk_level := "critical" if {
	input.ip_forwarding.ipv4_forwarding != 0
} else := "critical" if {
	not input.firewall.active
} else := "high" if {
	input.sysctl_parameters.non_compliant_count > 5
} else := "high" if {
	some p in input.sysctl_parameters.non_compliant_params
	p.parameter == "net.ipv4.tcp_syncookies"
} else := "medium" if {
	input.wireless_interfaces.has_wireless
} else := "low"

report := {
	"compliant": compliant,
	"risk_level": risk_level,
	"total_violations": count(violations),
	"violations": violations,
	"compliance_summary": compliance_summary,
	"critical_sysctl_issues": critical_sysctl_issues,
	"ip_forwarding_status": ip_forwarding_status,
	"ipv6_status": ipv6_status,
	"interface_summary": interface_summary,
	"firewall_status": firewall_status,
	"sysctl_summary": sysctl_summary,
	"collection_timestamp": object.get(input, ["collection_timestamp"], null),
}

