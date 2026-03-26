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
		[v | some v in sysctl_violations],
		[v | some v in ip_forwarding_violations],
	),
	array.concat(
		[v | some v in ipv6_violations],
		[v | some v in network_interface_violations],
	),
)

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
	"all_sysctl_compliant": input.compliance_checks.all_sysctl_compliant,
	"ip_forwarding_disabled": input.compliance_checks.ip_forwarding_disabled,
	"ipv6_compliant": input.compliance_checks.ipv6_compliant,
	"no_wireless_interfaces": input.compliance_checks.no_wireless_interfaces,
	"firewall_active": input.compliance_checks.firewall_active,
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
	"ipv4_forwarding": input.ip_forwarding.ipv4_forwarding,
	"ipv6_forwarding": input.ip_forwarding.ipv6_forwarding,
	"ipv4_compliant": input.ip_forwarding.ipv4_compliant,
	"ipv6_compliant": input.ip_forwarding.ipv6_compliant,
	"fully_compliant": input.ip_forwarding.fully_compliant,
}

# IPv6 status
ipv6_status := {
	"status": input.ipv6.status,
	"disabled": input.ipv6.disabled,
	"address_count": input.ipv6.address_count,
	"compliant": input.ipv6.compliant,
}

# Network interface summary
interface_summary := {
	"total_interfaces": input.network_interfaces.interface_count,
	"wireless_interfaces": input.wireless_interfaces.count,
	"has_wireless": input.wireless_interfaces.has_wireless,
}

# Firewall status
firewall_status := {
	"type": input.firewall.type,
	"active": input.firewall.active,
	"compliant": input.firewall.compliant,
}

# Sysctl parameter summary
sysctl_summary := {
	"total_parameters_checked": count(input.sysctl_parameters.expected_parameters),
	"compliant_count": input.sysctl_parameters.compliant_count,
	"non_compliant_count": input.sysctl_parameters.non_compliant_count,
	"all_compliant": input.sysctl_parameters.all_compliant,
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
	"collection_timestamp": input.collection_timestamp,
}

