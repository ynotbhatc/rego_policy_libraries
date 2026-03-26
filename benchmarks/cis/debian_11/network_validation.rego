package cis_debian_11.network

# CIS Debian Linux 11 Benchmark v1.0.0 - Sections 3.1/3.2/3.3: Network Configuration

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in sysctl_violations], [v | some v in ip_forwarding_violations]),
	array.concat([v | some v in ipv6_violations], [v | some v in network_interface_violations]),
)

# CIS 3.x: Kernel sysctl parameters
sysctl_violations contains msg if {
	some param in input.sysctl_parameters.non_compliant_params
	msg := sprintf("CIS 3.x: Kernel parameter '%s' has incorrect value (current: %s, expected: %s) - %s", [
		param.parameter, param.current_value, param.expected_value, param.description,
	])
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
	input.ip_forwarding.ipv4_forwarding != 0
	not input.ip_forwarding.ipv4_compliant
	msg := sprintf("CIS 3.1.1: IPv4 forwarding is enabled (value: %v, expected: 0)", [input.ip_forwarding.ipv4_forwarding])
}

ip_forwarding_violations contains msg if {
	input.ip_forwarding.ipv6_forwarding != 0
	not input.ip_forwarding.ipv6_compliant
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
	not input.ipv6.disabled
	input.ipv6.address_count > 0
	msg := sprintf("CIS 3.3.1: IPv6 is enabled but should be disabled (status: %s, addresses: %d)", [input.ipv6.status, input.ipv6.address_count])
}

# CIS 3.2.9: IPv6 router advertisements disabled
ipv6_violations contains msg if {
	not input.ipv6.disabled
	some param in input.sysctl_parameters.analysis
	contains(param.parameter, "ipv6.conf.")
	contains(param.parameter, ".accept_ra")
	param.current_value != "0"
	msg := sprintf("CIS 3.2.9: IPv6 router advertisements accepted on %s (rogue router risk)", [param.parameter])
}

# CIS 3.3.2: Wireless interfaces on servers
network_interface_violations contains msg if {
	input.wireless_interfaces.has_wireless
	some iface in input.wireless_interfaces.interfaces
	msg := sprintf("CIS 3.3.2: Wireless interface detected on server: %s", [iface])
}

network_interface_violations contains msg if {
	not input.wireless_interfaces.compliant
	msg := sprintf("CIS 3.3.2: %d wireless interfaces found on server (should have 0)", [input.wireless_interfaces.count])
}

# CIS 3.5.x: Firewall (Ubuntu uses ufw or nftables)
network_interface_violations contains msg if {
	not input.firewall.active
	msg := sprintf("CIS 3.5.x: No active firewall detected (type: %s)", [input.firewall.type])
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
	not input.firewall.active
} else := "high" if {
	input.sysctl_parameters.non_compliant_count > 5
} else := "medium" if {
	input.wireless_interfaces.has_wireless
} else := "low"

report := {
	"compliant": compliant,
	"risk_level": risk_level,
	"total_violations": count(violations),
	"violations": violations,
	"sysctl_violations": count(sysctl_violations),
	"ip_forwarding_violations": count(ip_forwarding_violations),
	"ipv6_violations": count(ipv6_violations),
	"network_interface_violations": count(network_interface_violations),
	"firewall": {"type": input.firewall.type, "active": input.firewall.active},
	"section": "3.1-3.3 Network Configuration",
	"benchmark": "CIS Debian 11 v1.0.0",
}
