package cis_rocky_linux_8.network_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

params := [
	{"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.rp_filter", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.log_martians", "current_value": "1"},
	{"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.send_redirects", "current_value": "0"},
	{"parameter": "net.ipv4.conf.default.send_redirects", "current_value": "0"},
]

test_network_forwarding_not_hidden_by_compliant_flag if {
	i := {"ip_forwarding": {"ipv4_forwarding": 1, "ipv4_compliant": true, "ipv6_forwarding": 0}}
	v := data.cis_rocky_linux_8.network.ip_forwarding_violations with input as i
	count([m | some m in v; contains(m, "IPv4 forwarding is enabled")]) == 1
}

test_network_ipv6_forwarding_not_hidden_by_compliant_flag if {
	i := {"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 1, "ipv6_compliant": true}}
	v := data.cis_rocky_linux_8.network.ip_forwarding_violations with input as i
	count([m | some m in v; contains(m, "IPv6 forwarding is enabled")]) == 1
}

test_network_forwarding_zero_ok if {
	v := data.cis_rocky_linux_8.network.ip_forwarding_violations with input as {"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0}}
	count(v) == 0
}

test_network_forwarding_missing_flagged if {
	v := data.cis_rocky_linux_8.network.ip_forwarding_violations with input as {}
	count(v) == 2
}

test_network_missing_syncookies_flagged if {
	i := {"sysctl_parameters": {"analysis": [p | some p in params; p.parameter != "net.ipv4.tcp_syncookies"]}}
	v := data.cis_rocky_linux_8.network.sysctl_violations with input as i
	count(v) == 1
	some m in v
	startswith(m, "CIS 3.2.8: evidence missing")
}

test_network_all_params_present_ok if {
	v := data.cis_rocky_linux_8.network.sysctl_violations with input as {"sysctl_parameters": {"analysis": params}}
	count(v) == 0
}
