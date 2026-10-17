package cis_rhel8.network_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

params := [
	{"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.rp_filter", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.log_martians", "current_value": "1"},
	{"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.send_redirects", "current_value": "0"},
	{"parameter": "net.ipv4.conf.default.send_redirects", "current_value": "0"},
]

good := {
	"sysctl_parameters": {"analysis": params, "non_compliant_params": [], "non_compliant_count": 0},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0},
	"firewall": {"type": "firewalld", "active": true},
	"wireless_interfaces": {"has_wireless": false, "count": 0, "compliant": true, "interfaces": []},
}

test_network_fully_evidenced_is_compliant if {
	data.cis_rhel8.network.compliant with input as good
}

test_network_empty_analysis_is_not_compliant if {
	i := object.union(json.remove(good, ["sysctl_parameters"]), {"sysctl_parameters": {"analysis": []}})
	not data.cis_rhel8.network.compliant with input as i
}

test_network_missing_syncookies_is_violation if {
	i := object.union(json.remove(good, ["sysctl_parameters"]), {"sysctl_parameters": {"analysis": [p | some p in params; p.parameter != "net.ipv4.tcp_syncookies"]}})
	v := data.cis_rhel8.network.sysctl_violations with input as i
	"CIS 3.2.8: evidence missing — sysctl net.ipv4.tcp_syncookies not collected" in v
}

test_network_missing_ip_forwarding_is_violation if {
	not data.cis_rhel8.network.compliant with input as json.remove(good, ["ip_forwarding"])
}

test_network_inactive_firewall_without_type_still_reported if {
	i := object.union(json.remove(good, ["firewall"]), {"firewall": {"active": false}})
	v := data.cis_rhel8.network.network_interface_violations with input as i
	"CIS 3.5.1.1: No active firewall detected (type: unknown)" in v
}
