package cis_ubuntu_24_04.network_test

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
	"firewall": {"type": "ufw", "active": true, "default_incoming": "deny"},
	"wireless_interfaces": {"has_wireless": false, "count": 0, "compliant": true, "interfaces": []},
}

test_network_fully_evidenced_is_compliant if {
	data.cis_ubuntu_24_04.network.compliant with input as good
}

test_network_empty_input_is_not_compliant if {
	not data.cis_ubuntu_24_04.network.compliant with input as {}
}

test_network_inactive_firewall_without_type_is_violation if {
	i := object.union(json.remove(good, ["firewall"]), {"firewall": {"active": false}})
	v := data.cis_ubuntu_24_04.network.network_interface_violations with input as i
	"CIS 3.5.x: No active firewall detected (type: unknown)" in v
	not data.cis_ubuntu_24_04.network.compliant with input as i
}

test_network_ipv6_enabled_without_status_is_violation if {
	i := object.union(good, {"require_ipv6_disabled": true, "ipv6": {"disabled": false, "address_count": 2}})
	v := data.cis_ubuntu_24_04.network.ipv6_violations with input as i
	count(v) >= 1
}

test_network_forwarding_value_beats_compliant_flag if {
	i := object.union(good, {"ip_forwarding": {"ipv4_forwarding": 1, "ipv4_compliant": true}})
	not data.cis_ubuntu_24_04.network.compliant with input as i
	v := data.cis_ubuntu_24_04.network.ip_forwarding_violations with input as i
	"CIS 3.1.1: IPv4 forwarding is enabled (value: 1, expected: 0)" in v
}

test_network_missing_ip_forwarding_is_violation if {
	not data.cis_ubuntu_24_04.network.compliant with input as json.remove(good, ["ip_forwarding"])
}

test_network_missing_sysctl_is_violation if {
	i := object.union(json.remove(good, ["sysctl_parameters"]), {"sysctl_parameters": {"analysis": [p | some p in params; p.parameter != "net.ipv4.tcp_syncookies"]}})
	"CIS 3.2.8: evidence missing — sysctl net.ipv4.tcp_syncookies not collected" in data.cis_ubuntu_24_04.network.sysctl_violations with input as i
}

test_network_ufw_without_default_incoming_is_violation if {
	i := object.union(json.remove(good, ["firewall"]), {"firewall": {"type": "ufw", "active": true}})
	not data.cis_ubuntu_24_04.network.compliant with input as i
}
