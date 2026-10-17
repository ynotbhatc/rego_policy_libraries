package cis_ubuntu_22_04.network_test

import rego.v1

# Validation fix 2026-10-17: compliant on empty input; "No active firewall" message was undefined
# without firewall.type; numeric sysctl values were false fails.

pkg := data.cis_ubuntu_22_04.network

sysctls := [
	{"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.rp_filter", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.log_martians", "current_value": "1"},
	{"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"},
	{"parameter": "net.ipv4.conf.all.send_redirects", "current_value": "0"},
	{"parameter": "net.ipv4.conf.default.send_redirects", "current_value": "0"},
]

good := {
	"sysctl_parameters": {"analysis": sysctls, "non_compliant_params": [], "non_compliant_count": 0},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0, "ipv4_compliant": true, "ipv6_compliant": true},
	"wireless_interfaces": {"has_wireless": false, "interfaces": [], "count": 0, "compliant": true},
	"firewall": {"type": "ufw", "active": true, "default_incoming": "deny"},
}

test_empty_input_not_compliant if {
	not pkg.compliant with input as {}
}

test_good_compliant if {
	pkg.compliant with input as good
}

test_numeric_sysctl_values_ok if {
	nums := [{"parameter": "net.ipv4.tcp_syncookies", "current_value": 1}, {"parameter": "net.ipv4.conf.all.rp_filter", "current_value": 1}, {"parameter": "net.ipv4.conf.all.log_martians", "current_value": 1}, {"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": 1}, {"parameter": "net.ipv4.conf.all.send_redirects", "current_value": 0}, {"parameter": "net.ipv4.conf.default.send_redirects", "current_value": 0}]
	pkg.compliant with input as object.union(object.remove(good, ["sysctl_parameters"]), {"sysctl_parameters": {"analysis": nums}})
}

test_missing_required_sysctl_violates if {
	partial := [p | some p in sysctls; p.parameter != "net.ipv4.tcp_syncookies"]
	v := pkg.sysctl_violations with input as object.union(object.remove(good, ["sysctl_parameters"]), {"sysctl_parameters": {"analysis": partial}})
	"CIS 3.x: evidence missing — sysctl net.ipv4.tcp_syncookies not collected" in v
}

test_sysctl_without_value_violates if {
	broken := [object.remove(p, ["current_value"]) | some p in sysctls]
	not pkg.compliant with input as object.union(object.remove(good, ["sysctl_parameters"]), {"sysctl_parameters": {"analysis": broken}})
}

test_firewall_without_type_still_violates if {
	inp := object.union(object.remove(good, ["firewall"]), {"firewall": {"active": false}})
	not pkg.compliant with input as inp
	v := pkg.network_interface_violations with input as inp
	"CIS 3.5.x: No active firewall detected (type: unknown)" in v
}

test_firewall_missing_violates if {
	not pkg.compliant with input as object.remove(good, ["firewall"])
}

test_forwarding_missing_violates if {
	not pkg.compliant with input as object.remove(good, ["ip_forwarding"])
}

test_forwarding_enabled_violates if {
	not pkg.compliant with input as object.union(good, {"ip_forwarding": {"ipv4_forwarding": 1, "ipv6_forwarding": 0, "ipv4_compliant": false}})
}

test_wireless_missing_violates if {
	not pkg.compliant with input as object.remove(good, ["wireless_interfaces"])
}
