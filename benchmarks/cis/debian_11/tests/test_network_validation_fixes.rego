package cis_debian_11.network_test

import rego.v1

good := {
	"sysctl_parameters": {"analysis": [{"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"}], "non_compliant_params": [], "non_compliant_count": 0},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0, "ipv4_compliant": true, "ipv6_compliant": true},
	"ipv6": {"disabled": true, "address_count": 0, "status": "disabled"},
	"wireless_interfaces": {"has_wireless": false, "interfaces": [], "compliant": true, "count": 0},
	"firewall": {"type": "ufw", "active": true, "default_incoming": "deny"},
}

test_good_compliant if {
	data.cis_debian_11.network.compliant with input as good
}

test_empty_input_not_compliant if {
	not data.cis_debian_11.network.compliant with input as {}
	count(data.cis_debian_11.network.violations) >= 4 with input as {}
}

test_each_missing_section_violates if {
	some k in ["sysctl_parameters", "ip_forwarding", "ipv6", "wireless_interfaces", "firewall"]
	not data.cis_debian_11.network.compliant with input as object.remove(good, [k])
}

test_inactive_firewall_without_type_violates if {
	i := object.union(object.remove(good, ["firewall"]), {"firewall": {"active": false}})
	some m in data.cis_debian_11.network.network_interface_violations with input as i
	contains(m, "No active firewall detected")
}

test_ipv6_enabled_without_status_violates if {
	i := object.union(object.remove(good, ["ipv6"]), {"require_ipv6_disabled": true, "ipv6": {"disabled": false, "address_count": 2}})
	some m in data.cis_debian_11.network.ipv6_violations with input as i
	contains(m, "IPv6 is enabled")
}

test_wireless_noncompliant_without_count_violates if {
	i := object.union(object.remove(good, ["wireless_interfaces"]), {"wireless_interfaces": {"has_wireless": false, "compliant": false}})
	some m in data.cis_debian_11.network.network_interface_violations with input as i
	contains(m, "wireless interfaces found")
}
