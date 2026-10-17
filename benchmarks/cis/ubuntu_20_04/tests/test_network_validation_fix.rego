package cis_ubuntu_20_04.network_test

import rego.v1

# Validation fix pass 2026-10-17.

good := {
	"sysctl_parameters": {"analysis": [], "non_compliant_params": [], "non_compliant_count": 0},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0},
	"wireless_interfaces": {"has_wireless": false, "compliant": true, "count": 0, "interfaces": []},
	"firewall": {"active": true, "type": "ufw", "default_incoming": "deny"},
}

test_good_input_compliant if {
	data.cis_ubuntu_20_04.network.compliant with input as good
}

test_empty_input_not_compliant if {
	not data.cis_ubuntu_20_04.network.compliant with input as {}
	r := data.cis_ubuntu_20_04.network.report with input as {}
	r.total_violations == 5
}

test_inactive_firewall_without_type_flagged if {
	inp := object.union(object.remove(good, ["firewall"]), {"firewall": {"active": false}})
	some m in data.cis_ubuntu_20_04.network.violations with input as inp
	startswith(m, "CIS 3.5.x: No active firewall")
}

test_wireless_non_compliant_without_count_flagged if {
	inp := object.union(object.remove(good, ["wireless_interfaces"]), {"wireless_interfaces": {"compliant": false}})
	not data.cis_ubuntu_20_04.network.compliant with input as inp
}

test_each_missing_section_not_compliant if {
	every sec in ["sysctl_parameters", "ip_forwarding", "wireless_interfaces", "firewall"] {
		not data.cis_ubuntu_20_04.network.compliant with input as json.remove(good, [sec])
	}
}
