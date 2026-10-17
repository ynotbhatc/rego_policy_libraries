package cis_rocky_linux_9.network_test

import rego.v1

good := {
	"sysctl_parameters": {"analysis": [{"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"}], "non_compliant_params": []},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0},
	"wireless_interfaces": {"compliant": true, "has_wireless": false, "count": 0},
	"firewall": {"active": true, "type": "firewalld"},
}

has(prefix, inp) if {
	v := data.cis_rocky_linux_9.network.violations with input as inp
	some x in v
	startswith(x, prefix)
}

test_full_facts_compliant if data.cis_rocky_linux_9.network.compliant with input as good

test_empty_sysctl_object_not_compliant if {
	inp := {
		"sysctl_parameters": {},
		"wireless_interfaces": {"compliant": true},
		"firewall": {"active": true, "type": "firewalld"},
	}
	not data.cis_rocky_linux_9.network.compliant with input as inp
	has("CIS 3.x: evidence missing", inp)
}

test_missing_ip_forwarding_flagged if {
	inp := object.remove(good, ["ip_forwarding"])
	has("CIS 3.1.1: evidence missing — ip_forwarding.ipv4", inp)
	has("CIS 3.1.1: evidence missing — ip_forwarding.ipv6", inp)
	not data.cis_rocky_linux_9.network.compliant with input as inp
}

test_forwarding_enabled_still_flagged if has("CIS 3.1.1: IPv4 forwarding is enabled", object.union(good, {"ip_forwarding": {"ipv4_forwarding": 1}}))
