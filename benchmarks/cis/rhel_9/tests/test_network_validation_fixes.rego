package cis_rhel9.network_test

import rego.v1

# Validation fixes 2026-10-17: present-but-empty facts and uncollected sysctl parameters are not evidence.

sysctl(name, val) := {"parameter": name, "current_value": val, "compliant": true}

good := {
	"sysctl_parameters": {"non_compliant_params": [], "analysis": [
		sysctl("net.ipv4.tcp_syncookies", "1"),
		sysctl("net.ipv4.conf.all.rp_filter", "1"),
		sysctl("net.ipv4.conf.all.log_martians", "1"),
		sysctl("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
		sysctl("net.ipv4.conf.all.send_redirects", "0"),
		sysctl("net.ipv4.conf.default.send_redirects", "0"),
		sysctl("net.ipv4.conf.all.accept_source_route", "0"),
		sysctl("net.ipv4.conf.all.accept_redirects", "0"),
		sysctl("net.ipv4.conf.all.secure_redirects", "0"),
	]},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0, "ipv4_compliant": true, "ipv6_compliant": true},
	"ipv6": {"disabled": false, "status": "enabled", "address_count": 1},
	"firewall": {"active": true, "type": "firewalld", "compliant": true},
	"wireless_interfaces": {"has_wireless": false, "count": 0, "compliant": true, "interfaces": []},
}

test_network_good_input_compliant if {
	data.cis_rhel9.network.compliant with input as good
}

test_network_empty_object_facts_not_compliant if {
	i := {"sysctl_parameters": {}, "ip_forwarding": {}, "ipv6": {}, "firewall": {}, "wireless_interfaces": {}}
	not data.cis_rhel9.network.compliant with input as i
}

test_network_each_empty_fact_is_violation if {
	every key in ["sysctl_parameters", "ip_forwarding", "ipv6", "firewall", "wireless_interfaces"] {
		not data.cis_rhel9.network.compliant with input as json.patch(good, [{"op": "replace", "path": concat("", ["/", key]), "value": {}}])
	}
}

test_network_uncollected_sysctl_param_is_violation if {
	every idx in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
		i := json.remove(good, [sprintf("/sysctl_parameters/analysis/%d", [idx])])
		not data.cis_rhel9.network.compliant with input as i
	}
}

test_network_missing_ipv4_forwarding_is_violation if {
	not data.cis_rhel9.network.compliant with input as json.remove(good, ["/ip_forwarding/ipv4_forwarding"])
}

test_network_ipv6_forwarding_not_required_when_ipv6_disabled if {
	i := json.patch(good, [{"op": "replace", "path": "/ipv6/disabled", "value": true}, {"op": "remove", "path": "/ip_forwarding/ipv6_forwarding"}])
	data.cis_rhel9.network.compliant with input as i
}
