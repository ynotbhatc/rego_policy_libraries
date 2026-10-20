package cis_rhel9.network_test

import rego.v1

# Validation fixes 2026-10-17: present-but-empty facts and uncollected sysctl parameters are not evidence.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 3.x -> v3 3.x / 4.1.x. Each sysctl needs its running value (sysctl_parameters.analysis) AND its
# persisted value (sysctl_parameters.persisted); ip_forwarding.* is no longer read (net.ipv4.ip_forward is).

good := {"attest": {"ipv6_status_identified": true, "firewalld_loopback_traffic_configured": true, "firewalld_loopback_source_traffic_configured": true, "firewalld_services_ports_reviewed": true, "firewalld_default_zone_drop": true}, "wireless_interfaces": {"has_wireless": true, "modules": [{"module": "iwlwifi", "disabled": true, "loaded": false}]}, "packages": {"bluez": false, "firewalld": true, "iptables-services": false, "ufw": false}, "disabled_network_modules": {"modules": [{"module": "dccp", "disabled": true, "loaded": false}, {"module": "tipc", "disabled": true, "loaded": false}, {"module": "rds", "disabled": true, "loaded": false}, {"module": "sctp", "disabled": true, "loaded": false}, {"module": "atm", "disabled": true, "loaded": false}, {"module": "can", "disabled": true, "loaded": false}]}, "sysctl_parameters": {"analysis": [{"parameter": "net.ipv4.ip_forward", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.forwarding", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.forwarding", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.send_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.send_redirects", "current_value": "0"}, {"parameter": "net.ipv4.icmp_ignore_bogus_error_responses", "current_value": "1"}, {"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"}, {"parameter": "net.ipv4.conf.all.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.secure_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.secure_redirects", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.rp_filter", "current_value": "1"}, {"parameter": "net.ipv4.conf.default.rp_filter", "current_value": "1"}, {"parameter": "net.ipv4.conf.all.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv4.conf.all.log_martians", "current_value": "1"}, {"parameter": "net.ipv4.conf.default.log_martians", "current_value": "1"}, {"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"}, {"parameter": "net.ipv4.conf.all.route_localnet", "current_value": "0"}, {"parameter": "net.ipv4.conf.default.route_localnet", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.forwarding", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.forwarding", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.accept_redirects", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.accept_source_route", "current_value": "0"}, {"parameter": "net.ipv6.conf.all.accept_ra", "current_value": "0"}, {"parameter": "net.ipv6.conf.default.accept_ra", "current_value": "0"}], "persisted": {"net.ipv4.ip_forward": "0", "net.ipv4.conf.all.forwarding": "0", "net.ipv4.conf.default.forwarding": "0", "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.default.send_redirects": "0", "net.ipv4.icmp_ignore_bogus_error_responses": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1", "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0", "net.ipv4.conf.all.secure_redirects": "0", "net.ipv4.conf.default.secure_redirects": "0", "net.ipv4.conf.all.rp_filter": "1", "net.ipv4.conf.default.rp_filter": "1", "net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.default.accept_source_route": "0", "net.ipv4.conf.all.log_martians": "1", "net.ipv4.conf.default.log_martians": "1", "net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.route_localnet": "0", "net.ipv4.conf.default.route_localnet": "0", "net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.default.forwarding": "0", "net.ipv6.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0", "net.ipv6.conf.all.accept_source_route": "0", "net.ipv6.conf.default.accept_source_route": "0", "net.ipv6.conf.all.accept_ra": "0", "net.ipv6.conf.default.accept_ra": "0"}}, "firewall": {"backend": "nftables", "zones": [{"name": "public", "interfaces": ["eth0"], "target": "default", "permanent_target": "default", "icmp_block_inversion": false, "icmp_blocks": ["timestamp-reply", "timestamp-request"]}, {"name": "trusted", "interfaces": ["lo"], "target": "ACCEPT", "permanent_target": "ACCEPT", "icmp_block_inversion": false, "icmp_blocks": []}], "log_denied": "unicast"}, "services": {"sshd.service": {"state": "running", "status": "enabled"}, "firewalld.service": {"state": "running", "status": "enabled"}, "nftables.service": {"state": "inactive", "status": "not-found"}}}

test_network_good_input_compliant if {
	data.cis_rhel9.network.compliant with input as good
}

test_network_empty_object_facts_not_compliant if {
	i := {"sysctl_parameters": {}, "ip_forwarding": {}, "ipv6": {}, "firewall": {}, "wireless_interfaces": {}}
	not data.cis_rhel9.network.compliant with input as i
}

test_network_each_empty_fact_is_violation if {
	every key in ["sysctl_parameters", "firewall", "wireless_interfaces", "disabled_network_modules"] {
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
	keep := [e | some e in good.sysctl_parameters.analysis; e.parameter != "net.ipv4.ip_forward"]
	i := json.patch(good, [{"op": "replace", "path": "/sysctl_parameters/analysis", "value": keep}])
	"3.3.1.1: evidence missing — sysctl_parameters.analysis/persisted[net.ipv4.ip_forward] not collected" in data.cis_rhel9.network.violations with input as i
}

test_network_ipv6_forwarding_not_required_when_ipv6_disabled if {
	keep := [e | some e in good.sysctl_parameters.analysis; not startswith(e.parameter, "net.ipv6.")]
	i := json.patch(good, [
		{"op": "replace", "path": "/sysctl_parameters/analysis", "value": keep},
		{"op": "add", "path": "/ipv6", "value": {"disabled": true, "status": "disabled"}},
	])
	data.cis_rhel9.network.compliant with input as i
}

test_network_persisted_value_required if {
	i := json.remove(good, ["/sysctl_parameters/persisted/net.ipv4.tcp_syncookies"])
	"3.3.1.18: evidence missing — sysctl_parameters.analysis/persisted[net.ipv4.tcp_syncookies] not collected" in data.cis_rhel9.network.violations with input as i
}
