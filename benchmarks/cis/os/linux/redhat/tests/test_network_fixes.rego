package cis.network_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

good_v4 := {
	"net_ipv4_conf_all_send_redirects": 0,
	"net_ipv4_conf_default_send_redirects": 0,
	"net_ipv4_ip_forward": 0,
	"net_ipv4_conf_all_accept_source_route": 0,
	"net_ipv4_conf_default_accept_source_route": 0,
	"net_ipv4_conf_all_accept_redirects": 0,
	"net_ipv4_conf_default_accept_redirects": 0,
	"net_ipv4_conf_all_secure_redirects": 0,
	"net_ipv4_conf_default_secure_redirects": 0,
	"net_ipv4_conf_all_log_martians": 1,
	"net_ipv4_conf_default_log_martians": 1,
	"net_ipv4_icmp_echo_ignore_broadcasts": 1,
	"net_ipv4_icmp_ignore_bogus_error_responses": 1,
	"net_ipv4_conf_all_rp_filter": 1,
	"net_ipv4_conf_default_rp_filter": 1,
	"net_ipv4_tcp_syncookies": 1,
	"wireless_interfaces": [],
}

ipv6_locked := {
	"net_ipv6_conf_all_accept_source_route": 0,
	"net_ipv6_conf_default_accept_source_route": 0,
	"net_ipv6_conf_all_accept_redirects": 0,
	"net_ipv6_conf_default_accept_redirects": 0,
	"net_ipv6_conf_all_accept_ra": 0,
	"net_ipv6_conf_default_accept_ra": 0,
}

test_network_string_sysctl_values_accepted if {
	data.cis.network.ip_forwarding_disabled with input as {"net_ipv4_ip_forward": "0"}
	data.cis.network.tcp_syn_cookies with input as {"net_ipv4_tcp_syncookies": "1"}
}

test_network_string_sysctl_value_wrong_rejected if {
	not data.cis.network.ip_forwarding_disabled with input as {"net_ipv4_ip_forward": "1"}
}

test_network_compliant_with_ipv6_locked_down if {
	data.cis.network.network_compliant with input as object.union(good_v4, ipv6_locked)
}

test_network_compliant_with_ipv6_disabled if {
	data.cis.network.network_compliant with input as object.union(good_v4, {"ipv6_disabled": true})
}

test_network_not_compliant_when_ipv6_ra_accepted if {
	i := object.union(good_v4, object.union(ipv6_locked, {"net_ipv6_conf_all_accept_ra": 1}))
	not data.cis.network.network_compliant with input as i
}

test_network_not_compliant_without_ipv6_evidence if {
	not data.cis.network.network_compliant with input as good_v4
}

test_network_not_compliant_with_wireless if {
	i := object.union(object.union(good_v4, ipv6_locked), {"wireless_interfaces": ["wlan0"]})
	not data.cis.network.network_compliant with input as i
}

test_network_report_defined_on_partial_input if {
	r := data.cis.network.network_compliance with input as {"net_ipv4_ip_forward": 0}
	count(r) == 16
	r.ipv6_disabled == false
	r.ip_forwarding_disabled == true
	r.overall_compliant == false
}
