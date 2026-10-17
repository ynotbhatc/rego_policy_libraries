# METADATA
# title: "DISA STIG for Oracle Linux 9 - Network Configuration Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 13
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.oracle_linux_9.network

# DISA STIG for Oracle Linux 9 - Network Configuration Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/network.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Firewall, network parameters, IPv6, ICMP redirects

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-000220 | V-271469 | CAT II
# Firewall must be active
default firewall_active := false

firewall_active if {
	input.firewall.active == true
}

firewall_active if {
	input.services.firewalld == "active"
}

firewall_active if {
	input.services.nftables == "active"
}

status_ol09_00_000220 := "Not_a_Finding" if { firewall_active } else := "Open"

finding_ol09_00_000220 := {
	"vuln_id": "V-271469",
	"stig_id": "OL09-00-000220",
	"severity": "CAT II",
	"rule_title": "OL 9 must have the firewalld package installed.",
	"status": status_ol09_00_000220,
	"fix_text": "Enable firewalld: systemctl enable --now firewalld",
}

# OL09-00-006028 | V-271872 | CAT II
# IP forwarding must be disabled
default ip_forwarding_disabled := false

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
	input.network_config.ipv4_forwarding == false
}

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
}

status_ol09_00_006028 := "Not_a_Finding" if { ip_forwarding_disabled } else := "Open"

finding_ol09_00_006028 := {
	"vuln_id": "V-271872",
	"stig_id": "OL09-00-006028",
	"severity": "CAT II",
	"rule_title": "OL 9 must not enable IPv4 packet forwarding unless the system is a router.",
	"status": status_ol09_00_006028,
	"fix_text": "Disable IP forwarding: Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006020 | V-271864 | CAT II
# ICMP redirects must not be accepted (IPv4)
default icmp_redirect_accept_disabled := false

icmp_redirect_accept_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_ol09_00_006020 := "Not_a_Finding" if { icmp_redirect_accept_disabled } else := "Open"

finding_ol09_00_006020 := {
	"vuln_id": "V-271864",
	"stig_id": "OL09-00-006020",
	"severity": "CAT II",
	"rule_title": "OL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_ol09_00_006020,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006032 | V-271875 | CAT II
# ICMP redirects must not be sent
default icmp_redirect_send_disabled := false

icmp_redirect_send_disabled if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.send_redirects"] == "0"
}

status_ol09_00_006032 := "Not_a_Finding" if { icmp_redirect_send_disabled } else := "Open"

finding_ol09_00_006032 := {
	"vuln_id": "V-271875",
	"stig_id": "OL09-00-006032",
	"severity": "CAT II",
	"rule_title": "OL 9 must not send Internet Control Message Protocol (ICMP) redirects.",
	"status": status_ol09_00_006032,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006042 | V-271879 | CAT II
# Source routing must be disabled
default source_routing_disabled := false

source_routing_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_source_route"] == "0"
}

status_ol09_00_006042 := "Not_a_Finding" if { source_routing_disabled } else := "Open"

finding_ol09_00_006042 := {
	"vuln_id": "V-271879",
	"stig_id": "OL09-00-006042",
	"severity": "CAT II",
	"rule_title": "OL 9 must not forward IPv6 source-routed packets.",
	"status": status_ol09_00_006042,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006031 | V-271874 | CAT II
# Bogus ICMP responses must be ignored
default icmp_bogus_error_responses := false

icmp_bogus_error_responses if {
	input.kernel_params["net.ipv4.icmp_ignore_bogus_error_responses"] == "1"
}

status_ol09_00_006031 := "Not_a_Finding" if { icmp_bogus_error_responses } else := "Open"

finding_ol09_00_006031 := {
	"vuln_id": "V-271874",
	"stig_id": "OL09-00-006031",
	"severity": "CAT II",
	"rule_title": "OL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.",
	"status": status_ol09_00_006031,
	"fix_text": "Set net.ipv4.icmp_ignore_bogus_error_responses=1 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006050 | V-271884 | CAT II
# IPv4 TCP syncookies must be enabled
default tcp_syncookies_enabled := false

tcp_syncookies_enabled if {
	input.kernel_params["net.ipv4.tcp_syncookies"] == "1"
}

status_ol09_00_006050 := "Not_a_Finding" if { tcp_syncookies_enabled } else := "Open"

finding_ol09_00_006050 := {
	"vuln_id": "V-271884",
	"stig_id": "OL09-00-006050",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured to use TCP syncookies.",
	"status": status_ol09_00_006050,
	"fix_text": "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006024 | V-271868 | CAT II
# Reverse path filter must be enabled
default rp_filter_enabled := false

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"
}

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"
}

status_ol09_00_006024 := "Not_a_Finding" if { rp_filter_enabled } else := "Open"

finding_ol09_00_006024 := {
	"vuln_id": "V-271868",
	"stig_id": "OL09-00-006024",
	"severity": "CAT II",
	"rule_title": "OL 9 must use reverse path filtering on all IPv4 interfaces.",
	"status": status_ol09_00_006024,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-stig.conf",
}

# OL09-00-006041 | V-271878 | CAT II
# IPv6 must be disabled unless required
default ipv6_disabled_or_configured := false

ipv6_disabled_or_configured if {
	input.network_config.ipv6_disabled == true
}

ipv6_disabled_or_configured if {
	input.kernel_params["net.ipv6.conf.all.disable_ipv6"] == "1"
}

ipv6_disabled_or_configured if {
	# IPv6 enabled but properly configured
	input.network_config.ipv6_required == true
	input.kernel_params["net.ipv6.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv6.conf.all.accept_source_route"] == "0"
}

status_ol09_00_006041 := "Not_a_Finding" if { ipv6_disabled_or_configured } else := "Open"

finding_ol09_00_006041 := {
	"vuln_id": "V-271878",
	"stig_id": "OL09-00-006041",
	"severity": "CAT II",
	"rule_title": "OL 9 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_ol09_00_006041,
	"fix_text": "Disable IPv6 or configure: Set net.ipv6.conf.all.disable_ipv6=1",
}

# OL09-00-006001 | V-271859 | CAT II
# Wireless interfaces must be disabled unless mission requires
default wireless_disabled := false

wireless_disabled if {
	input.network_config.wireless_disabled == true
}

wireless_disabled if {
	# Missing evidence is not a pass: the list must be collected (empty means none found).
	is_array(input.wireless_interfaces)
	count(input.wireless_interfaces) == 0
}

# The gather_network_config collector emits an object {interfaces, count, has_wireless}.
wireless_disabled if {
	is_object(input.wireless_interfaces)
	input.wireless_interfaces.has_wireless == false
}

status_ol09_00_006001 := "Not_a_Finding" if { wireless_disabled } else := "Open"

finding_ol09_00_006001 := {
	"vuln_id": "V-271859",
	"stig_id": "OL09-00-006001",
	"severity": "CAT II",
	"rule_title": "OL 9 wireless network adapters must be disabled.",
	"status": status_ol09_00_006001,
	"fix_text": "Disable wireless: nmcli radio wifi off or disable in NetworkManager",
}

# OL09-00-000046 | V-271449 | CAT II
# Bluetooth kernel module must be disabled
default bluetooth_module_disabled := false

bluetooth_module_disabled if {
	input.kernel_modules["bluetooth"].blacklisted == true
}

bluetooth_module_disabled if {
	input.kernel_modules["bluetooth"].status == "disabled"
}

status_ol09_00_000046 := "Not_a_Finding" if { bluetooth_module_disabled } else := "Open"

finding_ol09_00_000046 := {
	"vuln_id": "V-271449",
	"stig_id": "OL09-00-000046",
	"severity": "CAT II",
	"rule_title": "OL 9 Bluetooth must be disabled.",
	"status": status_ol09_00_000046,
	"fix_text": "Blacklist bluetooth: echo 'install bluetooth /bin/false' >> /etc/modprobe.d/bluetooth.conf",
}

# OL09-00-006004 | V-271862 | CAT II
# Network interfaces must not be in promiscuous mode
default no_promiscuous_interfaces := false

no_promiscuous_interfaces if {
	# Missing evidence is not a pass: the list must be collected (empty means none found).
	is_array(input.promiscuous_interfaces)
	count(input.promiscuous_interfaces) == 0
}


status_ol09_00_006004 := "Not_a_Finding" if { no_promiscuous_interfaces } else := "Open"

finding_ol09_00_006004 := {
	"vuln_id": "V-271862",
	"stig_id": "OL09-00-006004",
	"severity": "CAT II",
	"rule_title": "OL 9 network interfaces must not be in promiscuous mode.",
	"status": status_ol09_00_006004,
	"fix_text": "Disable promiscuous mode: ip link set <interface> promisc off",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol09_00_000220,
	finding_ol09_00_006028,
	finding_ol09_00_006020,
	finding_ol09_00_006032,
	finding_ol09_00_006042,
	finding_ol09_00_006031,
	finding_ol09_00_006050,
	finding_ol09_00_006024,
	finding_ol09_00_006041,
	finding_ol09_00_006001,
	finding_ol09_00_000046,
	finding_ol09_00_006004,
]

cat_iii_findings := []

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "network",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
