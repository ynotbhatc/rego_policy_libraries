# METADATA
# title: "DISA STIG for RHEL 10 - Network Configuration Module"
# custom:
#   class: security
#   framework: stig_rhel_10
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 12
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_10.network

# DISA STIG for RHEL 10 - Network Configuration Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/network.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Firewall, network parameters, IPv6, ICMP redirects

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-200531 | V-280956 | CAT II
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

status_rhel_10_200531 := "Not_a_Finding" if firewall_active

else := "Open"

finding_rhel_10_200531 := {
	"vuln_id": "V-280956",
	"stig_id": "RHEL-10-200531",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must have the \"firewalld\" service set to active.",
	"status": status_rhel_10_200531,
	"fix_text": "Enable firewalld: systemctl enable --now firewalld",
}

# RHEL-10-800210 | V-281353 | CAT II
# IP forwarding must be disabled
default ip_forwarding_disabled := false

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
	input.network_config.ipv4_forwarding == false
}

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
}

status_rhel_10_800210 := "Not_a_Finding" if ip_forwarding_disabled

else := "Open"

finding_rhel_10_800210 := {
	"vuln_id": "V-281353",
	"stig_id": "RHEL-10-800210",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not enable Internet Protocol version 4 (IPv4) packet forwarding unless the system is a router.",
	"status": status_rhel_10_800210,
	"fix_text": "Disable IP forwarding: Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800090 | V-281341 | CAT II
# ICMP redirects must not be accepted (IPv4)
default icmp_redirect_accept_disabled := false

icmp_redirect_accept_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_rhel_10_800090 := "Not_a_Finding" if icmp_redirect_accept_disabled

else := "Open"

finding_rhel_10_800090 := {
	"vuln_id": "V-281341",
	"stig_id": "RHEL-10-800090",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_rhel_10_800090,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800190 | V-281351 | CAT II
# ICMP redirects must not be sent
default icmp_redirect_send_disabled := false

icmp_redirect_send_disabled if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.send_redirects"] == "0"
}

status_rhel_10_800190 := "Not_a_Finding" if icmp_redirect_send_disabled

else := "Open"

finding_rhel_10_800190 := {
	"vuln_id": "V-281351",
	"stig_id": "RHEL-10-800190",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not send Internet Control Message Protocol (ICMP) redirects.",
	"status": status_rhel_10_800190,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800100 | V-281342 | CAT II
# Source routing must be disabled
default source_routing_disabled := false

source_routing_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_source_route"] == "0"
}

status_rhel_10_800100 := "Not_a_Finding" if source_routing_disabled

else := "Open"

finding_rhel_10_800100 := {
	"vuln_id": "V-281342",
	"stig_id": "RHEL-10-800100",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not forward Internet Protocol version 4 (IPv4) source-routed packets.",
	"status": status_rhel_10_800100,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800180 | V-281350 | CAT II
# Bogus ICMP responses must be ignored
default icmp_bogus_error_responses := false

icmp_bogus_error_responses if {
	input.kernel_params["net.ipv4.icmp_ignore_bogus_error_responses"] == "1"
}

status_rhel_10_800180 := "Not_a_Finding" if icmp_bogus_error_responses

else := "Open"

finding_rhel_10_800180 := {
	"vuln_id": "V-281350",
	"stig_id": "RHEL-10-800180",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.",
	"status": status_rhel_10_800180,
	"fix_text": "Set net.ipv4.icmp_ignore_bogus_error_responses=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800080 | V-281340 | CAT II
# IPv4 TCP syncookies must be enabled
default tcp_syncookies_enabled := false

tcp_syncookies_enabled if {
	input.kernel_params["net.ipv4.tcp_syncookies"] == "1"
}

status_rhel_10_800080 := "Not_a_Finding" if tcp_syncookies_enabled

else := "Open"

finding_rhel_10_800080 := {
	"vuln_id": "V-281340",
	"stig_id": "RHEL-10-800080",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured to use Transmission Control Protocol (TCP) syncookies.",
	"status": status_rhel_10_800080,
	"fix_text": "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-800130 | V-281345 | CAT II
# Reverse path filter must be enabled
default rp_filter_enabled := false

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"
}

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"
}

status_rhel_10_800130 := "Not_a_Finding" if rp_filter_enabled

else := "Open"

finding_rhel_10_800130 := {
	"vuln_id": "V-281345",
	"stig_id": "RHEL-10-800130",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must use reverse path filtering on all Internet Protocol version 4 (IPv4) interfaces.",
	"status": status_rhel_10_800130,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-10-700870 | V-281290 | CAT II
# Wireless interfaces must be disabled unless mission requires
default wireless_disabled := false

wireless_disabled if {
	input.network_config.wireless_disabled == true
}

wireless_disabled if {
	count(input.wireless_interfaces) == 0
}

wireless_disabled if {
	not input.wireless_interfaces
}

status_rhel_10_700870 := "Not_a_Finding" if wireless_disabled

else := "Open"

finding_rhel_10_700870 := {
	"vuln_id": "V-281290",
	"stig_id": "RHEL-10-700870",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must disable wireless network adapters.",
	"status": status_rhel_10_700870,
	"fix_text": "Disable wireless: nmcli radio wifi off or disable in NetworkManager",
}

# RHEL-10-700860 | V-281289 | CAT II
# Bluetooth kernel module must be disabled
default bluetooth_module_disabled := false

bluetooth_module_disabled if {
	input.kernel_modules.bluetooth.blacklisted == true
}

bluetooth_module_disabled if {
	input.kernel_modules.bluetooth.status == "disabled"
}

status_rhel_10_700860 := "Not_a_Finding" if bluetooth_module_disabled

else := "Open"

finding_rhel_10_700860 := {
	"vuln_id": "V-281289",
	"stig_id": "RHEL-10-700860",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must disable Bluetooth.",
	"status": status_rhel_10_700860,
	"fix_text": "Blacklist bluetooth: echo 'install bluetooth /bin/false' >> /etc/modprobe.d/bluetooth.conf",
}

# RHEL-10-800020 | V-281334 | CAT II
# Network interfaces must not be in promiscuous mode
default no_promiscuous_interfaces := false

no_promiscuous_interfaces if {
	count(input.promiscuous_interfaces) == 0
}

no_promiscuous_interfaces if {
	not input.promiscuous_interfaces
}

status_rhel_10_800020 := "Not_a_Finding" if no_promiscuous_interfaces

else := "Open"

finding_rhel_10_800020 := {
	"vuln_id": "V-281334",
	"stig_id": "RHEL-10-800020",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce that network interfaces not be in promiscuous mode.",
	"status": status_rhel_10_800020,
	"fix_text": "Disable promiscuous mode: ip link set <interface> promisc off",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22
# types a literal empty array as having no members and rejects `some f in cat_i_findings`
# as an undefined ref, so the module fails to compile when it is loaded on its own
# (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_10_200531,
	finding_rhel_10_800210,
	finding_rhel_10_800090,
	finding_rhel_10_800190,
	finding_rhel_10_800100,
	finding_rhel_10_800180,
	finding_rhel_10_800080,
	finding_rhel_10_800130,
	finding_rhel_10_700870,
	finding_rhel_10_700860,
	finding_rhel_10_800020,
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
