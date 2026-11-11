# METADATA
# title: "DISA STIG for RHEL 9 - Network Configuration Module"
# custom:
#   class: security
#   framework: stig_rhel_9
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
package stig.rhel_9.network

# DISA STIG for RHEL 9 - Network Configuration Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: Firewall, network parameters, IPv6, ICMP redirects

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-251015 | V-257936 | CAT II
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

status_rhel_09_251015 := "Not_a_Finding" if firewall_active

else := "Open"

finding_rhel_09_251015 := {
	"vuln_id": "V-257936",
	"stig_id": "RHEL-09-251015",
	"severity": "CAT II",
	"rule_title": "The firewalld service on RHEL 9 must be active.",
	"status": status_rhel_09_251015,
	"fix_text": "Enable firewalld: systemctl enable --now firewalld",
}

# RHEL-09-253075 | V-257970 | CAT II
# IP forwarding must be disabled
default ip_forwarding_disabled := false

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
	input.network_config.ipv4_forwarding == false
}

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
}

status_rhel_09_253075 := "Not_a_Finding" if ip_forwarding_disabled

else := "Open"

finding_rhel_09_253075 := {
	"vuln_id": "V-257970",
	"stig_id": "RHEL-09-253075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not enable IPv4 packet forwarding unless the system is a router.",
	"status": status_rhel_09_253075,
	"fix_text": "Disable IP forwarding: Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-253015 | V-257958 | CAT II
# ICMP redirects must not be accepted (IPv4)
default icmp_redirect_accept_disabled := false

icmp_redirect_accept_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_rhel_09_253015 := "Not_a_Finding" if icmp_redirect_accept_disabled

else := "Open"

finding_rhel_09_253015 := {
	"vuln_id": "V-257958",
	"stig_id": "RHEL-09-253015",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_rhel_09_253015,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-253065 | V-257968 | CAT II
# ICMP redirects must not be sent
default icmp_redirect_send_disabled := false

icmp_redirect_send_disabled if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.send_redirects"] == "0"
}

status_rhel_09_253065 := "Not_a_Finding" if icmp_redirect_send_disabled

else := "Open"

finding_rhel_09_253065 := {
	"vuln_id": "V-257968",
	"stig_id": "RHEL-09-253065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not send Internet Control Message Protocol (ICMP) redirects.",
	"status": status_rhel_09_253065,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-253020 | V-257959 | CAT II
# Source routing must be disabled
default source_routing_disabled := false

source_routing_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_source_route"] == "0"
}

status_rhel_09_253020 := "Not_a_Finding" if source_routing_disabled

else := "Open"

finding_rhel_09_253020 := {
	"vuln_id": "V-257959",
	"stig_id": "RHEL-09-253020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not forward Internet Protocol version 4 (IPv4) source-routed packets.",
	"status": status_rhel_09_253020,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-253060 | V-257967 | CAT II
# Bogus ICMP responses must be ignored
default icmp_bogus_error_responses := false

icmp_bogus_error_responses if {
	input.kernel_params["net.ipv4.icmp_ignore_bogus_error_responses"] == "1"
}

status_rhel_09_253060 := "Not_a_Finding" if icmp_bogus_error_responses

else := "Open"

finding_rhel_09_253060 := {
	"vuln_id": "V-257967",
	"stig_id": "RHEL-09-253060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must limit the number of bogus Internet Control Message Protocol (ICMP) response errors logs.",
	"status": status_rhel_09_253060,
	"fix_text": "Set net.ipv4.icmp_ignore_bogus_error_responses=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-253010 | V-257957 | CAT II
# IPv4 TCP syncookies must be enabled
default tcp_syncookies_enabled := false

tcp_syncookies_enabled if {
	input.kernel_params["net.ipv4.tcp_syncookies"] == "1"
}

status_rhel_09_253010 := "Not_a_Finding" if tcp_syncookies_enabled

else := "Open"

finding_rhel_09_253010 := {
	"vuln_id": "V-257957",
	"stig_id": "RHEL-09-253010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured to use TCP syncookies.",
	"status": status_rhel_09_253010,
	"fix_text": "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-253035 | V-257962 | CAT II
# Reverse path filter must be enabled
default rp_filter_enabled := false

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"
}

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"
}

status_rhel_09_253035 := "Not_a_Finding" if rp_filter_enabled

else := "Open"

finding_rhel_09_253035 := {
	"vuln_id": "V-257962",
	"stig_id": "RHEL-09-253035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use reverse path filtering on all IPv4 interfaces.",
	"status": status_rhel_09_253035,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-291040 | V-258040 | CAT II
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

status_rhel_09_291040 := "Not_a_Finding" if wireless_disabled

else := "Open"

finding_rhel_09_291040 := {
	"vuln_id": "V-258040",
	"stig_id": "RHEL-09-291040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 wireless network adapters must be disabled.",
	"status": status_rhel_09_291040,
	"fix_text": "Disable wireless: nmcli radio wifi off or disable in NetworkManager",
}

# RHEL-09-291035 | V-258039 | CAT II
# Bluetooth kernel module must be disabled
default bluetooth_module_disabled := false

bluetooth_module_disabled if {
	input.kernel_modules.bluetooth.blacklisted == true
}

bluetooth_module_disabled if {
	input.kernel_modules.bluetooth.status == "disabled"
}

status_rhel_09_291035 := "Not_a_Finding" if bluetooth_module_disabled

else := "Open"

finding_rhel_09_291035 := {
	"vuln_id": "V-258039",
	"stig_id": "RHEL-09-291035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 Bluetooth must be disabled.",
	"status": status_rhel_09_291035,
	"fix_text": "Blacklist bluetooth: echo 'install bluetooth /bin/false' >> /etc/modprobe.d/bluetooth.conf",
}

# RHEL-09-251040 | V-257941 | CAT II
# Network interfaces must not be in promiscuous mode
default no_promiscuous_interfaces := false

no_promiscuous_interfaces if {
	count(input.promiscuous_interfaces) == 0
}

no_promiscuous_interfaces if {
	not input.promiscuous_interfaces
}

status_rhel_09_251040 := "Not_a_Finding" if no_promiscuous_interfaces

else := "Open"

finding_rhel_09_251040 := {
	"vuln_id": "V-257941",
	"stig_id": "RHEL-09-251040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 network interfaces must not be in promiscuous mode.",
	"status": status_rhel_09_251040,
	"fix_text": "Disable promiscuous mode: ip link set <interface> promisc off",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_09_251015,
	finding_rhel_09_253075,
	finding_rhel_09_253015,
	finding_rhel_09_253065,
	finding_rhel_09_253020,
	finding_rhel_09_253060,
	finding_rhel_09_253010,
	finding_rhel_09_253035,
	finding_rhel_09_291040,
	finding_rhel_09_291035,
	finding_rhel_09_251040,
]

# No CAT III rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_iii_findings := array.concat([], [])

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

# `compliant`: no open finding at ANY category (CAT I, II or III).
# `cat_i_compliant`: the former CAT-I-only meaning, for gating on the critical subset.
default cat_i_compliant := false

open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

cat_i_compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "network",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
