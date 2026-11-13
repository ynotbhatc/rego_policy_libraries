# METADATA
# title: "DISA STIG for RHEL 8 - Network Configuration Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 9
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_8.network

# DISA STIG for RHEL 8 - Network Configuration Module
# STIG Version: V2R8 | Released: 01 Jul 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.

import rego.v1

default compliant := false

# =============================================================================
# CAT I
# =============================================================================

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-040101 | V-244544 | CAT II - Firewall must be active
default firewall_active := false

firewall_active if input.firewall.active == true
firewall_active if input.services.firewalld == "active"

status_rhel_08_040101 := "Not_a_Finding" if firewall_active

else := "Open"

finding_rhel_08_040101 := {
	"vuln_id": "V-244544",
	"stig_id": "RHEL-08-040101",
	"severity": "CAT II",
	"rule_title": "A firewall must be active on RHEL 8.",
	"status": status_rhel_08_040101,
	"fix_text": "systemctl enable --now firewalld",
}

# RHEL-08-040259 | V-250317 | CAT II - IP forwarding must be disabled
default ip_forward_disabled := false

ip_forward_disabled if input.kernel_params["net.ipv4.ip_forward"] == "0"

status_rhel_08_040259 := "Not_a_Finding" if ip_forward_disabled

else := "Open"

finding_rhel_08_040259 := {
	"vuln_id": "V-250317",
	"stig_id": "RHEL-08-040259",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not enable IPv4 packet forwarding unless the system is a router.",
	"status": status_rhel_08_040259,
	"fix_text": "Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-08-040279 | V-244553 | CAT II - No ICMP redirects accepted
default no_icmp_redirects := false

no_icmp_redirects if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_rhel_08_040279 := "Not_a_Finding" if no_icmp_redirects

else := "Open"

finding_rhel_08_040279 := {
	"vuln_id": "V-244553",
	"stig_id": "RHEL-08-040279",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_rhel_08_040279,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0",
}

# RHEL-08-040220 | V-230536 | CAT II - No ICMP redirects sent
default no_icmp_send := false

no_icmp_send if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
}

status_rhel_08_040220 := "Not_a_Finding" if no_icmp_send

else := "Open"

finding_rhel_08_040220 := {
	"vuln_id": "V-230536",
	"stig_id": "RHEL-08-040220",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not allow IPv4 ICMP redirect messages.",
	"status": status_rhel_08_040220,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0",
}

# RHEL-08-040239 | V-244551 | CAT II - Source routing disabled
default no_source_routing := false

no_source_routing if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
}

status_rhel_08_040239 := "Not_a_Finding" if no_source_routing

else := "Open"

finding_rhel_08_040239 := {
	"vuln_id": "V-244551",
	"stig_id": "RHEL-08-040239",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not forward IPv4 source-routed packets.",
	"status": status_rhel_08_040239,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0",
}

# RHEL-08-040111 | V-230507 | CAT II - Bluetooth disabled
default no_bluetooth := false

no_bluetooth if input.kernel_modules.bluetooth.blacklisted == true
no_bluetooth if input.services.bluetooth == "inactive"

status_rhel_08_040111 := "Not_a_Finding" if no_bluetooth

else := "Open"

finding_rhel_08_040111 := {
	"vuln_id": "V-230507",
	"stig_id": "RHEL-08-040111",
	"severity": "CAT II",
	"rule_title": "RHEL 8 Bluetooth must be disabled.",
	"status": status_rhel_08_040111,
	"fix_text": "Blacklist bluetooth module",
}

# RHEL-08-040110 | V-230506 | CAT II - Wireless disabled
default no_wireless := false

no_wireless if {
	is_array(input.wireless_interfaces)
	count(input.wireless_interfaces) == 0
}

status_rhel_08_040110 := "Not_a_Finding" if no_wireless

else := "Open"

finding_rhel_08_040110 := {
	"vuln_id": "V-230506",
	"stig_id": "RHEL-08-040110",
	"severity": "CAT II",
	"rule_title": "RHEL 8 wireless network adapters must be disabled.",
	"status": status_rhel_08_040110,
	"fix_text": "Disable wireless interfaces",
}

# RHEL-08-040285 | V-230549 | CAT II - Reverse path filter
default rp_filter := false

rp_filter if input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"
rp_filter if input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"

status_rhel_08_040285 := "Not_a_Finding" if rp_filter

else := "Open"

finding_rhel_08_040285 := {
	"vuln_id": "V-230549",
	"stig_id": "RHEL-08-040285",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use reverse path filtering on all IPv4 interfaces.",
	"status": status_rhel_08_040285,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_08_040101,
	finding_rhel_08_040259,
	finding_rhel_08_040279,
	finding_rhel_08_040220,
	finding_rhel_08_040239,
	finding_rhel_08_040111,
	finding_rhel_08_040110,
	finding_rhel_08_040285,
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
