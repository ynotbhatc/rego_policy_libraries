package stig.rhel_8.network

# DISA STIG for RHEL 8 - Network Configuration Module
# STIG Version: V1R13 | Released: July 2024

import rego.v1

default compliant := false

# =============================================================================
# CAT I
# =============================================================================

# RHEL-08-040000 (network) | V-230505 | CAT I - Firewall must be active
default firewall_active := false
firewall_active if { input.firewall.active == true }
firewall_active if { input.services.firewalld == "active" }

status_rhel_08_n_040000 := "Not_a_Finding" if { firewall_active } else := "Open"
finding_rhel_08_n_040000 := {
	"vuln_id": "V-230505",
	"stig_id": "RHEL-08-040100",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must have firewalld installed",
	"status": status_rhel_08_n_040000,
	"fix_text": "systemctl enable --now firewalld",
}

# RHEL-08-040110 | V-230506 | CAT I - IP forwarding must be disabled
default ip_forward_disabled := false
ip_forward_disabled if { input.kernel_params["net.ipv4.ip_forward"] == "0" }

status_rhel_08_040110 := "Not_a_Finding" if { ip_forward_disabled } else := "Open"
finding_rhel_08_040110 := {
	"vuln_id": "V-230506",
	"stig_id": "RHEL-08-040110",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not enable IPv4 packet forwarding unless system is a router",
	"status": status_rhel_08_040110,
	"fix_text": "Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# =============================================================================
# CAT II
# =============================================================================

# RHEL-08-040120 | V-230507 | CAT II - No ICMP redirects accepted
default no_icmp_redirects := false
no_icmp_redirects if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_rhel_08_040120 := "Not_a_Finding" if { no_icmp_redirects } else := "Open"
finding_rhel_08_040120 := {
	"vuln_id": "V-230507",
	"stig_id": "RHEL-08-040120",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not accept ICMP redirect messages",
	"status": status_rhel_08_040120,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0",
}

# RHEL-08-040130 | V-230508 | CAT II - No ICMP redirects sent
default no_icmp_send := false
no_icmp_send if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
}

status_rhel_08_040130 := "Not_a_Finding" if { no_icmp_send } else := "Open"
finding_rhel_08_040130 := {
	"vuln_id": "V-230508",
	"stig_id": "RHEL-08-040130",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not send ICMP redirects",
	"status": status_rhel_08_040130,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0",
}

# RHEL-08-040140 | V-230509 | CAT II - Source routing disabled
default no_source_routing := false
no_source_routing if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
}

status_rhel_08_040140 := "Not_a_Finding" if { no_source_routing } else := "Open"
finding_rhel_08_040140 := {
	"vuln_id": "V-230509",
	"stig_id": "RHEL-08-040140",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not forward IPv4 source-routed packets",
	"status": status_rhel_08_040140,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0",
}

# RHEL-08-040150 | V-230510 | CAT II - TCP syncookies enabled
default tcp_syncookies := false
tcp_syncookies if { input.kernel_params["net.ipv4.tcp_syncookies"] == "1" }

status_rhel_08_040150 := "Not_a_Finding" if { tcp_syncookies } else := "Open"
finding_rhel_08_040150 := {
	"vuln_id": "V-230510",
	"stig_id": "RHEL-08-040150",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must use TCP syncookies",
	"status": status_rhel_08_040150,
	"fix_text": "Set net.ipv4.tcp_syncookies=1",
}

# RHEL-08-040155 | V-230511 | CAT II - Bluetooth disabled
default no_bluetooth := false
no_bluetooth if { input.kernel_modules["bluetooth"].blacklisted == true }
no_bluetooth if { input.services.bluetooth == "inactive" }

status_rhel_08_040155 := "Not_a_Finding" if { no_bluetooth } else := "Open"
finding_rhel_08_040155 := {
	"vuln_id": "V-230511",
	"stig_id": "RHEL-08-040155",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable the Bluetooth kernel module",
	"status": status_rhel_08_040155,
	"fix_text": "Blacklist bluetooth module",
}

# RHEL-08-040157 | V-230512 | CAT II - Wireless disabled
default no_wireless := false
no_wireless if { not input.wireless_interfaces }
no_wireless if { count(input.wireless_interfaces) == 0 }

status_rhel_08_040157 := "Not_a_Finding" if { no_wireless } else := "Open"
finding_rhel_08_040157 := {
	"vuln_id": "V-230512",
	"stig_id": "RHEL-08-040157",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable wireless network adapters",
	"status": status_rhel_08_040157,
	"fix_text": "Disable wireless interfaces",
}

# RHEL-08-040158 | V-230513 | CAT II - Reverse path filter
default rp_filter := false
rp_filter if { input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1" }
rp_filter if { input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2" }

status_rhel_08_040158 := "Not_a_Finding" if { rp_filter } else := "Open"
finding_rhel_08_040158 := {
	"vuln_id": "V-230513",
	"stig_id": "RHEL-08-040158",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must enable reverse path filtering",
	"status": status_rhel_08_040158,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_n_040000,
	finding_rhel_08_040110,
]

cat_ii_findings := [
	finding_rhel_08_040120,
	finding_rhel_08_040130,
	finding_rhel_08_040140,
	finding_rhel_08_040150,
	finding_rhel_08_040155,
	finding_rhel_08_040157,
	finding_rhel_08_040158,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "network",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
