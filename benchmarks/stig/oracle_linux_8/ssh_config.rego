# METADATA
# title: "DISA STIG for Oracle Linux 8 - SSH Configuration Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 9
#     cited: 8
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_8.ssh_config

# DISA STIG for Oracle Linux 8 - SSH Configuration Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/ssh_config.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: SSH daemon hardening, key exchange, MACs, ciphers

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule Oracle Linux 8 does not carry)

# Approved MACs
approved_macs := {
	"hmac-sha2-512",
	"hmac-sha2-256",
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256-etm@openssh.com",
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL08-00-010290 | V-283457 | CAT I
# SSH must use FIPS-approved MACs
default ssh_fips_macs := false

ssh_fips_macs if {
	macs_str := input.ssh_config.MACs
	macs := split(macs_str, ",")
	count([m | some m in macs; not m in approved_macs]) == 0
	count(macs) > 0
}

status_ol08_00_010290 := "Not_a_Finding" if { ssh_fips_macs } else := "Open"

finding_ol08_00_010290 := {
	"vuln_id": "V-283457",
	"stig_id": "OL08-00-010290",
	"severity": "CAT I",
	"rule_title": "The OL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_ol08_00_010290,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-010550 | V-248613 | CAT II
# SSH must not permit root login
default ssh_no_root_login := false

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "no"
}

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "forced-commands-only"
}

status_ol08_00_010550 := "Not_a_Finding" if { ssh_no_root_login } else := "Open"

finding_ol08_00_010550 := {
	"vuln_id": "V-248613",
	"stig_id": "OL08-00-010550",
	"severity": "CAT II",
	"rule_title": "OL 8 must not permit direct logons to the root account using remote access via SSH.",
	"status": status_ol08_00_010550,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# OL08-00-040160 | V-248867 | CAT II
# SSH protocol must be 2
default ssh_protocol_2 := false

ssh_protocol_2 if {
	input.ssh_config.Protocol == "2"
}

ssh_protocol_2 if {
	not input.ssh_config.Protocol  # Protocol 2 is default in OpenSSH 7+
}

status_ol08_00_040160 := "Not_a_Finding" if { ssh_protocol_2 } else := "Open"

finding_ol08_00_040160 := {
	"vuln_id": "V-248867",
	"stig_id": "OL08-00-040160",
	"severity": "CAT II",
	"rule_title": "All OL 8 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.",
	"status": status_ol08_00_040160,
	"fix_text": "Ensure Protocol 2 is configured (or remove Protocol line for modern OpenSSH)",
}

# OL08-00-010201 | V-248553 | CAT II
# SSH ClientAliveInterval must be 600 or less
default ssh_client_alive_interval_ok := false

ssh_client_alive_interval_ok if {
	interval := to_number(input.ssh_config.ClientAliveInterval)
	interval <= 600
	interval > 0
}

status_ol08_00_010201 := "Not_a_Finding" if { ssh_client_alive_interval_ok } else := "Open"

finding_ol08_00_010201 := {
	"vuln_id": "V-248553",
	"stig_id": "OL08-00-010201",
	"severity": "CAT II",
	"rule_title": "OL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.",
	"status": status_ol08_00_010201,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# OL08-00-010200 | V-248552 | CAT II
# SSH ClientAliveCountMax must be 1 or less
default ssh_client_alive_count_ok := false

ssh_client_alive_count_ok if {
	count_max := to_number(input.ssh_config.ClientAliveCountMax)
	count_max <= 1
}

status_ol08_00_010200 := "Not_a_Finding" if { ssh_client_alive_count_ok } else := "Open"

finding_ol08_00_010200 := {
	"vuln_id": "V-248552",
	"stig_id": "OL08-00-010200",
	"severity": "CAT II",
	"rule_title": "OL 8 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.",
	"status": status_ol08_00_010200,
	"fix_text": "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config",
}

# OL08-00-010500 | V-248603 | CAT II
# SSH must use strict mode
default ssh_strict_modes := false

ssh_strict_modes if {
	lower(input.ssh_config.StrictModes) == "yes"
}

status_ol08_00_010500 := "Not_a_Finding" if { ssh_strict_modes } else := "Open"

finding_ol08_00_010500 := {
	"vuln_id": "V-248603",
	"stig_id": "OL08-00-010500",
	"severity": "CAT II",
	"rule_title": "The OL 8 SSH daemon must perform strict mode checking of home directory configuration files.",
	"status": status_ol08_00_010500,
	"fix_text": "Set StrictModes yes in /etc/ssh/sshd_config",
}

# OL08-00-010520 | V-248605 | CAT II
# SSH must not allow .shosts
default ssh_ignore_user_known_hosts := false

ssh_ignore_user_known_hosts if {
	lower(input.ssh_config.IgnoreUserKnownHosts) == "yes"
}

status_ol08_00_010520 := "Not_a_Finding" if { ssh_ignore_user_known_hosts } else := "Open"

finding_ol08_00_010520 := {
	"vuln_id": "V-248605",
	"stig_id": "OL08-00-010520",
	"severity": "CAT II",
	"rule_title": "The OL 8 SSH daemon must not allow authentication using known host's authentication.",
	"status": status_ol08_00_010520,
	"fix_text": "Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config",
}

# OL08-00-020350 | V-248718 | CAT II
# SSH PrintLastLog must be enabled
default ssh_print_last_log := false

ssh_print_last_log if {
	lower(input.ssh_config.PrintLastLog) == "yes"
}

status_ol08_00_020350 := "Not_a_Finding" if { ssh_print_last_log } else := "Open"

finding_ol08_00_020350 := {
	"vuln_id": "V-248718",
	"stig_id": "OL08-00-020350",
	"severity": "CAT II",
	"rule_title": "OL 8 must display the date and time of the last successful account logon upon an SSH logon.",
	"status": status_ol08_00_020350,
	"fix_text": "Set PrintLastLog yes in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol08_00_010290,
]

cat_ii_findings := [
	finding_ol08_00_010550,
	finding_ol08_00_040160,
	finding_ol08_00_010201,
	finding_ol08_00_010200,
	finding_ol08_00_010500,
	finding_ol08_00_010520,
	finding_ol08_00_020350,
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
	"module": "ssh_config",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
