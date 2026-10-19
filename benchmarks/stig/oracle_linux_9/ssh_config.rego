# METADATA
# title: "DISA STIG for Oracle Linux 9 - SSH Configuration Module"
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
#     as_of: v2.4.1
package stig.oracle_linux_9.ssh_config

# DISA STIG for Oracle Linux 9 - SSH Configuration Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/ssh_config.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: SSH daemon hardening, key exchange, MACs, ciphers

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule Oracle Linux 9 does not carry)

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

# OL09-00-000255 | V-271486 | CAT I
# SSH must use FIPS-approved MACs
default ssh_fips_macs := false

ssh_fips_macs if {
	macs_str := input.ssh_config.MACs
	macs := split(macs_str, ",")
	count([m | some m in macs; not m in approved_macs]) == 0
	count(macs) > 0
}

status_ol09_00_000255 := "Not_a_Finding" if { ssh_fips_macs } else := "Open"

finding_ol09_00_000255 := {
	"vuln_id": "V-271486",
	"stig_id": "OL09-00-000255",
	"severity": "CAT I",
	"rule_title": "OL 9 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_ol09_00_000255,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# OL09-00-002343 | V-271706 | CAT I
# SSH must not permit empty passwords
default ssh_no_empty_passwords := false

ssh_no_empty_passwords if {
	lower(input.ssh_config.PermitEmptyPasswords) == "no"
}

status_ol09_00_002343 := "Not_a_Finding" if { ssh_no_empty_passwords } else := "Open"

finding_ol09_00_002343 := {
	"vuln_id": "V-271706",
	"stig_id": "OL09-00-002343",
	"severity": "CAT I",
	"rule_title": "OL 9 SSHD must not allow blank passwords.",
	"status": status_ol09_00_002343,
	"fix_text": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
}

# OL09-00-002344 | V-271707 | CAT I
# SSH must use privilege separation
default ssh_use_pam := false

ssh_use_pam if {
	lower(input.ssh_config.UsePAM) == "yes"
}

status_ol09_00_002344 := "Not_a_Finding" if { ssh_use_pam } else := "Open"

finding_ol09_00_002344 := {
	"vuln_id": "V-271707",
	"stig_id": "OL09-00-002344",
	"severity": "CAT I",
	"rule_title": "OL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD.",
	"status": status_ol09_00_002344,
	"fix_text": "Set UsePAM yes in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-002345 | V-271708 | CAT II
# SSH must not permit root login
default ssh_no_root_login := false

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "no"
}

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "forced-commands-only"
}

status_ol09_00_002345 := "Not_a_Finding" if { ssh_no_root_login } else := "Open"

finding_ol09_00_002345 := {
	"vuln_id": "V-271708",
	"stig_id": "OL09-00-002345",
	"severity": "CAT II",
	"rule_title": "OL 9 must not permit direct logons to the root account using remote access via SSH.",
	"status": status_ol09_00_002345,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# OL09-00-000251 | V-271483 | CAT II
# SSH protocol must be 2
default ssh_protocol_2 := false

ssh_protocol_2 if {
	input.ssh_config.Protocol == "2"
}

ssh_protocol_2 if {
	not input.ssh_config.Protocol  # Protocol 2 is default in OpenSSH 7+
}

status_ol09_00_000251 := "Not_a_Finding" if { ssh_protocol_2 } else := "Open"

finding_ol09_00_000251 := {
	"vuln_id": "V-271483",
	"stig_id": "OL09-00-000251",
	"severity": "CAT II",
	"rule_title": "OL 9 networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.",
	"status": status_ol09_00_000251,
	"fix_text": "Ensure Protocol 2 is configured (or remove Protocol line for modern OpenSSH)",
}

# OL09-00-002357 | V-271719 | CAT II
# SSH must not allow host-based authentication
default ssh_no_hostbased_auth := false

ssh_no_hostbased_auth if {
	lower(input.ssh_config.HostbasedAuthentication) == "no"
}

status_ol09_00_002357 := "Not_a_Finding" if { ssh_no_hostbased_auth } else := "Open"

finding_ol09_00_002357 := {
	"vuln_id": "V-271719",
	"stig_id": "OL09-00-002357",
	"severity": "CAT II",
	"rule_title": "OL 9 must not allow a noncertificate trusted host SSH logon to the system.",
	"status": status_ol09_00_002357,
	"fix_text": "Set HostbasedAuthentication no in /etc/ssh/sshd_config",
}

# OL09-00-002347 | V-271710 | CAT II
# SSH ClientAliveInterval must be 600 or less
default ssh_client_alive_interval_ok := false

ssh_client_alive_interval_ok if {
	interval := to_number(input.ssh_config.ClientAliveInterval)
	interval <= 600
	interval > 0
}

status_ol09_00_002347 := "Not_a_Finding" if { ssh_client_alive_interval_ok } else := "Open"

finding_ol09_00_002347 := {
	"vuln_id": "V-271710",
	"stig_id": "OL09-00-002347",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.",
	"status": status_ol09_00_002347,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# OL09-00-002346 | V-271709 | CAT II
# SSH ClientAliveCountMax must be 1 or less
default ssh_client_alive_count_ok := false

ssh_client_alive_count_ok if {
	count_max := to_number(input.ssh_config.ClientAliveCountMax)
	count_max <= 1
}

status_ol09_00_002346 := "Not_a_Finding" if { ssh_client_alive_count_ok } else := "Open"

finding_ol09_00_002346 := {
	"vuln_id": "V-271709",
	"stig_id": "OL09-00-002346",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.",
	"status": status_ol09_00_002346,
	"fix_text": "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config",
}

# OL09-00-002351 | V-271714 | CAT II
# SSH must use strict mode
default ssh_strict_modes := false

ssh_strict_modes if {
	lower(input.ssh_config.StrictModes) == "yes"
}

status_ol09_00_002351 := "Not_a_Finding" if { ssh_strict_modes } else := "Open"

finding_ol09_00_002351 := {
	"vuln_id": "V-271714",
	"stig_id": "OL09-00-002351",
	"severity": "CAT II",
	"rule_title": "OL 9 SSH daemon must perform strict mode checking of home directory configuration files.",
	"status": status_ol09_00_002351,
	"fix_text": "Set StrictModes yes in /etc/ssh/sshd_config",
}

# OL09-00-002348 | V-271711 | CAT II
# SSH must disable rhosts authentication
default ssh_ignore_rhosts := false

ssh_ignore_rhosts if {
	lower(input.ssh_config.IgnoreRhosts) == "yes"
}

status_ol09_00_002348 := "Not_a_Finding" if { ssh_ignore_rhosts } else := "Open"

finding_ol09_00_002348 := {
	"vuln_id": "V-271711",
	"stig_id": "OL09-00-002348",
	"severity": "CAT II",
	"rule_title": "OL 9 SSH daemon must not allow rhosts authentication.",
	"status": status_ol09_00_002348,
	"fix_text": "Set IgnoreRhosts yes in /etc/ssh/sshd_config",
}

# OL09-00-002349 | V-271712 | CAT II
# SSH must not allow .shosts
default ssh_ignore_user_known_hosts := false

ssh_ignore_user_known_hosts if {
	lower(input.ssh_config.IgnoreUserKnownHosts) == "yes"
}

status_ol09_00_002349 := "Not_a_Finding" if { ssh_ignore_user_known_hosts } else := "Open"

finding_ol09_00_002349 := {
	"vuln_id": "V-271712",
	"stig_id": "OL09-00-002349",
	"severity": "CAT II",
	"rule_title": "OL 9 SSH daemon must not allow known hosts authentication.",
	"status": status_ol09_00_002349,
	"fix_text": "Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config",
}

# OL09-00-002352 | V-271715 | CAT II
# SSH PrintLastLog must be enabled
default ssh_print_last_log := false

ssh_print_last_log if {
	lower(input.ssh_config.PrintLastLog) == "yes"
}

status_ol09_00_002352 := "Not_a_Finding" if { ssh_print_last_log } else := "Open"

finding_ol09_00_002352 := {
	"vuln_id": "V-271715",
	"stig_id": "OL09-00-002352",
	"severity": "CAT II",
	"rule_title": "OL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon.",
	"status": status_ol09_00_002352,
	"fix_text": "Set PrintLastLog yes in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol09_00_000255,
	finding_ol09_00_002343,
	finding_ol09_00_002344,
]

cat_ii_findings := [
	finding_ol09_00_002345,
	finding_ol09_00_000251,
	finding_ol09_00_002357,
	finding_ol09_00_002347,
	finding_ol09_00_002346,
	finding_ol09_00_002351,
	finding_ol09_00_002348,
	finding_ol09_00_002349,
	finding_ol09_00_002352,
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
	"module": "ssh_config",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
