# METADATA
# title: "DISA STIG for RHEL 9 - SSH Configuration Module"
# custom:
#   class: security
#   framework: stig_rhel_9
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 14
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_9.ssh_config

# DISA STIG for RHEL 9 - SSH Configuration Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: SSH daemon hardening, key exchange, MACs, ciphers

import rego.v1

default compliant := false

# Approved ciphers for FIPS compliance
approved_ciphers := {
	"aes256-gcm@openssh.com",
	"aes128-gcm@openssh.com",
	"aes256-ctr",
	"aes192-ctr",
	"aes128-ctr",
}

# Approved MACs
approved_macs := {
	"hmac-sha2-512",
	"hmac-sha2-256",
	"hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256-etm@openssh.com",
}

# Approved key exchange algorithms
approved_kex := {
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group-exchange-sha256",
	"diffie-hellman-group14-sha256",
}

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-255065 | V-257989 | CAT I
# SSH must use FIPS-approved ciphers
default ssh_fips_ciphers := false

ssh_fips_ciphers if {
	ciphers_str := input.ssh_config.Ciphers
	ciphers := split(ciphers_str, ",")
	count([c | some c in ciphers; not c in approved_ciphers]) == 0
	count(ciphers) > 0
}

status_rhel_09_255065 := "Not_a_Finding" if ssh_fips_ciphers

else := "Open"

finding_rhel_09_255065 := {
	"vuln_id": "V-257989",
	"stig_id": "RHEL-09-255065",
	"severity": "CAT I",
	"rule_title": "The RHEL 9 SSH server must be configured to use only DoW-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_rhel_09_255065,
	"fix_text": "Set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /etc/ssh/sshd_config",
}

# RHEL-09-255075 | V-257991 | CAT I
# SSH must use FIPS-approved MACs
default ssh_fips_macs := false

ssh_fips_macs if {
	macs_str := input.ssh_config.MACs
	macs := split(macs_str, ",")
	count([m | some m in macs; not m in approved_macs]) == 0
	count(macs) > 0
}

status_rhel_09_255075 := "Not_a_Finding" if ssh_fips_macs

else := "Open"

finding_rhel_09_255075 := {
	"vuln_id": "V-257991",
	"stig_id": "RHEL-09-255075",
	"severity": "CAT I",
	"rule_title": "The RHEL 9 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_rhel_09_255075,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# RHEL-09-255040 | V-257984 | CAT I
# SSH must not permit empty passwords
default ssh_no_empty_passwords := false

ssh_no_empty_passwords if {
	lower(input.ssh_config.PermitEmptyPasswords) == "no"
}

status_rhel_09_255040 := "Not_a_Finding" if ssh_no_empty_passwords

else := "Open"

finding_rhel_09_255040 := {
	"vuln_id": "V-257984",
	"stig_id": "RHEL-09-255040",
	"severity": "CAT I",
	"rule_title": "RHEL 9 SSHD must not allow blank passwords.",
	"status": status_rhel_09_255040,
	"fix_text": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
}

# RHEL-09-255050 | V-257986 | CAT I
# SSH must use privilege separation
default ssh_use_pam := false

ssh_use_pam if {
	lower(input.ssh_config.UsePAM) == "yes"
}

status_rhel_09_255050 := "Not_a_Finding" if ssh_use_pam

else := "Open"

finding_rhel_09_255050 := {
	"vuln_id": "V-257986",
	"stig_id": "RHEL-09-255050",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must enable the Pluggable Authentication Module (PAM) interface for SSHD.",
	"status": status_rhel_09_255050,
	"fix_text": "Set UsePAM yes in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-255045 | V-257985 | CAT II
# SSH must not permit root login
default ssh_no_root_login := false

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "no"
}

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "forced-commands-only"
}

status_rhel_09_255045 := "Not_a_Finding" if ssh_no_root_login

else := "Open"

finding_rhel_09_255045 := {
	"vuln_id": "V-257985",
	"stig_id": "RHEL-09-255045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not permit direct logons to the root account using remote access via SSH.",
	"status": status_rhel_09_255045,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# RHEL-09-255080 | V-257992 | CAT II
# SSH must not allow host-based authentication
default ssh_no_hostbased_auth := false

ssh_no_hostbased_auth if {
	lower(input.ssh_config.HostbasedAuthentication) == "no"
}

status_rhel_09_255080 := "Not_a_Finding" if ssh_no_hostbased_auth

else := "Open"

finding_rhel_09_255080 := {
	"vuln_id": "V-257992",
	"stig_id": "RHEL-09-255080",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not allow a noncertificate trusted host SSH logon to the system.",
	"status": status_rhel_09_255080,
	"fix_text": "Set HostbasedAuthentication no in /etc/ssh/sshd_config",
}

# RHEL-09-255100 | V-257996 | CAT II
# SSH ClientAliveInterval must be 600 or less
default ssh_client_alive_interval_ok := false

ssh_client_alive_interval_ok if {
	interval := to_number(input.ssh_config.ClientAliveInterval)
	interval <= 600
	interval > 0
}

status_rhel_09_255100 := "Not_a_Finding" if ssh_client_alive_interval_ok

else := "Open"

finding_rhel_09_255100 := {
	"vuln_id": "V-257996",
	"stig_id": "RHEL-09-255100",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.",
	"status": status_rhel_09_255100,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# RHEL-09-255095 | V-257995 | CAT II
# SSH ClientAliveCountMax must be 1 or less
default ssh_client_alive_count_ok := false

ssh_client_alive_count_ok if {
	count_max := to_number(input.ssh_config.ClientAliveCountMax)
	count_max > 0 # 0 disables connection termination in sshd
	count_max <= 1
}

status_rhel_09_255095 := "Not_a_Finding" if ssh_client_alive_count_ok

else := "Open"

finding_rhel_09_255095 := {
	"vuln_id": "V-257995",
	"stig_id": "RHEL-09-255095",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.",
	"status": status_rhel_09_255095,
	"fix_text": "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config",
}

# RHEL-09-255160 | V-258008 | CAT II
# SSH must use strict mode
default ssh_strict_modes := false

ssh_strict_modes if {
	lower(input.ssh_config.StrictModes) == "yes"
}

status_rhel_09_255160 := "Not_a_Finding" if ssh_strict_modes

else := "Open"

finding_rhel_09_255160 := {
	"vuln_id": "V-258008",
	"stig_id": "RHEL-09-255160",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files.",
	"status": status_rhel_09_255160,
	"fix_text": "Set StrictModes yes in /etc/ssh/sshd_config",
}

# RHEL-09-255145 | V-258005 | CAT II
# SSH must disable rhosts authentication
default ssh_ignore_rhosts := false

ssh_ignore_rhosts if {
	lower(input.ssh_config.IgnoreRhosts) == "yes"
}

status_rhel_09_255145 := "Not_a_Finding" if ssh_ignore_rhosts

else := "Open"

finding_rhel_09_255145 := {
	"vuln_id": "V-258005",
	"stig_id": "RHEL-09-255145",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must not allow rhosts authentication.",
	"status": status_rhel_09_255145,
	"fix_text": "Set IgnoreRhosts yes in /etc/ssh/sshd_config",
}

# RHEL-09-255150 | V-258006 | CAT II
# SSH must not allow .shosts
default ssh_ignore_user_known_hosts := false

ssh_ignore_user_known_hosts if {
	lower(input.ssh_config.IgnoreUserKnownHosts) == "yes"
}

status_rhel_09_255150 := "Not_a_Finding" if ssh_ignore_user_known_hosts

else := "Open"

finding_rhel_09_255150 := {
	"vuln_id": "V-258006",
	"stig_id": "RHEL-09-255150",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must not allow known hosts authentication.",
	"status": status_rhel_09_255150,
	"fix_text": "Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config",
}

# RHEL-09-255165 | V-258009 | CAT II
# SSH PrintLastLog must be enabled
default ssh_print_last_log := false

ssh_print_last_log if {
	lower(input.ssh_config.PrintLastLog) == "yes"
}

status_rhel_09_255165 := "Not_a_Finding" if ssh_print_last_log

else := "Open"

finding_rhel_09_255165 := {
	"vuln_id": "V-258009",
	"stig_id": "RHEL-09-255165",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon.",
	"status": status_rhel_09_255165,
	"fix_text": "Set PrintLastLog yes in /etc/ssh/sshd_config",
}

# RHEL-09-255155 | V-258007 | CAT II
# SSH X11Forwarding must be disabled
default ssh_no_x11 := false

ssh_no_x11 if {
	lower(input.ssh_config.X11Forwarding) == "no"
}

status_rhel_09_255155 := "Not_a_Finding" if ssh_no_x11

else := "Open"

finding_rhel_09_255155 := {
	"vuln_id": "V-258007",
	"stig_id": "RHEL-09-255155",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must disable remote X connections for interactive users.",
	"status": status_rhel_09_255155,
	"fix_text": "Set X11Forwarding no in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_255065,
	finding_rhel_09_255075,
	finding_rhel_09_255040,
	finding_rhel_09_255050,
]

cat_ii_findings := [
	finding_rhel_09_255045,
	finding_rhel_09_255080,
	finding_rhel_09_255100,
	finding_rhel_09_255095,
	finding_rhel_09_255160,
	finding_rhel_09_255145,
	finding_rhel_09_255150,
	finding_rhel_09_255165,
	finding_rhel_09_255155,
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
	"module": "ssh_config",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
