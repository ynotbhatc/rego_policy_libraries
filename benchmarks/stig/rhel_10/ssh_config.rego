# METADATA
# title: "DISA STIG for RHEL 10 - SSH Configuration Module"
# custom:
#   class: security
#   framework: stig_rhel_10
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
package stig.rhel_10.ssh_config

# DISA STIG for RHEL 10 - SSH Configuration Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/ssh_config.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: SSH daemon hardening, key exchange, MACs, ciphers

import rego.v1

default compliant := false

# =============================================================================
# SHARED HELPERS
# =============================================================================

# Shared helpers (defined in a source block whose rule RHEL 10 does not carry)

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

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-10-300040 | V-281011 | CAT I
# SSH must use FIPS-approved ciphers
default ssh_fips_ciphers := false

ssh_fips_ciphers if {
	ciphers_str := input.ssh_config.Ciphers
	ciphers := split(ciphers_str, ",")
	count([c | some c in ciphers; not c in approved_ciphers]) == 0
	count(ciphers) > 0
}

status_rhel_10_300040 := "Not_a_Finding" if ssh_fips_ciphers

else := "Open"

finding_rhel_10_300040 := {
	"vuln_id": "V-281011",
	"stig_id": "RHEL-10-300040",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must be configured so that Secure Shell (SSH) servers use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_rhel_10_300040,
	"fix_text": "Set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /etc/ssh/sshd_config",
}

# RHEL-10-300060 | V-281013 | CAT I
# SSH must use FIPS-approved MACs
default ssh_fips_macs := false

ssh_fips_macs if {
	macs_str := input.ssh_config.MACs
	macs := split(macs_str, ",")
	count([m | some m in macs; not m in approved_macs]) == 0
	count(macs) > 0
}

status_rhel_10_300060 := "Not_a_Finding" if ssh_fips_macs

else := "Open"

finding_rhel_10_300060 := {
	"vuln_id": "V-281013",
	"stig_id": "RHEL-10-300060",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must be configured so that Secure Shell (SSH) servers use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_rhel_10_300060,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# RHEL-10-600640 | V-281216 | CAT I
# SSH must use privilege separation
default ssh_use_pam := false

ssh_use_pam if {
	lower(input.ssh_config.UsePAM) == "yes"
}

status_rhel_10_600640 := "Not_a_Finding" if ssh_use_pam

else := "Open"

finding_rhel_10_600640 := {
	"vuln_id": "V-281216",
	"stig_id": "RHEL-10-600640",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must enable the Pluggable Authentication Module (PAM) interface for SSHD.",
	"status": status_rhel_10_600640,
	"fix_text": "Set UsePAM yes in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-700610 | V-281264 | CAT II
# SSH must not permit empty passwords
default ssh_no_empty_passwords := false

ssh_no_empty_passwords if {
	lower(input.ssh_config.PermitEmptyPasswords) == "no"
}

status_rhel_10_700610 := "Not_a_Finding" if ssh_no_empty_passwords

else := "Open"

finding_rhel_10_700610 := {
	"vuln_id": "V-281264",
	"stig_id": "RHEL-10-700610",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that SSHD does not allow blank passwords.",
	"status": status_rhel_10_700610,
	"fix_text": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
}

# RHEL-10-700620 | V-281265 | CAT II
# SSH must not permit root login
default ssh_no_root_login := false

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "no"
}

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "forced-commands-only"
}

status_rhel_10_700620 := "Not_a_Finding" if ssh_no_root_login

else := "Open"

finding_rhel_10_700620 := {
	"vuln_id": "V-281265",
	"stig_id": "RHEL-10-700620",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not permit direct logins to the root account using remote access via Secure Shell (SSH).",
	"status": status_rhel_10_700620,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# RHEL-10-700630 | V-281266 | CAT II
# SSH must not allow host-based authentication
default ssh_no_hostbased_auth := false

ssh_no_hostbased_auth if {
	lower(input.ssh_config.HostbasedAuthentication) == "no"
}

status_rhel_10_700630 := "Not_a_Finding" if ssh_no_hostbased_auth

else := "Open"

finding_rhel_10_700630 := {
	"vuln_id": "V-281266",
	"stig_id": "RHEL-10-700630",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not allow a noncertificate trusted host Secure Shell (SSH) login to the system.",
	"status": status_rhel_10_700630,
	"fix_text": "Set HostbasedAuthentication no in /etc/ssh/sshd_config",
}

# RHEL-10-700930 | V-281296 | CAT II
# SSH ClientAliveInterval must be 600 or less
default ssh_client_alive_interval_ok := false

ssh_client_alive_interval_ok if {
	interval := to_number(input.ssh_config.ClientAliveInterval)
	interval <= 600
	interval > 0
}

status_rhel_10_700930 := "Not_a_Finding" if ssh_client_alive_interval_ok

else := "Open"

finding_rhel_10_700930 := {
	"vuln_id": "V-281296",
	"stig_id": "RHEL-10-700930",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured with a timeout interval for the Secure Shell (SSH) daemon.",
	"status": status_rhel_10_700930,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# RHEL-10-700660 | V-281269 | CAT II
# SSH ClientAliveCountMax must be 1 or less
default ssh_client_alive_count_ok := false

ssh_client_alive_count_ok if {
	count_max := to_number(input.ssh_config.ClientAliveCountMax)
	count_max > 0 # 0 disables connection termination in sshd
	count_max <= 1
}

status_rhel_10_700660 := "Not_a_Finding" if ssh_client_alive_count_ok

else := "Open"

finding_rhel_10_700660 := {
	"vuln_id": "V-281269",
	"stig_id": "RHEL-10-700660",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that all network connections associated with Secure Shell (SSH) traffic terminate after becoming unresponsive.",
	"status": status_rhel_10_700660,
	"fix_text": "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config",
}

# RHEL-10-700560 | V-281259 | CAT II
# SSH must use strict mode
default ssh_strict_modes := false

ssh_strict_modes if {
	lower(input.ssh_config.StrictModes) == "yes"
}

status_rhel_10_700560 := "Not_a_Finding" if ssh_strict_modes

else := "Open"

finding_rhel_10_700560 := {
	"vuln_id": "V-281259",
	"stig_id": "RHEL-10-700560",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that the Secure Shell (SSH) daemon performs strict mode checking of home directory configuration files.",
	"status": status_rhel_10_700560,
	"fix_text": "Set StrictModes yes in /etc/ssh/sshd_config",
}

# RHEL-10-700530 | V-281256 | CAT II
# SSH must disable rhosts authentication
default ssh_ignore_rhosts := false

ssh_ignore_rhosts if {
	lower(input.ssh_config.IgnoreRhosts) == "yes"
}

status_rhel_10_700530 := "Not_a_Finding" if ssh_ignore_rhosts

else := "Open"

finding_rhel_10_700530 := {
	"vuln_id": "V-281256",
	"stig_id": "RHEL-10-700530",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that the Secure Shell (SSH) daemon does not allow rhosts authentication.",
	"status": status_rhel_10_700530,
	"fix_text": "Set IgnoreRhosts yes in /etc/ssh/sshd_config",
}

# RHEL-10-700540 | V-281257 | CAT II
# SSH must not allow .shosts
default ssh_ignore_user_known_hosts := false

ssh_ignore_user_known_hosts if {
	lower(input.ssh_config.IgnoreUserKnownHosts) == "yes"
}

status_rhel_10_700540 := "Not_a_Finding" if ssh_ignore_user_known_hosts

else := "Open"

finding_rhel_10_700540 := {
	"vuln_id": "V-281257",
	"stig_id": "RHEL-10-700540",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that the Secure Shell (SSH) daemon does not allow known hosts authentication.",
	"status": status_rhel_10_700540,
	"fix_text": "Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config",
}

# RHEL-10-700570 | V-281260 | CAT II
# SSH PrintLastLog must be enabled
default ssh_print_last_log := false

ssh_print_last_log if {
	lower(input.ssh_config.PrintLastLog) == "yes"
}

status_rhel_10_700570 := "Not_a_Finding" if ssh_print_last_log

else := "Open"

finding_rhel_10_700570 := {
	"vuln_id": "V-281260",
	"stig_id": "RHEL-10-700570",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that the Secure Shell (SSH) daemon displays the date and time of the last successful account login upon an SSH login.",
	"status": status_rhel_10_700570,
	"fix_text": "Set PrintLastLog yes in /etc/ssh/sshd_config",
}

# RHEL-10-700550 | V-281258 | CAT II
# SSH X11Forwarding must be disabled
default ssh_no_x11 := false

ssh_no_x11 if {
	lower(input.ssh_config.X11Forwarding) == "no"
}

status_rhel_10_700550 := "Not_a_Finding" if ssh_no_x11

else := "Open"

finding_rhel_10_700550 := {
	"vuln_id": "V-281258",
	"stig_id": "RHEL-10-700550",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must be configured so that the Secure Shell (SSH) daemon disables remote X connections for interactive users.",
	"status": status_rhel_10_700550,
	"fix_text": "Set X11Forwarding no in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_10_300040,
	finding_rhel_10_300060,
	finding_rhel_10_600640,
]

cat_ii_findings := [
	finding_rhel_10_700610,
	finding_rhel_10_700620,
	finding_rhel_10_700630,
	finding_rhel_10_700930,
	finding_rhel_10_700660,
	finding_rhel_10_700560,
	finding_rhel_10_700530,
	finding_rhel_10_700540,
	finding_rhel_10_700570,
	finding_rhel_10_700550,
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

# `compliant`: no open finding at ANY category (CAT I, II or III), as in the RHEL 8/9 modules.
# `cat_i_compliant`: the CAT-I-only meaning, for gating on the critical subset.
open_all_findings := [f | some f in findings; f.status == "Open"]

compliant if {
	count(open_all_findings) == 0
}

default cat_i_compliant := false

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
