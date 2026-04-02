package stig.rhel_9.ssh_config

# DISA STIG for RHEL 9 - SSH Configuration Module
# STIG Version: V2R2 | Released: October 2024
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

# RHEL-09-255010 | V-257985 | CAT I
# SSH must not permit root login
default ssh_no_root_login := false

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "no"
}

ssh_no_root_login if {
	lower(input.ssh_config.PermitRootLogin) == "forced-commands-only"
}

status_rhel_09_255010 := "Not_a_Finding" if { ssh_no_root_login } else := "Open"

finding_rhel_09_255010 := {
	"vuln_id": "V-257985",
	"stig_id": "RHEL-09-255010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not permit direct logons to the root account using remote access via SSH",
	"status": status_rhel_09_255010,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# RHEL-09-255015 | V-257986 | CAT I
# SSH protocol must be 2
default ssh_protocol_2 := false

ssh_protocol_2 if {
	input.ssh_config.Protocol == "2"
}

ssh_protocol_2 if {
	not input.ssh_config.Protocol  # Protocol 2 is default in OpenSSH 7+
}

status_rhel_09_255015 := "Not_a_Finding" if { ssh_protocol_2 } else := "Open"

finding_rhel_09_255015 := {
	"vuln_id": "V-257986",
	"stig_id": "RHEL-09-255015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must use SSH to protect the confidentiality and integrity of transmitted information",
	"status": status_rhel_09_255015,
	"fix_text": "Ensure Protocol 2 is configured (or remove Protocol line for modern OpenSSH)",
}

# RHEL-09-255020 | V-257987 | CAT I
# SSH must use FIPS-approved ciphers
default ssh_fips_ciphers := false

ssh_fips_ciphers if {
	ciphers_str := input.ssh_config.Ciphers
	ciphers := split(ciphers_str, ",")
	count([c | some c in ciphers; not c in approved_ciphers]) == 0
	count(ciphers) > 0
}

status_rhel_09_255020 := "Not_a_Finding" if { ssh_fips_ciphers } else := "Open"

finding_rhel_09_255020 := {
	"vuln_id": "V-257987",
	"stig_id": "RHEL-09-255020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement DoD-approved encryption in the OpenSSH client",
	"status": status_rhel_09_255020,
	"fix_text": "Set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-255025 | V-257988 | CAT II
# SSH must use FIPS-approved MACs
default ssh_fips_macs := false

ssh_fips_macs if {
	macs_str := input.ssh_config.MACs
	macs := split(macs_str, ",")
	count([m | some m in macs; not m in approved_macs]) == 0
	count(macs) > 0
}

status_rhel_09_255025 := "Not_a_Finding" if { ssh_fips_macs } else := "Open"

finding_rhel_09_255025 := {
	"vuln_id": "V-257988",
	"stig_id": "RHEL-09-255025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms",
	"status": status_rhel_09_255025,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# RHEL-09-255030 | V-257989 | CAT II
# SSH must not permit empty passwords
default ssh_no_empty_passwords := false

ssh_no_empty_passwords if {
	lower(input.ssh_config.PermitEmptyPasswords) == "no"
}

status_rhel_09_255030 := "Not_a_Finding" if { ssh_no_empty_passwords } else := "Open"

finding_rhel_09_255030 := {
	"vuln_id": "V-257989",
	"stig_id": "RHEL-09-255030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not allow blank or null passwords in the SSH daemon",
	"status": status_rhel_09_255030,
	"fix_text": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
}

# RHEL-09-255035 | V-257990 | CAT II
# SSH must not allow host-based authentication
default ssh_no_hostbased_auth := false

ssh_no_hostbased_auth if {
	lower(input.ssh_config.HostbasedAuthentication) == "no"
}

status_rhel_09_255035 := "Not_a_Finding" if { ssh_no_hostbased_auth } else := "Open"

finding_rhel_09_255035 := {
	"vuln_id": "V-257990",
	"stig_id": "RHEL-09-255035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not allow a non-certificate trusted host SSH logon to the system",
	"status": status_rhel_09_255035,
	"fix_text": "Set HostbasedAuthentication no in /etc/ssh/sshd_config",
}

# RHEL-09-255040 | V-257991 | CAT II
# SSH MaxAuthTries must be 4 or less
default ssh_max_auth_tries_ok := false

ssh_max_auth_tries_ok if {
	tries := to_number(input.ssh_config.MaxAuthTries)
	tries <= 4
}

status_rhel_09_255040 := "Not_a_Finding" if { ssh_max_auth_tries_ok } else := "Open"

finding_rhel_09_255040 := {
	"vuln_id": "V-257991",
	"stig_id": "RHEL-09-255040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must limit the number of SSH connection attempts",
	"status": status_rhel_09_255040,
	"fix_text": "Set MaxAuthTries 4 in /etc/ssh/sshd_config",
}

# RHEL-09-255045 | V-257992 | CAT II
# SSH ClientAliveInterval must be 600 or less
default ssh_client_alive_interval_ok := false

ssh_client_alive_interval_ok if {
	interval := to_number(input.ssh_config.ClientAliveInterval)
	interval <= 600
	interval > 0
}

status_rhel_09_255045 := "Not_a_Finding" if { ssh_client_alive_interval_ok } else := "Open"

finding_rhel_09_255045 := {
	"vuln_id": "V-257992",
	"stig_id": "RHEL-09-255045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must set SSH client alive count max to 1",
	"status": status_rhel_09_255045,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# RHEL-09-255050 | V-257993 | CAT II
# SSH ClientAliveCountMax must be 1 or less
default ssh_client_alive_count_ok := false

ssh_client_alive_count_ok if {
	count_max := to_number(input.ssh_config.ClientAliveCountMax)
	count_max <= 1
}

status_rhel_09_255050 := "Not_a_Finding" if { ssh_client_alive_count_ok } else := "Open"

finding_rhel_09_255050 := {
	"vuln_id": "V-257993",
	"stig_id": "RHEL-09-255050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH client alive count max must be set to 1",
	"status": status_rhel_09_255050,
	"fix_text": "Set ClientAliveCountMax 1 in /etc/ssh/sshd_config",
}

# RHEL-09-255055 | V-257994 | CAT II
# SSH must use strict mode
default ssh_strict_modes := false

ssh_strict_modes if {
	lower(input.ssh_config.StrictModes) == "yes"
}

status_rhel_09_255055 := "Not_a_Finding" if { ssh_strict_modes } else := "Open"

finding_rhel_09_255055 := {
	"vuln_id": "V-257994",
	"stig_id": "RHEL-09-255055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files",
	"status": status_rhel_09_255055,
	"fix_text": "Set StrictModes yes in /etc/ssh/sshd_config",
}

# RHEL-09-255060 | V-257995 | CAT II
# SSH must not use compression
default ssh_no_compression := false

ssh_no_compression if {
	lower(input.ssh_config.Compression) == "no"
}

status_rhel_09_255060 := "Not_a_Finding" if { ssh_no_compression } else := "Open"

finding_rhel_09_255060 := {
	"vuln_id": "V-257995",
	"stig_id": "RHEL-09-255060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must not allow compression",
	"status": status_rhel_09_255060,
	"fix_text": "Set Compression no in /etc/ssh/sshd_config",
}

# RHEL-09-255065 | V-257996 | CAT II
# SSH must disable rhosts authentication
default ssh_ignore_rhosts := false

ssh_ignore_rhosts if {
	lower(input.ssh_config.IgnoreRhosts) == "yes"
}

status_rhel_09_255065 := "Not_a_Finding" if { ssh_ignore_rhosts } else := "Open"

finding_rhel_09_255065 := {
	"vuln_id": "V-257996",
	"stig_id": "RHEL-09-255065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must ignore .rhosts files",
	"status": status_rhel_09_255065,
	"fix_text": "Set IgnoreRhosts yes in /etc/ssh/sshd_config",
}

# RHEL-09-255070 | V-257997 | CAT II
# SSH must not allow .shosts
default ssh_ignore_user_known_hosts := false

ssh_ignore_user_known_hosts if {
	lower(input.ssh_config.IgnoreUserKnownHosts) == "yes"
}

status_rhel_09_255070 := "Not_a_Finding" if { ssh_ignore_user_known_hosts } else := "Open"

finding_rhel_09_255070 := {
	"vuln_id": "V-257997",
	"stig_id": "RHEL-09-255070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must not allow known hosts for authentication",
	"status": status_rhel_09_255070,
	"fix_text": "Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config",
}

# RHEL-09-255075 | V-257998 | CAT II
# SSH must use privilege separation
default ssh_use_pam := false

ssh_use_pam if {
	lower(input.ssh_config.UsePAM) == "yes"
}

status_rhel_09_255075 := "Not_a_Finding" if { ssh_use_pam } else := "Open"

finding_rhel_09_255075 := {
	"vuln_id": "V-257998",
	"stig_id": "RHEL-09-255075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable the Pluggable Authentication Modules (PAM) for SSH",
	"status": status_rhel_09_255075,
	"fix_text": "Set UsePAM yes in /etc/ssh/sshd_config",
}

# RHEL-09-255080 | V-257999 | CAT II
# SSH PrintLastLog must be enabled
default ssh_print_last_log := false

ssh_print_last_log if {
	lower(input.ssh_config.PrintLastLog) == "yes"
}

status_rhel_09_255080 := "Not_a_Finding" if { ssh_print_last_log } else := "Open"

finding_rhel_09_255080 := {
	"vuln_id": "V-257999",
	"stig_id": "RHEL-09-255080",
	"severity": "CAT II",
	"rule_title": "RHEL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon",
	"status": status_rhel_09_255080,
	"fix_text": "Set PrintLastLog yes in /etc/ssh/sshd_config",
}

# RHEL-09-255085 | V-258000 | CAT II
# SSH X11Forwarding must be disabled
default ssh_no_x11 := false

ssh_no_x11 if {
	lower(input.ssh_config.X11Forwarding) == "no"
}

status_rhel_09_255085 := "Not_a_Finding" if { ssh_no_x11 } else := "Open"

finding_rhel_09_255085 := {
	"vuln_id": "V-258000",
	"stig_id": "RHEL-09-255085",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable X11 Forwarding for SSH unless mission requires",
	"status": status_rhel_09_255085,
	"fix_text": "Set X11Forwarding no in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_255010,
	finding_rhel_09_255015,
	finding_rhel_09_255020,
]

cat_ii_findings := [
	finding_rhel_09_255025,
	finding_rhel_09_255030,
	finding_rhel_09_255035,
	finding_rhel_09_255040,
	finding_rhel_09_255045,
	finding_rhel_09_255050,
	finding_rhel_09_255055,
	finding_rhel_09_255060,
	finding_rhel_09_255065,
	finding_rhel_09_255070,
	finding_rhel_09_255075,
	finding_rhel_09_255080,
	finding_rhel_09_255085,
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
