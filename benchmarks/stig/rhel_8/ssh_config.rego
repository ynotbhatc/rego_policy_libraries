# METADATA
# title: "DISA STIG for RHEL 8 - SSH Configuration Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 7
#     cited: 6
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_8.ssh_config

# DISA STIG for RHEL 8 - SSH Configuration Module
# STIG Version: V2R8 | Released: 01 Jul 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.

import rego.v1

default compliant := false

# =============================================================================
# CAT I
# =============================================================================

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-08-010291 | V-230252 | CAT I - SSH must use FIPS ciphers
default ssh_fips_ciphers := false

# DoD-approved set per the rule's fix text; every listed cipher must be in it.
approved_ciphers := {"aes256-ctr", "aes192-ctr", "aes128-ctr"}

ssh_fips_ciphers if {
	ciphers := split(input.ssh_config.Ciphers, ",")
	count(ciphers) > 0
	count([c | some c in ciphers; not trim_space(c) in approved_ciphers]) == 0
}

status_rhel_08_010291 := "Not_a_Finding" if ssh_fips_ciphers

else := "Open"

finding_rhel_08_010291 := {
	"vuln_id": "V-230252",
	"stig_id": "RHEL-08-010291",
	"severity": "CAT I",
	"rule_title": "The RHEL 8 SSH server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_rhel_08_010291,
	"fix_text": "Set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /etc/ssh/sshd_config",
}

# RHEL-08-020330 | V-230380 | CAT I - SSH must not allow empty passwords
default no_empty_passwords := false

no_empty_passwords if lower(input.ssh_config.PermitEmptyPasswords) == "no"

status_rhel_08_020330 := "Not_a_Finding" if no_empty_passwords

else := "Open"

finding_rhel_08_020330 := {
	"vuln_id": "V-230380",
	"stig_id": "RHEL-08-020330",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not allow accounts configured with blank or null passwords.",
	"status": status_rhel_08_020330,
	"fix_text": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
}

# RHEL-08-010290 | V-230251 | CAT I - SSH must use FIPS MACs
default ssh_fips_macs := false

approved_macs := {"hmac-sha2-512", "hmac-sha2-256", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"}

ssh_fips_macs if {
	macs := split(input.ssh_config.MACs, ",")
	count(macs) > 0
	count([m | some m in macs; not trim_space(m) in approved_macs]) == 0
}

status_rhel_08_010290 := "Not_a_Finding" if ssh_fips_macs

else := "Open"

finding_rhel_08_010290 := {
	"vuln_id": "V-230251",
	"stig_id": "RHEL-08-010290",
	"severity": "CAT I",
	"rule_title": "The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.",
	"status": status_rhel_08_010290,
	"fix_text": "Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-010550 | V-230296 | CAT II - SSH must not allow root login
default no_root_login := false

no_root_login if lower(input.ssh_config.PermitRootLogin) == "no"

status_rhel_08_010550 := "Not_a_Finding" if no_root_login

else := "Open"

finding_rhel_08_010550 := {
	"vuln_id": "V-230296",
	"stig_id": "RHEL-08-010550",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not permit direct logons to the root account using remote access via SSH.",
	"status": status_rhel_08_010550,
	"fix_text": "Set PermitRootLogin no in /etc/ssh/sshd_config",
}

# RHEL-08-010201 | V-244525 | CAT II - ClientAliveInterval must be 600 or less
default client_alive := false

client_alive if {
	to_number(input.ssh_config.ClientAliveInterval) <= 600
	to_number(input.ssh_config.ClientAliveInterval) > 0
}

status_rhel_08_010201 := "Not_a_Finding" if client_alive

else := "Open"

finding_rhel_08_010201 := {
	"vuln_id": "V-244525",
	"stig_id": "RHEL-08-010201",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.",
	"status": status_rhel_08_010201,
	"fix_text": "Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
}

# RHEL-08-010060 | V-230227 | CAT II - Banner must be set
default ssh_banner := false

ssh_banner if {
	input.ssh_config.Banner != ""
	input.ssh_config.Banner != "none"
}

status_rhel_08_010060 := "Not_a_Finding" if ssh_banner

else := "Open"

finding_rhel_08_010060 := {
	"vuln_id": "V-230227",
	"stig_id": "RHEL-08-010060",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.",
	"status": status_rhel_08_010060,
	"fix_text": "Set Banner /etc/issue in /etc/ssh/sshd_config",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_010291,
	finding_rhel_08_020330,
	finding_rhel_08_010290,
]

cat_ii_findings := [
	finding_rhel_08_010550,
	finding_rhel_08_010201,
	finding_rhel_08_010060,
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
