# METADATA
# title: "DISA STIG for RHEL 8 - Account and Authentication Module"
# custom:
#   class: security
#   framework: stig_rhel_8
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 10
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_8.account_auth

# DISA STIG for RHEL 8 - Account and Authentication Module
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

# RHEL-08-010121 | V-251706 | CAT I - No empty passwords
default no_empty_passwords := false

no_empty_passwords if {
	is_array(input.local_accounts_with_empty_passwords)
	count(input.local_accounts_with_empty_passwords) == 0
}

status_rhel_08_010121 := "Not_a_Finding" if no_empty_passwords

else := "Open"

finding_rhel_08_010121 := {
	"vuln_id": "V-251706",
	"stig_id": "RHEL-08-010121",
	"severity": "CAT I",
	"rule_title": "The RHEL 8 operating system must not have accounts configured with blank or null passwords.",
	"status": status_rhel_08_010121,
	"fix_text": "Lock empty password accounts: passwd -l <username>",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-08-020250 | V-230372 | CAT II - MFA must be used
default mfa_enabled := false

mfa_enabled if input.pam_config.mfa_enabled == true
mfa_enabled if input.pam_config.sssd_mfa == true

status_rhel_08_020250 := "Not_a_Finding" if mfa_enabled

else := "Open"

finding_rhel_08_020250 := {
	"vuln_id": "V-230372",
	"stig_id": "RHEL-08-020250",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts.",
	"status": status_rhel_08_020250,
	"fix_text": "Configure MFA via SSSD with PIV/CAC",
}

# RHEL-08-020010 | V-230332 | CAT II - Accounts must lock after 3 failed attempts
default account_lockout := false

account_lockout if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_rhel_08_020010 := "Not_a_Finding" if account_lockout

else := "Open"

finding_rhel_08_020010 := {
	"vuln_id": "V-230332",
	"stig_id": "RHEL-08-020010",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur.",
	"status": status_rhel_08_020010,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# RHEL-08-010110 | V-230231 | CAT II - Passwords must be SHA-512
default password_sha512 := false

password_sha512 if input.password_policy.sha512 == true
password_sha512 if input.pam_config.password_hash == "sha512"

status_rhel_08_010110 := "Not_a_Finding" if password_sha512

else := "Open"

finding_rhel_08_010110 := {
	"vuln_id": "V-230231",
	"stig_id": "RHEL-08-010110",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.",
	"status": status_rhel_08_010110,
	"fix_text": "Configure SHA-512 in PAM: pam_unix.so sha512",
}

# RHEL-08-020230 | V-230369 | CAT II - Password minimum length 15
default password_minlen := false

password_minlen if input.password_policy.minlen >= 15

status_rhel_08_020230 := "Not_a_Finding" if password_minlen

else := "Open"

finding_rhel_08_020230 := {
	"vuln_id": "V-230369",
	"stig_id": "RHEL-08-020230",
	"severity": "CAT II",
	"rule_title": "RHEL 8 passwords must have a minimum of 15 characters.",
	"status": status_rhel_08_020230,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# RHEL-08-020200 | V-230366 | CAT II - Password max age 60 days
default password_maxage := false

password_maxage if {
	input.password_policy.maxdays <= 60
	input.password_policy.maxdays > 0
}

status_rhel_08_020200 := "Not_a_Finding" if password_maxage

else := "Open"

finding_rhel_08_020200 := {
	"vuln_id": "V-230366",
	"stig_id": "RHEL-08-020200",
	"severity": "CAT II",
	"rule_title": "RHEL 8 user account passwords must have a 60-day maximum password lifetime restriction.",
	"status": status_rhel_08_020200,
	"fix_text": "Set PASS_MAX_DAYS 60 in /etc/login.defs",
}

# RHEL-08-020012 | V-230334 | CAT II - Lockout time 15 minutes
default lockout_duration := false

lockout_duration if input.pam_config.lockout_time >= 900

status_rhel_08_020012 := "Not_a_Finding" if lockout_duration

else := "Open"

finding_rhel_08_020012 := {
	"vuln_id": "V-230334",
	"stig_id": "RHEL-08-020012",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.",
	"status": status_rhel_08_020012,
	"fix_text": "Set unlock_time=900 in /etc/security/faillock.conf",
}

# RHEL-08-020260 | V-230373 | CAT II - Inactive accounts lock after 35 days
default inactive_lock := false

inactive_lock if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_rhel_08_020260 := "Not_a_Finding" if inactive_lock

else := "Open"

finding_rhel_08_020260 := {
	"vuln_id": "V-230373",
	"stig_id": "RHEL-08-020260",
	"severity": "CAT II",
	"rule_title": "RHEL 8 account identifiers (individuals, groups, roles, and devices) must be disabled after 35 days of inactivity.",
	"status": status_rhel_08_020260,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# RHEL-08-020240 | V-230371 | CAT II - No duplicate UIDs
default no_dup_uids := false

no_dup_uids if {
	is_array(input.duplicate_uids)
	count(input.duplicate_uids) == 0
}

status_rhel_08_020240 := "Not_a_Finding" if no_dup_uids

else := "Open"

finding_rhel_08_020240 := {
	"vuln_id": "V-230371",
	"stig_id": "RHEL-08-020240",
	"severity": "CAT II",
	"rule_title": "RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users.",
	"status": status_rhel_08_020240,
	"fix_text": "Resolve duplicate UIDs in /etc/passwd",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [finding_rhel_08_010121]

cat_ii_findings := [
	finding_rhel_08_020250,
	finding_rhel_08_020010,
	finding_rhel_08_010110,
	finding_rhel_08_020230,
	finding_rhel_08_020200,
	finding_rhel_08_020012,
	finding_rhel_08_020260,
	finding_rhel_08_020240,
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
	"module": "account_auth",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
