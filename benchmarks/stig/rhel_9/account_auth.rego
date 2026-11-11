# METADATA
# title: "DISA STIG for RHEL 9 - Account and Authentication Module"
# custom:
#   class: security
#   framework: stig_rhel_9
#   source: disa
#   domains: [linux, rhel]
#   coverage:
#     checks: 16
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.rhel_9.account_auth

# DISA STIG for RHEL 9 - Account and Authentication Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Rule ids, vuln ids, severities and titles stamped from the October 2026 SRG-STIG library XCCDF on 2026-11-10
# (tools/stig_generators/stamp_catalog.py); each finding is keyed on the fact its logic checks.
# Covers: Password policy, PAM, account lockout, MFA, inactivity

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-611165 | V-258122 | CAT II
# Multifactor authentication must be used
default mfa_enabled := false

mfa_enabled if {
	input.pam_config.mfa_enabled == true
}

mfa_enabled if {
	input.pam_config.sssd_mfa == true
}

status_rhel_09_611165 := "Not_a_Finding" if mfa_enabled

else := "Open"

finding_rhel_09_611165 := {
	"vuln_id": "V-258122",
	"stig_id": "RHEL-09-611165",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable certificate based smart card authentication.",
	"status": status_rhel_09_611165,
	"fix_text": "Configure MFA via SSSD with smart card or PIV authentication",
}

# RHEL-09-611140 | V-258117 | CAT II
# Passwords must be hashed with SHA-512
default password_sha512 := false

password_sha512 if {
	input.password_policy.sha512 == true
}

password_sha512 if {
	input.pam_config.password_hash == "sha512"
}

status_rhel_09_611140 := "Not_a_Finding" if password_sha512

else := "Open"

finding_rhel_09_611140 := {
	"vuln_id": "V-258117",
	"stig_id": "RHEL-09-611140",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must be configured to use the shadow file to store only encrypted representations of passwords.",
	"status": status_rhel_09_611140,
	"fix_text": "Configure PAM to use SHA-512: Set password sufficient pam_unix.so sha512 in /etc/pam.d/system-auth",
}

# RHEL-09-411075 | V-258054 | CAT II
# Accounts must be locked after failed login attempts
default account_lockout_enabled := false

account_lockout_enabled if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_rhel_09_411075 := "Not_a_Finding" if account_lockout_enabled

else := "Open"

finding_rhel_09_411075 := {
	"vuln_id": "V-258054",
	"stig_id": "RHEL-09-411075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur.",
	"status": status_rhel_09_411075,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# RHEL-09-611155 | V-258120 | CAT II
# System must not have empty passwords in /etc/shadow
default no_empty_password_hashes := false

no_empty_password_hashes if {
	count(input.local_accounts_with_empty_passwords) == 0
}

no_empty_password_hashes if {
	not input.local_accounts_with_empty_passwords
}

status_rhel_09_611155 := "Not_a_Finding" if no_empty_password_hashes

else := "Open"

finding_rhel_09_611155 := {
	"vuln_id": "V-258120",
	"stig_id": "RHEL-09-611155",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not have accounts configured with blank or null passwords.",
	"status": status_rhel_09_611155,
	"fix_text": "Lock accounts with empty passwords: passwd -l <username>",
}

# RHEL-09-611090 | V-258107 | CAT II
# Password minimum length must be 15
default password_minlen := false

password_minlen if {
	input.password_policy.minlen >= 15
}

status_rhel_09_611090 := "Not_a_Finding" if password_minlen

else := "Open"

finding_rhel_09_611090 := {
	"vuln_id": "V-258107",
	"stig_id": "RHEL-09-611090",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must be created with a minimum of 15 characters.",
	"status": status_rhel_09_611090,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# RHEL-09-611110 | V-258111 | CAT II
# Password must require at least 1 uppercase character
default password_uppercase := false

password_uppercase if {
	input.password_policy.ucredit <= -1
}

password_uppercase if {
	input.password_policy.minclass >= 4
}

status_rhel_09_611110 := "Not_a_Finding" if password_uppercase

else := "Open"

finding_rhel_09_611110 := {
	"vuln_id": "V-258111",
	"stig_id": "RHEL-09-611110",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enforce password complexity by requiring that at least one uppercase character be used.",
	"status": status_rhel_09_611110,
	"fix_text": "Set ucredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611065 | V-258102 | CAT II
# Password must require at least 1 lowercase character
default password_lowercase := false

password_lowercase if {
	input.password_policy.lcredit <= -1
}

password_lowercase if {
	input.password_policy.minclass >= 4
}

status_rhel_09_611065 := "Not_a_Finding" if password_lowercase

else := "Open"

finding_rhel_09_611065 := {
	"vuln_id": "V-258102",
	"stig_id": "RHEL-09-611065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enforce password complexity by requiring that at least one lowercase character be used.",
	"status": status_rhel_09_611065,
	"fix_text": "Set lcredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611070 | V-258103 | CAT II
# Password must require at least 1 numeric character
default password_numeric := false

password_numeric if {
	input.password_policy.dcredit <= -1
}

password_numeric if {
	input.password_policy.minclass >= 4
}

status_rhel_09_611070 := "Not_a_Finding" if password_numeric

else := "Open"

finding_rhel_09_611070 := {
	"vuln_id": "V-258103",
	"stig_id": "RHEL-09-611070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enforce password complexity by requiring that at least one numeric character be used.",
	"status": status_rhel_09_611070,
	"fix_text": "Set dcredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611100 | V-258109 | CAT II
# Password must require at least 1 special character
default password_special := false

password_special if {
	input.password_policy.ocredit <= -1
}

status_rhel_09_611100 := "Not_a_Finding" if password_special

else := "Open"

finding_rhel_09_611100 := {
	"vuln_id": "V-258109",
	"stig_id": "RHEL-09-611100",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enforce password complexity by requiring that at least one special character be used.",
	"status": status_rhel_09_611100,
	"fix_text": "Set ocredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-411010 | V-258041 | CAT II
# Password maximum age must be 60 days or less
default password_maxage := false

password_maxage if {
	input.password_policy.maxdays <= 60
	input.password_policy.maxdays > 0
}

status_rhel_09_411010 := "Not_a_Finding" if password_maxage

else := "Open"

finding_rhel_09_411010 := {
	"vuln_id": "V-258041",
	"stig_id": "RHEL-09-411010",
	"severity": "CAT II",
	"rule_title": "RHEL 9 user account passwords for new users or password changes must have a 180-day maximum password lifetime restriction in /etc/login.defs.",
	"status": status_rhel_09_411010,
	"fix_text": "Set PASS_MAX_DAYS 60 in /etc/login.defs",
}

# RHEL-09-611075 | V-258104 | CAT II
# Password minimum age must be 1 day
default password_minage := false

password_minage if {
	input.password_policy.mindays >= 1
}

status_rhel_09_611075 := "Not_a_Finding" if password_minage

else := "Open"

finding_rhel_09_611075 := {
	"vuln_id": "V-258104",
	"stig_id": "RHEL-09-611075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords for new users or password changes must have a 24 hours minimum password lifetime restriction in /etc/login.defs.",
	"status": status_rhel_09_611075,
	"fix_text": "Set PASS_MIN_DAYS 1 in /etc/login.defs",
}

# RHEL-09-411085 | V-258056 | CAT II
# Account lockout time must be at least 15 minutes
default lockout_duration_ok := false

lockout_duration_ok if {
	input.pam_config.lockout_time >= 900 # 900 seconds = 15 minutes
}

status_rhel_09_411085 := "Not_a_Finding" if lockout_duration_ok

else := "Open"

finding_rhel_09_411085 := {
	"vuln_id": "V-258056",
	"stig_id": "RHEL-09-411085",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.",
	"status": status_rhel_09_411085,
	"fix_text": "Set unlock_time=900 in /etc/security/faillock.conf",
}

# RHEL-09-411050 | V-258049 | CAT II
# Inactive accounts must be disabled after 35 days
default inactive_lock_ok := false

inactive_lock_ok if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_rhel_09_411050 := "Not_a_Finding" if inactive_lock_ok

else := "Open"

finding_rhel_09_411050 := {
	"vuln_id": "V-258049",
	"stig_id": "RHEL-09-411050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.",
	"status": status_rhel_09_411050,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# RHEL-09-411030 | V-258045 | CAT II
# No duplicate UIDs should exist
default no_duplicate_uids := false

no_duplicate_uids if {
	count(input.duplicate_uids) == 0
}

no_duplicate_uids if {
	not input.duplicate_uids
}

status_rhel_09_411030 := "Not_a_Finding" if no_duplicate_uids

else := "Open"

finding_rhel_09_411030 := {
	"vuln_id": "V-258045",
	"stig_id": "RHEL-09-411030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 duplicate User IDs (UIDs) must not exist for interactive users.",
	"status": status_rhel_09_411030,
	"fix_text": "Identify and resolve duplicate UIDs: awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d",
}

# RHEL-09-411110 | V-258061 | CAT II
# No duplicate GIDs should exist
default no_duplicate_gids := false

no_duplicate_gids if {
	count(input.duplicate_gids) == 0
}

no_duplicate_gids if {
	not input.duplicate_gids
}

status_rhel_09_411110 := "Not_a_Finding" if no_duplicate_gids

else := "Open"

finding_rhel_09_411110 := {
	"vuln_id": "V-258061",
	"stig_id": "RHEL-09-411110",
	"severity": "CAT II",
	"rule_title": "RHEL 9 groups must have unique Group ID (GID).",
	"status": status_rhel_09_411110,
	"fix_text": "Identify and resolve duplicate GIDs",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

# No CAT I rule in this module. array.concat rather than the literal `[]`: OPA >= 1.22 types a literal
# empty array as having no members and rejects iterating it (scripts/check_per_file_load.py).
cat_i_findings := array.concat([], [])

cat_ii_findings := [
	finding_rhel_09_611165,
	finding_rhel_09_611140,
	finding_rhel_09_411075,
	finding_rhel_09_611155,
	finding_rhel_09_611090,
	finding_rhel_09_611110,
	finding_rhel_09_611065,
	finding_rhel_09_611070,
	finding_rhel_09_611100,
	finding_rhel_09_411010,
	finding_rhel_09_611075,
	finding_rhel_09_411085,
	finding_rhel_09_411050,
	finding_rhel_09_411030,
	finding_rhel_09_411110,
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
