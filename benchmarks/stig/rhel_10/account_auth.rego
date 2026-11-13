# METADATA
# title: "DISA STIG for RHEL 10 - Account and Authentication Module"
# custom:
#   class: security
#   framework: stig_rhel_10
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
package stig.rhel_10.account_auth

# DISA STIG for RHEL 10 - Account and Authentication Module
# STIG Version: V1R2 | Released: 01 Jul 2026
# Derived from stig/rhel_9/account_auth.rego by DISA rule title: RHEL 10 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the RHEL 10 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Password policy, PAM, account lockout, MFA, inactivity

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-10-600740 | V-281222 | CAT I
# Passwords must be hashed with SHA-512
default password_sha512 := false

password_sha512 if {
	input.password_policy.sha512 == true
}

password_sha512 if {
	input.pam_config.password_hash == "sha512"
}

status_rhel_10_600740 := "Not_a_Finding" if password_sha512

else := "Open"

finding_rhel_10_600740 := {
	"vuln_id": "V-281222",
	"stig_id": "RHEL-10-600740",
	"severity": "CAT I",
	"rule_title": "RHEL 10 must be configured to use the shadow file to store only encrypted representations of passwords.",
	"status": status_rhel_10_600740,
	"fix_text": "Configure PAM to use SHA-512: Set password sufficient pam_unix.so sha512 in /etc/pam.d/system-auth",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-10-701220 | V-281324 | CAT II
# Multifactor authentication must be used
default mfa_enabled := false

mfa_enabled if {
	input.pam_config.mfa_enabled == true
}

mfa_enabled if {
	input.pam_config.sssd_mfa == true
}

status_rhel_10_701220 := "Not_a_Finding" if mfa_enabled

else := "Open"

finding_rhel_10_701220 := {
	"vuln_id": "V-281324",
	"stig_id": "RHEL-10-701220",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enable certificate-based smart card authentication.",
	"status": status_rhel_10_701220,
	"fix_text": "Configure MFA via SSSD with smart card or PIV authentication",
}

# RHEL-10-600410 | V-281194 | CAT II
# Accounts must be locked after failed login attempts
default account_lockout_enabled := false

account_lockout_enabled if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_rhel_10_600410 := "Not_a_Finding" if account_lockout_enabled

else := "Open"

finding_rhel_10_600410 := {
	"vuln_id": "V-281194",
	"stig_id": "RHEL-10-600410",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must automatically lock an account when three unsuccessful login attempts occur.",
	"status": status_rhel_10_600410,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# RHEL-10-600460 | V-281201 | CAT II
# System must not have empty passwords in /etc/shadow
default no_empty_password_hashes := false

no_empty_password_hashes if {
	is_array(input.local_accounts_with_empty_passwords)
	count(input.local_accounts_with_empty_passwords) == 0
}

status_rhel_10_600460 := "Not_a_Finding" if no_empty_password_hashes

else := "Open"

finding_rhel_10_600460 := {
	"vuln_id": "V-281201",
	"stig_id": "RHEL-10-600460",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not have accounts configured with blank or null passwords.",
	"status": status_rhel_10_600460,
	"fix_text": "Lock accounts with empty passwords: passwd -l <username>",
}

# RHEL-10-600220 | V-281181 | CAT II
# Password minimum length must be 15
default password_minlen := false

password_minlen if {
	input.password_policy.minlen >= 15
}

status_rhel_10_600220 := "Not_a_Finding" if password_minlen

else := "Open"

finding_rhel_10_600220 := {
	"vuln_id": "V-281181",
	"stig_id": "RHEL-10-600220",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce that passwords be created with a minimum of 15 characters.",
	"status": status_rhel_10_600220,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# RHEL-10-600250 | V-281184 | CAT II
# Password must require at least 1 uppercase character
default password_uppercase := false

password_uppercase if {
	input.password_policy.ucredit <= -1
}

password_uppercase if {
	input.password_policy.minclass >= 4
}

status_rhel_10_600250 := "Not_a_Finding" if password_uppercase

else := "Open"

finding_rhel_10_600250 := {
	"vuln_id": "V-281184",
	"stig_id": "RHEL-10-600250",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce password complexity by requiring that at least one uppercase character be used.",
	"status": status_rhel_10_600250,
	"fix_text": "Set ucredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-10-600240 | V-281183 | CAT II
# Password must require at least 1 lowercase character
default password_lowercase := false

password_lowercase if {
	input.password_policy.lcredit <= -1
}

password_lowercase if {
	input.password_policy.minclass >= 4
}

status_rhel_10_600240 := "Not_a_Finding" if password_lowercase

else := "Open"

finding_rhel_10_600240 := {
	"vuln_id": "V-281183",
	"stig_id": "RHEL-10-600240",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce password complexity by requiring that at least one lowercase character be used.",
	"status": status_rhel_10_600240,
	"fix_text": "Set lcredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-10-600310 | V-281190 | CAT II
# Password must require at least 1 numeric character
default password_numeric := false

password_numeric if {
	input.password_policy.dcredit <= -1
}

password_numeric if {
	input.password_policy.minclass >= 4
}

status_rhel_10_600310 := "Not_a_Finding" if password_numeric

else := "Open"

finding_rhel_10_600310 := {
	"vuln_id": "V-281190",
	"stig_id": "RHEL-10-600310",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce password complexity by requiring that at least one numeric character be used.",
	"status": status_rhel_10_600310,
	"fix_text": "Set dcredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-10-600230 | V-281182 | CAT II
# Password must require at least 1 special character
default password_special := false

password_special if {
	input.password_policy.ocredit <= -1
}

status_rhel_10_600230 := "Not_a_Finding" if password_special

else := "Open"

finding_rhel_10_600230 := {
	"vuln_id": "V-281182",
	"stig_id": "RHEL-10-600230",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce password complexity by requiring at least one special character to be used.",
	"status": status_rhel_10_600230,
	"fix_text": "Set ocredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-10-600100 | V-281169 | CAT II
# Password maximum age must be 60 days or less
default password_maxage := false

password_maxage if {
	input.password_policy.maxdays <= 60
	input.password_policy.maxdays > 0
}

status_rhel_10_600100 := "Not_a_Finding" if password_maxage

else := "Open"

finding_rhel_10_600100 := {
	"vuln_id": "V-281169",
	"stig_id": "RHEL-10-600100",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must, for new users or password changes, have a 60-day maximum password lifetime restriction for user account passwords in \"/etc/login.defs\".",
	"status": status_rhel_10_600100,
	"fix_text": "Set PASS_MAX_DAYS 60 in /etc/login.defs",
}

# RHEL-10-600210 | V-281180 | CAT II
# Password minimum age must be 1 day
default password_minage := false

password_minage if {
	input.password_policy.mindays >= 1
}

status_rhel_10_600210 := "Not_a_Finding" if password_minage

else := "Open"

finding_rhel_10_600210 := {
	"vuln_id": "V-281180",
	"stig_id": "RHEL-10-600210",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must enforce a 24-hours minimum password lifetime restriction for passwords for new users or password changes in \"/etc/login.defs\".",
	"status": status_rhel_10_600210,
	"fix_text": "Set PASS_MIN_DAYS 1 in /etc/login.defs",
}

# RHEL-10-600420 | V-281196 | CAT II
# Account lockout time must be at least 15 minutes
default lockout_duration_ok := false

lockout_duration_ok if {
	input.pam_config.lockout_time >= 900 # 900 seconds = 15 minutes
}

status_rhel_10_600420 := "Not_a_Finding" if lockout_duration_ok

else := "Open"

finding_rhel_10_600420 := {
	"vuln_id": "V-281196",
	"stig_id": "RHEL-10-600420",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must automatically lock an account when three unsuccessful login attempts occur during a 15-minute time period.",
	"status": status_rhel_10_600420,
	"fix_text": "Set unlock_time=900 in /etc/security/faillock.conf",
}

# RHEL-10-600160 | V-281175 | CAT II
# Inactive accounts must be disabled after 35 days
default inactive_lock_ok := false

inactive_lock_ok if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_rhel_10_600160 := "Not_a_Finding" if inactive_lock_ok

else := "Open"

finding_rhel_10_600160 := {
	"vuln_id": "V-281175",
	"stig_id": "RHEL-10-600160",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.",
	"status": status_rhel_10_600160,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# RHEL-10-600130 | V-281172 | CAT II
# No duplicate UIDs should exist
default no_duplicate_uids := false

no_duplicate_uids if {
	is_array(input.duplicate_uids)
	count(input.duplicate_uids) == 0
}

status_rhel_10_600130 := "Not_a_Finding" if no_duplicate_uids

else := "Open"

finding_rhel_10_600130 := {
	"vuln_id": "V-281172",
	"stig_id": "RHEL-10-600130",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must not allow duplicate user IDs (UIDs) to exist for interactive users.",
	"status": status_rhel_10_600130,
	"fix_text": "Identify and resolve duplicate UIDs: awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d",
}

# RHEL-10-600470 | V-281202 | CAT II
# No duplicate GIDs should exist
default no_duplicate_gids := false

no_duplicate_gids if {
	is_array(input.duplicate_gids)
	count(input.duplicate_gids) == 0
}

status_rhel_10_600470 := "Not_a_Finding" if no_duplicate_gids

else := "Open"

finding_rhel_10_600470 := {
	"vuln_id": "V-281202",
	"stig_id": "RHEL-10-600470",
	"severity": "CAT II",
	"rule_title": "RHEL 10 must have a unique group ID (GID) for each group in \"/etc/group\".",
	"status": status_rhel_10_600470,
	"fix_text": "Identify and resolve duplicate GIDs",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [finding_rhel_10_600740]

cat_ii_findings := [
	finding_rhel_10_701220,
	finding_rhel_10_600410,
	finding_rhel_10_600460,
	finding_rhel_10_600220,
	finding_rhel_10_600250,
	finding_rhel_10_600240,
	finding_rhel_10_600310,
	finding_rhel_10_600230,
	finding_rhel_10_600100,
	finding_rhel_10_600210,
	finding_rhel_10_600420,
	finding_rhel_10_600160,
	finding_rhel_10_600130,
	finding_rhel_10_600470,
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
	"module": "account_auth",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
	"cat_i_compliant": cat_i_compliant,
}
