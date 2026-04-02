package stig.rhel_9.account_auth

# DISA STIG for RHEL 9 - Account and Authentication Module
# STIG Version: V2R2 | Released: October 2024
# Covers: Password policy, PAM, account lockout, MFA, inactivity

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-611010 | V-258050 | CAT I
# Multifactor authentication must be used
default mfa_enabled := false

mfa_enabled if {
	input.pam_config.mfa_enabled == true
}

mfa_enabled if {
	input.pam_config.sssd_mfa == true
}

status_rhel_09_611010 := "Not_a_Finding" if { mfa_enabled } else := "Open"

finding_rhel_09_611010 := {
	"vuln_id": "V-258050",
	"stig_id": "RHEL-09-611010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must implement multifactor authentication for access to privileged accounts",
	"status": status_rhel_09_611010,
	"fix_text": "Configure MFA via SSSD with smart card or PIV authentication",
}

# RHEL-09-611015 | V-258051 | CAT I
# Passwords must be hashed with SHA-512
default password_sha512 := false

password_sha512 if {
	input.password_policy.sha512 == true
}

password_sha512 if {
	input.pam_config.password_hash == "sha512"
}

status_rhel_09_611015 := "Not_a_Finding" if { password_sha512 } else := "Open"

finding_rhel_09_611015 := {
	"vuln_id": "V-258051",
	"stig_id": "RHEL-09-611015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must store only encrypted representations of passwords",
	"status": status_rhel_09_611015,
	"fix_text": "Configure PAM to use SHA-512: Set password sufficient pam_unix.so sha512 in /etc/pam.d/system-auth",
}

# RHEL-09-611020 | V-258052 | CAT I
# Accounts must be locked after failed login attempts
default account_lockout_enabled := false

account_lockout_enabled if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_rhel_09_611020 := "Not_a_Finding" if { account_lockout_enabled } else := "Open"

finding_rhel_09_611020 := {
	"vuln_id": "V-258052",
	"stig_id": "RHEL-09-611020",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must lock an account after three consecutive invalid access attempts",
	"status": status_rhel_09_611020,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# RHEL-09-611025 | V-258053 | CAT I
# System must not have empty passwords in /etc/shadow
default no_empty_password_hashes := false

no_empty_password_hashes if {
	count(input.local_accounts_with_empty_passwords) == 0
}

no_empty_password_hashes if {
	not input.local_accounts_with_empty_passwords
}

status_rhel_09_611025 := "Not_a_Finding" if { no_empty_password_hashes } else := "Open"

finding_rhel_09_611025 := {
	"vuln_id": "V-258053",
	"stig_id": "RHEL-09-611025",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not have accounts configured with blank or null passwords",
	"status": status_rhel_09_611025,
	"fix_text": "Lock accounts with empty passwords: passwd -l <username>",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-611030 | V-258054 | CAT II
# Password minimum length must be 15
default password_minlen := false

password_minlen if {
	input.password_policy.minlen >= 15
}

status_rhel_09_611030 := "Not_a_Finding" if { password_minlen } else := "Open"

finding_rhel_09_611030 := {
	"vuln_id": "V-258054",
	"stig_id": "RHEL-09-611030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must have a minimum of 15 characters",
	"status": status_rhel_09_611030,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# RHEL-09-611035 | V-258055 | CAT II
# Password must require at least 1 uppercase character
default password_uppercase := false

password_uppercase if {
	input.password_policy.ucredit <= -1
}

password_uppercase if {
	input.password_policy.minclass >= 4
}

status_rhel_09_611035 := "Not_a_Finding" if { password_uppercase } else := "Open"

finding_rhel_09_611035 := {
	"vuln_id": "V-258055",
	"stig_id": "RHEL-09-611035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must require at least one uppercase letter",
	"status": status_rhel_09_611035,
	"fix_text": "Set ucredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611040 | V-258056 | CAT II
# Password must require at least 1 lowercase character
default password_lowercase := false

password_lowercase if {
	input.password_policy.lcredit <= -1
}

password_lowercase if {
	input.password_policy.minclass >= 4
}

status_rhel_09_611040 := "Not_a_Finding" if { password_lowercase } else := "Open"

finding_rhel_09_611040 := {
	"vuln_id": "V-258056",
	"stig_id": "RHEL-09-611040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must require at least one lowercase letter",
	"status": status_rhel_09_611040,
	"fix_text": "Set lcredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611045 | V-258057 | CAT II
# Password must require at least 1 numeric character
default password_numeric := false

password_numeric if {
	input.password_policy.dcredit <= -1
}

password_numeric if {
	input.password_policy.minclass >= 4
}

status_rhel_09_611045 := "Not_a_Finding" if { password_numeric } else := "Open"

finding_rhel_09_611045 := {
	"vuln_id": "V-258057",
	"stig_id": "RHEL-09-611045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must require at least one numeric digit",
	"status": status_rhel_09_611045,
	"fix_text": "Set dcredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611050 | V-258058 | CAT II
# Password must require at least 1 special character
default password_special := false

password_special if {
	input.password_policy.ocredit <= -1
}

status_rhel_09_611050 := "Not_a_Finding" if { password_special } else := "Open"

finding_rhel_09_611050 := {
	"vuln_id": "V-258058",
	"stig_id": "RHEL-09-611050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must require at least one special character",
	"status": status_rhel_09_611050,
	"fix_text": "Set ocredit=-1 in /etc/security/pwquality.conf",
}

# RHEL-09-611055 | V-258059 | CAT II
# Password maximum age must be 60 days or less
default password_maxage := false

password_maxage if {
	input.password_policy.maxdays <= 60
	input.password_policy.maxdays > 0
}

status_rhel_09_611055 := "Not_a_Finding" if { password_maxage } else := "Open"

finding_rhel_09_611055 := {
	"vuln_id": "V-258059",
	"stig_id": "RHEL-09-611055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords for new users must be restricted to a 60-day maximum lifetime",
	"status": status_rhel_09_611055,
	"fix_text": "Set PASS_MAX_DAYS 60 in /etc/login.defs",
}

# RHEL-09-611060 | V-258060 | CAT II
# Password minimum age must be 1 day
default password_minage := false

password_minage if {
	input.password_policy.mindays >= 1
}

status_rhel_09_611060 := "Not_a_Finding" if { password_minage } else := "Open"

finding_rhel_09_611060 := {
	"vuln_id": "V-258060",
	"stig_id": "RHEL-09-611060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 passwords must have a minimum of one day age",
	"status": status_rhel_09_611060,
	"fix_text": "Set PASS_MIN_DAYS 1 in /etc/login.defs",
}

# RHEL-09-611065 | V-258061 | CAT II
# Password history must remember at least 5 passwords
default password_history := false

password_history if {
	input.password_policy.remember >= 5
}

status_rhel_09_611065 := "Not_a_Finding" if { password_history } else := "Open"

finding_rhel_09_611065 := {
	"vuln_id": "V-258061",
	"stig_id": "RHEL-09-611065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must prohibit password reuse for a minimum of five generations",
	"status": status_rhel_09_611065,
	"fix_text": "Set remember=5 in /etc/pam.d/system-auth for pam_unix.so",
}

# RHEL-09-611070 | V-258062 | CAT II
# Account lockout time must be at least 15 minutes
default lockout_duration_ok := false

lockout_duration_ok if {
	input.pam_config.lockout_time >= 900  # 900 seconds = 15 minutes
}

status_rhel_09_611070 := "Not_a_Finding" if { lockout_duration_ok } else := "Open"

finding_rhel_09_611070 := {
	"vuln_id": "V-258062",
	"stig_id": "RHEL-09-611070",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must automatically lock an account until the locked account is released by an administrator when three unsuccessful login attempts occur during a 15-minute time period",
	"status": status_rhel_09_611070,
	"fix_text": "Set unlock_time=900 in /etc/security/faillock.conf",
}

# RHEL-09-611075 | V-258063 | CAT II
# Inactive accounts must be disabled after 35 days
default inactive_lock_ok := false

inactive_lock_ok if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_rhel_09_611075 := "Not_a_Finding" if { inactive_lock_ok } else := "Open"

finding_rhel_09_611075 := {
	"vuln_id": "V-258063",
	"stig_id": "RHEL-09-611075",
	"severity": "CAT II",
	"rule_title": "RHEL 9 accounts subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period",
	"status": status_rhel_09_611075,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# RHEL-09-611080 | V-258064 | CAT II
# Password expiration warning must be 7 days
default password_warn_age := false

password_warn_age if {
	input.password_policy.warn_age >= 7
}

status_rhel_09_611080 := "Not_a_Finding" if { password_warn_age } else := "Open"

finding_rhel_09_611080 := {
	"vuln_id": "V-258064",
	"stig_id": "RHEL-09-611080",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must provide a warning 14 days before a password expires",
	"status": status_rhel_09_611080,
	"fix_text": "Set PASS_WARN_AGE 7 in /etc/login.defs",
}

# RHEL-09-611085 | V-258065 | CAT II
# No duplicate UIDs should exist
default no_duplicate_uids := false

no_duplicate_uids if {
	count(input.duplicate_uids) == 0
}

no_duplicate_uids if {
	not input.duplicate_uids
}

status_rhel_09_611085 := "Not_a_Finding" if { no_duplicate_uids } else := "Open"

finding_rhel_09_611085 := {
	"vuln_id": "V-258065",
	"stig_id": "RHEL-09-611085",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not allow duplicate UIDs",
	"status": status_rhel_09_611085,
	"fix_text": "Identify and resolve duplicate UIDs: awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d",
}

# RHEL-09-611090 | V-258066 | CAT II
# No duplicate GIDs should exist
default no_duplicate_gids := false

no_duplicate_gids if {
	count(input.duplicate_gids) == 0
}

no_duplicate_gids if {
	not input.duplicate_gids
}

status_rhel_09_611090 := "Not_a_Finding" if { no_duplicate_gids } else := "Open"

finding_rhel_09_611090 := {
	"vuln_id": "V-258066",
	"stig_id": "RHEL-09-611090",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not allow duplicate GIDs",
	"status": status_rhel_09_611090,
	"fix_text": "Identify and resolve duplicate GIDs",
}

# RHEL-09-611095 | V-258067 | CAT II
# All groups in /etc/passwd must exist in /etc/group
default all_groups_valid := false

all_groups_valid if {
	count(input.invalid_group_references) == 0
}

all_groups_valid if {
	not input.invalid_group_references
}

status_rhel_09_611095 := "Not_a_Finding" if { all_groups_valid } else := "Open"

finding_rhel_09_611095 := {
	"vuln_id": "V-258067",
	"stig_id": "RHEL-09-611095",
	"severity": "CAT II",
	"rule_title": "All RHEL 9 groups in the /etc/passwd file must be defined in the /etc/group file",
	"status": status_rhel_09_611095,
	"fix_text": "Ensure all GIDs in /etc/passwd correspond to groups in /etc/group",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_611010,
	finding_rhel_09_611015,
	finding_rhel_09_611020,
	finding_rhel_09_611025,
]

cat_ii_findings := [
	finding_rhel_09_611030,
	finding_rhel_09_611035,
	finding_rhel_09_611040,
	finding_rhel_09_611045,
	finding_rhel_09_611050,
	finding_rhel_09_611055,
	finding_rhel_09_611060,
	finding_rhel_09_611065,
	finding_rhel_09_611070,
	finding_rhel_09_611075,
	finding_rhel_09_611080,
	finding_rhel_09_611085,
	finding_rhel_09_611090,
	finding_rhel_09_611095,
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
	"module": "account_auth",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
