package stig.rhel_8.account_auth

# DISA STIG for RHEL 8 - Account and Authentication Module
# STIG Version: V1R13 | Released: July 2024

import rego.v1

default compliant := false

# =============================================================================
# CAT I
# =============================================================================

# RHEL-08-020000 | V-230280 | CAT I - MFA must be used
default mfa_enabled := false
mfa_enabled if { input.pam_config.mfa_enabled == true }
mfa_enabled if { input.pam_config.sssd_mfa == true }

status_rhel_08_020000 := "Not_a_Finding" if { mfa_enabled } else := "Open"
finding_rhel_08_020000 := {
	"vuln_id": "V-230280",
	"stig_id": "RHEL-08-020000",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must implement multifactor authentication for access to privileged accounts",
	"status": status_rhel_08_020000,
	"fix_text": "Configure MFA via SSSD with PIV/CAC",
}

# RHEL-08-020010 | V-230281 | CAT I - Accounts must lock after 3 failed attempts
default account_lockout := false
account_lockout if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_rhel_08_020010 := "Not_a_Finding" if { account_lockout } else := "Open"
finding_rhel_08_020010 := {
	"vuln_id": "V-230281",
	"stig_id": "RHEL-08-020010",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must lock an account after three consecutive invalid access attempts",
	"status": status_rhel_08_020010,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# RHEL-08-020020 | V-230282 | CAT I - Passwords must be SHA-512
default password_sha512 := false
password_sha512 if { input.password_policy.sha512 == true }
password_sha512 if { input.pam_config.password_hash == "sha512" }

status_rhel_08_020020 := "Not_a_Finding" if { password_sha512 } else := "Open"
finding_rhel_08_020020 := {
	"vuln_id": "V-230282",
	"stig_id": "RHEL-08-020020",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must store only encrypted representations of passwords",
	"status": status_rhel_08_020020,
	"fix_text": "Configure SHA-512 in PAM: pam_unix.so sha512",
}

# RHEL-08-020030 | V-230283 | CAT I - No empty passwords
default no_empty_passwords := false
no_empty_passwords if { not input.local_accounts_with_empty_passwords }
no_empty_passwords if { count(input.local_accounts_with_empty_passwords) == 0 }

status_rhel_08_020030 := "Not_a_Finding" if { no_empty_passwords } else := "Open"
finding_rhel_08_020030 := {
	"vuln_id": "V-230283",
	"stig_id": "RHEL-08-020030",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must not have accounts configured with blank or null passwords",
	"status": status_rhel_08_020030,
	"fix_text": "Lock empty password accounts: passwd -l <username>",
}

# =============================================================================
# CAT II
# =============================================================================

# RHEL-08-020040 | V-230284 | CAT II - Password minimum length 15
default password_minlen := false
password_minlen if { input.password_policy.minlen >= 15 }

status_rhel_08_020040 := "Not_a_Finding" if { password_minlen } else := "Open"
finding_rhel_08_020040 := {
	"vuln_id": "V-230284",
	"stig_id": "RHEL-08-020040",
	"severity": "CAT II",
	"rule_title": "RHEL 8 passwords must have a minimum of 15 characters",
	"status": status_rhel_08_020040,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# RHEL-08-020050 | V-230285 | CAT II - Password max age 60 days
default password_maxage := false
password_maxage if {
	input.password_policy.maxdays <= 60
	input.password_policy.maxdays > 0
}

status_rhel_08_020050 := "Not_a_Finding" if { password_maxage } else := "Open"
finding_rhel_08_020050 := {
	"vuln_id": "V-230285",
	"stig_id": "RHEL-08-020050",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must enforce a 60-day maximum password lifetime restriction",
	"status": status_rhel_08_020050,
	"fix_text": "Set PASS_MAX_DAYS 60 in /etc/login.defs",
}

# RHEL-08-020060 | V-230286 | CAT II - Password history (remember 5)
default password_history := false
password_history if { input.password_policy.remember >= 5 }

status_rhel_08_020060 := "Not_a_Finding" if { password_history } else := "Open"
finding_rhel_08_020060 := {
	"vuln_id": "V-230286",
	"stig_id": "RHEL-08-020060",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must prohibit password reuse for a minimum of five generations",
	"status": status_rhel_08_020060,
	"fix_text": "Set remember=5 in PAM password configuration",
}

# RHEL-08-020070 | V-230287 | CAT II - Lockout time 15 minutes
default lockout_duration := false
lockout_duration if { input.pam_config.lockout_time >= 900 }

status_rhel_08_020070 := "Not_a_Finding" if { lockout_duration } else := "Open"
finding_rhel_08_020070 := {
	"vuln_id": "V-230287",
	"stig_id": "RHEL-08-020070",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must automatically lock accounts after three unsuccessful login attempts",
	"status": status_rhel_08_020070,
	"fix_text": "Set unlock_time=900 in /etc/security/faillock.conf",
}

# RHEL-08-020080 | V-230288 | CAT II - Inactive accounts lock after 35 days
default inactive_lock := false
inactive_lock if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_rhel_08_020080 := "Not_a_Finding" if { inactive_lock } else := "Open"
finding_rhel_08_020080 := {
	"vuln_id": "V-230288",
	"stig_id": "RHEL-08-020080",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must disable account identifiers after 35 days of inactivity",
	"status": status_rhel_08_020080,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# RHEL-08-020090 | V-230289 | CAT II - No duplicate UIDs
default no_dup_uids := false
no_dup_uids if { not input.duplicate_uids }
no_dup_uids if { count(input.duplicate_uids) == 0 }

status_rhel_08_020090 := "Not_a_Finding" if { no_dup_uids } else := "Open"
finding_rhel_08_020090 := {
	"vuln_id": "V-230289",
	"stig_id": "RHEL-08-020090",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must not allow duplicate UIDs",
	"status": status_rhel_08_020090,
	"fix_text": "Resolve duplicate UIDs in /etc/passwd",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_020000,
	finding_rhel_08_020010,
	finding_rhel_08_020020,
	finding_rhel_08_020030,
]

cat_ii_findings := [
	finding_rhel_08_020040,
	finding_rhel_08_020050,
	finding_rhel_08_020060,
	finding_rhel_08_020070,
	finding_rhel_08_020080,
	finding_rhel_08_020090,
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

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "account_auth",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
