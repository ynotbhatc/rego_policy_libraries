# METADATA
# title: "DISA STIG for Oracle Linux 8 - Account and Authentication Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 12
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_8.account_auth

# DISA STIG for Oracle Linux 8 - Account and Authentication Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/account_auth.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Password policy, PAM, account lockout, MFA, inactivity

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# OL08-00-020330 | V-248714 | CAT I
# System must not have empty passwords in /etc/shadow
default no_empty_password_hashes := false

no_empty_password_hashes if {
	count(input.local_accounts_with_empty_passwords) == 0
}

no_empty_password_hashes if {
	not input.local_accounts_with_empty_passwords
}

status_ol08_00_020330 := "Not_a_Finding" if { no_empty_password_hashes } else := "Open"

finding_ol08_00_020330 := {
	"vuln_id": "V-248714",
	"stig_id": "OL08-00-020330",
	"severity": "CAT I",
	"rule_title": "OL 8 must not allow accounts configured with blank or null passwords.",
	"status": status_ol08_00_020330,
	"fix_text": "Lock accounts with empty passwords: passwd -l <username>",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-010110 | V-248533 | CAT II
# Passwords must be hashed with SHA-512
default password_sha512 := false

password_sha512 if {
	input.password_policy.sha512 == true
}

password_sha512 if {
	input.pam_config.password_hash == "sha512"
}

status_ol08_00_010110 := "Not_a_Finding" if { password_sha512 } else := "Open"

finding_ol08_00_010110 := {
	"vuln_id": "V-248533",
	"stig_id": "OL08-00-010110",
	"severity": "CAT II",
	"rule_title": "OL 8 must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.",
	"status": status_ol08_00_010110,
	"fix_text": "Configure PAM to use SHA-512: Set password sufficient pam_unix.so sha512 in /etc/pam.d/system-auth",
}

# OL08-00-020011 | V-248653 | CAT II
# Accounts must be locked after failed login attempts
default account_lockout_enabled := false

account_lockout_enabled if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_ol08_00_020011 := "Not_a_Finding" if { account_lockout_enabled } else := "Open"

finding_ol08_00_020011 := {
	"vuln_id": "V-248653",
	"stig_id": "OL08-00-020011",
	"severity": "CAT II",
	"rule_title": "OL 8 systems, versions 8.2 and above, must automatically lock an account when three unsuccessful logon attempts occur.",
	"status": status_ol08_00_020011,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# OL08-00-020230 | V-248699 | CAT II
# Password minimum length must be 15
default password_minlen := false

password_minlen if {
	input.password_policy.minlen >= 15
}

status_ol08_00_020230 := "Not_a_Finding" if { password_minlen } else := "Open"

finding_ol08_00_020230 := {
	"vuln_id": "V-248699",
	"stig_id": "OL08-00-020230",
	"severity": "CAT II",
	"rule_title": "OL 8 passwords must have a minimum of 15 characters.",
	"status": status_ol08_00_020230,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# OL08-00-020190 | V-248695 | CAT II
# Password minimum age must be 1 day
default password_minage := false

password_minage if {
	input.password_policy.mindays >= 1
}

status_ol08_00_020190 := "Not_a_Finding" if { password_minage } else := "Open"

finding_ol08_00_020190 := {
	"vuln_id": "V-248695",
	"stig_id": "OL08-00-020190",
	"severity": "CAT II",
	"rule_title": "OL 8 passwords for new users or password changes must have a 24 hours/one day minimum password lifetime restriction in \"/etc/login.defs\".",
	"status": status_ol08_00_020190,
	"fix_text": "Set PASS_MIN_DAYS 1 in /etc/login.defs",
}

# OL08-00-020013 | V-248655 | CAT II
# Inactive accounts must be disabled after 35 days
default inactive_lock_ok := false

inactive_lock_ok if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_ol08_00_020013 := "Not_a_Finding" if { inactive_lock_ok } else := "Open"

finding_ol08_00_020013 := {
	"vuln_id": "V-248655",
	"stig_id": "OL08-00-020013",
	"severity": "CAT II",
	"rule_title": "OL 8 systems, versions 8.2 and above, must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.",
	"status": status_ol08_00_020013,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# OL08-00-020240 | V-248701 | CAT II
# No duplicate UIDs should exist
default no_duplicate_uids := false

no_duplicate_uids if {
	count(input.duplicate_uids) == 0
}

no_duplicate_uids if {
	not input.duplicate_uids
}

status_ol08_00_020240 := "Not_a_Finding" if { no_duplicate_uids } else := "Open"

finding_ol08_00_020240 := {
	"vuln_id": "V-248701",
	"stig_id": "OL08-00-020240",
	"severity": "CAT II",
	"rule_title": "OL 8 duplicate User IDs (UIDs) must not exist for interactive users.",
	"status": status_ol08_00_020240,
	"fix_text": "Identify and resolve duplicate UIDs: awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d",
}

# =============================================================================
# CAT III - LOW SEVERITY
# =============================================================================

# OL08-00-020110 | V-248687 | CAT III
# Password must require at least 1 uppercase character
default password_uppercase := false

password_uppercase if {
	input.password_policy.ucredit <= -1
}

password_uppercase if {
	input.password_policy.minclass >= 4
}

status_ol08_00_020110 := "Not_a_Finding" if { password_uppercase } else := "Open"

finding_ol08_00_020110 := {
	"vuln_id": "V-248687",
	"stig_id": "OL08-00-020110",
	"severity": "CAT III",
	"rule_title": "OL 8 must enforce password complexity by requiring that at least one uppercase character be used.",
	"status": status_ol08_00_020110,
	"fix_text": "Set ucredit=-1 in /etc/security/pwquality.conf",
}

# OL08-00-020120 | V-248688 | CAT III
# Password must require at least 1 lowercase character
default password_lowercase := false

password_lowercase if {
	input.password_policy.lcredit <= -1
}

password_lowercase if {
	input.password_policy.minclass >= 4
}

status_ol08_00_020120 := "Not_a_Finding" if { password_lowercase } else := "Open"

finding_ol08_00_020120 := {
	"vuln_id": "V-248688",
	"stig_id": "OL08-00-020120",
	"severity": "CAT III",
	"rule_title": "OL 8 must enforce password complexity by requiring that at least one lowercase character be used.",
	"status": status_ol08_00_020120,
	"fix_text": "Set lcredit=-1 in /etc/security/pwquality.conf",
}

# OL08-00-020130 | V-248689 | CAT III
# Password must require at least 1 numeric character
default password_numeric := false

password_numeric if {
	input.password_policy.dcredit <= -1
}

password_numeric if {
	input.password_policy.minclass >= 4
}

status_ol08_00_020130 := "Not_a_Finding" if { password_numeric } else := "Open"

finding_ol08_00_020130 := {
	"vuln_id": "V-248689",
	"stig_id": "OL08-00-020130",
	"severity": "CAT III",
	"rule_title": "OL 8 must enforce password complexity by requiring that at least one numeric character be used.",
	"status": status_ol08_00_020130,
	"fix_text": "Set dcredit=-1 in /etc/security/pwquality.conf",
}

# OL08-00-020280 | V-248709 | CAT III
# Password must require at least 1 special character
default password_special := false

password_special if {
	input.password_policy.ocredit <= -1
}

status_ol08_00_020280 := "Not_a_Finding" if { password_special } else := "Open"

finding_ol08_00_020280 := {
	"vuln_id": "V-248709",
	"stig_id": "OL08-00-020280",
	"severity": "CAT III",
	"rule_title": "All OL 8 passwords must contain at least one special character.",
	"status": status_ol08_00_020280,
	"fix_text": "Set ocredit=-1 in /etc/security/pwquality.conf",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_ol08_00_020330,
]

cat_ii_findings := [
	finding_ol08_00_010110,
	finding_ol08_00_020011,
	finding_ol08_00_020230,
	finding_ol08_00_020190,
	finding_ol08_00_020013,
	finding_ol08_00_020240,
]

cat_iii_findings := [
	finding_ol08_00_020110,
	finding_ol08_00_020120,
	finding_ol08_00_020130,
	finding_ol08_00_020280,
]

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

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
