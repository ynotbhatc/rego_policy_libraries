# METADATA
# title: "DISA STIG for Oracle Linux 9 - Account and Authentication Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_9
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 13
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_linux_9.account_auth

# DISA STIG for Oracle Linux 9 - Account and Authentication Module
# STIG Version: V1R7 | Released: 30 Sep 2026
# Derived from stig/rhel_9/account_auth.rego by DISA rule title: Oracle Linux 9 and RHEL 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 9 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Password policy, PAM, account lockout, MFA, inactivity

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL09-00-001055 | V-271623 | CAT II
# Passwords must be hashed with SHA-512
default password_sha512 := false

password_sha512 if {
	input.password_policy.sha512 == true
}

password_sha512 if {
	input.pam_config.password_hash == "sha512"
}

status_ol09_00_001055 := "Not_a_Finding" if { password_sha512 } else := "Open"

finding_ol09_00_001055 := {
	"vuln_id": "V-271623",
	"stig_id": "OL09-00-001055",
	"severity": "CAT II",
	"rule_title": "OL 9 must be configured to use the shadow file to store only encrypted representations of passwords.",
	"status": status_ol09_00_001055,
	"fix_text": "Configure PAM to use SHA-512: Set password sufficient pam_unix.so sha512 in /etc/pam.d/system-auth",
}

# OL09-00-003020 | V-271839 | CAT II
# Accounts must be locked after failed login attempts
default account_lockout_enabled := false

account_lockout_enabled if {
	input.pam_config.lockout_attempts <= 3
	input.pam_config.lockout_attempts > 0
}

status_ol09_00_003020 := "Not_a_Finding" if { account_lockout_enabled } else := "Open"

finding_ol09_00_003020 := {
	"vuln_id": "V-271839",
	"stig_id": "OL09-00-003020",
	"severity": "CAT II",
	"rule_title": "OL 9 must automatically lock an account when three unsuccessful logon attempts occur.",
	"status": status_ol09_00_003020,
	"fix_text": "Configure pam_faillock: deny=3 in /etc/security/faillock.conf",
}

# OL09-00-001130 | V-271638 | CAT II
# System must not have empty passwords in /etc/shadow
default no_empty_password_hashes := false

no_empty_password_hashes if {
	count(input.local_accounts_with_empty_passwords) == 0
}

no_empty_password_hashes if {
	not input.local_accounts_with_empty_passwords
}

status_ol09_00_001130 := "Not_a_Finding" if { no_empty_password_hashes } else := "Open"

finding_ol09_00_001130 := {
	"vuln_id": "V-271638",
	"stig_id": "OL09-00-001130",
	"severity": "CAT II",
	"rule_title": "OL 9 must not have accounts configured with blank or null passwords.",
	"status": status_ol09_00_001130,
	"fix_text": "Lock accounts with empty passwords: passwd -l <username>",
}

# OL09-00-001105 | V-271633 | CAT II
# Password minimum length must be 15
default password_minlen := false

password_minlen if {
	input.password_policy.minlen >= 15
}

status_ol09_00_001105 := "Not_a_Finding" if { password_minlen } else := "Open"

finding_ol09_00_001105 := {
	"vuln_id": "V-271633",
	"stig_id": "OL09-00-001105",
	"severity": "CAT II",
	"rule_title": "OL 9 passwords must be created with a minimum of 15 characters.",
	"status": status_ol09_00_001105,
	"fix_text": "Set minlen=15 in /etc/security/pwquality.conf",
}

# OL09-00-001005 | V-271613 | CAT II
# Password must require at least 1 uppercase character
default password_uppercase := false

password_uppercase if {
	input.password_policy.ucredit <= -1
}

password_uppercase if {
	input.password_policy.minclass >= 4
}

status_ol09_00_001005 := "Not_a_Finding" if { password_uppercase } else := "Open"

finding_ol09_00_001005 := {
	"vuln_id": "V-271613",
	"stig_id": "OL09-00-001005",
	"severity": "CAT II",
	"rule_title": "OL 9 must enforce password complexity by requiring that at least one uppercase character be used.",
	"status": status_ol09_00_001005,
	"fix_text": "Set ucredit=-1 in /etc/security/pwquality.conf",
}

# OL09-00-001015 | V-271615 | CAT II
# Password must require at least 1 lowercase character
default password_lowercase := false

password_lowercase if {
	input.password_policy.lcredit <= -1
}

password_lowercase if {
	input.password_policy.minclass >= 4
}

status_ol09_00_001015 := "Not_a_Finding" if { password_lowercase } else := "Open"

finding_ol09_00_001015 := {
	"vuln_id": "V-271615",
	"stig_id": "OL09-00-001015",
	"severity": "CAT II",
	"rule_title": "OL 9 must enforce password complexity by requiring that at least one lowercase character be used.",
	"status": status_ol09_00_001015,
	"fix_text": "Set lcredit=-1 in /etc/security/pwquality.conf",
}

# OL09-00-001020 | V-271616 | CAT II
# Password must require at least 1 numeric character
default password_numeric := false

password_numeric if {
	input.password_policy.dcredit <= -1
}

password_numeric if {
	input.password_policy.minclass >= 4
}

status_ol09_00_001020 := "Not_a_Finding" if { password_numeric } else := "Open"

finding_ol09_00_001020 := {
	"vuln_id": "V-271616",
	"stig_id": "OL09-00-001020",
	"severity": "CAT II",
	"rule_title": "OL 9 must enforce password complexity by requiring that at least one numeric character be used.",
	"status": status_ol09_00_001020,
	"fix_text": "Set dcredit=-1 in /etc/security/pwquality.conf",
}

# OL09-00-001120 | V-271636 | CAT II
# Password must require at least 1 special character
default password_special := false

password_special if {
	input.password_policy.ocredit <= -1
}

status_ol09_00_001120 := "Not_a_Finding" if { password_special } else := "Open"

finding_ol09_00_001120 := {
	"vuln_id": "V-271636",
	"stig_id": "OL09-00-001120",
	"severity": "CAT II",
	"rule_title": "OL 9 must enforce password complexity by requiring that at least one special character be used.",
	"status": status_ol09_00_001120,
	"fix_text": "Set ocredit=-1 in /etc/security/pwquality.conf",
}

# OL09-00-001085 | V-271629 | CAT II
# Password minimum age must be 1 day
default password_minage := false

password_minage if {
	input.password_policy.mindays >= 1
}

status_ol09_00_001085 := "Not_a_Finding" if { password_minage } else := "Open"

finding_ol09_00_001085 := {
	"vuln_id": "V-271629",
	"stig_id": "OL09-00-001085",
	"severity": "CAT II",
	"rule_title": "OL 9 passwords for new users or password changes must have a 24-hour minimum password lifetime restriction in /etc/login.defs.",
	"status": status_ol09_00_001085,
	"fix_text": "Set PASS_MIN_DAYS 1 in /etc/login.defs",
}

# OL09-00-002416 | V-271754 | CAT II
# Inactive accounts must be disabled after 35 days
default inactive_lock_ok := false

inactive_lock_ok if {
	input.password_policy.inactive_days <= 35
	input.password_policy.inactive_days >= 0
}

status_ol09_00_002416 := "Not_a_Finding" if { inactive_lock_ok } else := "Open"

finding_ol09_00_002416 := {
	"vuln_id": "V-271754",
	"stig_id": "OL09-00-002416",
	"severity": "CAT II",
	"rule_title": "OL 9 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.",
	"status": status_ol09_00_002416,
	"fix_text": "Set INACTIVE=35 in /etc/default/useradd",
}

# OL09-00-003001 | V-271832 | CAT II
# No duplicate UIDs should exist
default no_duplicate_uids := false

no_duplicate_uids if {
	count(input.duplicate_uids) == 0
}

no_duplicate_uids if {
	not input.duplicate_uids
}

status_ol09_00_003001 := "Not_a_Finding" if { no_duplicate_uids } else := "Open"

finding_ol09_00_003001 := {
	"vuln_id": "V-271832",
	"stig_id": "OL09-00-003001",
	"severity": "CAT II",
	"rule_title": "OL 9 duplicate User IDs (UIDs) must not exist for interactive users.",
	"status": status_ol09_00_003001,
	"fix_text": "Identify and resolve duplicate UIDs: awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d",
}

# OL09-00-003006 | V-271835 | CAT II
# No duplicate GIDs should exist
default no_duplicate_gids := false

no_duplicate_gids if {
	count(input.duplicate_gids) == 0
}

no_duplicate_gids if {
	not input.duplicate_gids
}

status_ol09_00_003006 := "Not_a_Finding" if { no_duplicate_gids } else := "Open"

finding_ol09_00_003006 := {
	"vuln_id": "V-271835",
	"stig_id": "OL09-00-003006",
	"severity": "CAT II",
	"rule_title": "OL 9 groups must have unique Group ID (GID).",
	"status": status_ol09_00_003006,
	"fix_text": "Identify and resolve duplicate GIDs",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol09_00_001055,
	finding_ol09_00_003020,
	finding_ol09_00_001130,
	finding_ol09_00_001105,
	finding_ol09_00_001005,
	finding_ol09_00_001015,
	finding_ol09_00_001020,
	finding_ol09_00_001120,
	finding_ol09_00_001085,
	finding_ol09_00_002416,
	finding_ol09_00_003001,
	finding_ol09_00_003006,
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
