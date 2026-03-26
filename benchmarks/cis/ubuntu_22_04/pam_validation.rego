package cis_ubuntu_22_04.pam

# CIS Ubuntu 22.04 LTS Benchmark v1.0.0 - Sections 5.4-5.5: PAM and Password Policies

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in pwquality_violations], [v | some v in faillock_violations]),
	array.concat([v | some v in password_aging_violations], [v | some v in account_violations]),
)

# CIS 5.4.1: Ensure password creation requirements are configured (pwquality)

# CIS 5.4.1.1: Minimum password length >= 14
pwquality_violations contains msg if {
	some line in split(input.pam.pwquality_conf_raw, "\n")
	startswith(trim_space(line), "minlen")
	parts := split(trim_space(line), "=")
	count(parts) >= 2
	to_number(trim_space(parts[1])) < 14
	msg := sprintf("CIS 5.4.1.1: Password minimum length is %s, should be at least 14", [trim_space(parts[1])])
}

pwquality_violations contains msg if {
	not contains(input.pam.pwquality_conf_raw, "minlen")
	msg := "CIS 5.4.1.1: Password minimum length (minlen) not configured in pwquality.conf"
}

# CIS 5.4.1.2: Ensure password complexity (minclass or dcredit/ucredit/lcredit/ocredit)
pwquality_violations contains msg if {
	not contains(input.pam.pwquality_conf_raw, "minclass")
	not contains(input.pam.pwquality_conf_raw, "dcredit")
	msg := "CIS 5.4.1.2: Password complexity not configured (minclass or dcredit not set)"
}

# CIS 5.4.2: Ensure lockout for failed password attempts
faillock_violations contains msg if {
	not input.pam.faillock_configured
	msg := "CIS 5.4.2: pam_faillock (or pam_tally2) not configured for failed password lockout"
}

faillock_violations contains msg if {
	input.pam.faillock_configured
	input.pam.faillock_deny > 5
	msg := sprintf("CIS 5.4.2: Account lockout threshold is %d attempts, should be 5 or less", [input.pam.faillock_deny])
}

faillock_violations contains msg if {
	input.pam.faillock_configured
	input.pam.faillock_unlock_time > 0
	input.pam.faillock_unlock_time < 900
	msg := sprintf("CIS 5.4.2: Account unlock time is %d seconds, should be 900 or more (or 0 for never)", [input.pam.faillock_unlock_time])
}

# CIS 5.4.3: Ensure password reuse is limited
faillock_violations contains msg if {
	not input.pam.remember_configured
	msg := "CIS 5.4.3: Password history (remember) not configured in PAM"
}

faillock_violations contains msg if {
	input.pam.remember_configured
	input.pam.remember_count < 5
	msg := sprintf("CIS 5.4.3: Password history remembers only %d passwords, should be 5 or more", [input.pam.remember_count])
}

# CIS 5.4.4: Ensure password hashing algorithm is SHA-512 or yescrypt
pwquality_violations contains msg if {
	not contains(input.pam.common_password_raw, "sha512")
	not contains(input.pam.common_password_raw, "yescrypt")
	msg := "CIS 5.4.4: Password hashing algorithm is not SHA-512 or yescrypt"
}

# CIS 5.5.1: Ensure minimum days between password changes
password_aging_violations contains msg if {
	input.pam.pass_min_days < 1
	msg := sprintf("CIS 5.5.1: PASS_MIN_DAYS is %d, should be 1 or more", [input.pam.pass_min_days])
}

# CIS 5.5.2: Ensure password expiration is 365 days or less
password_aging_violations contains msg if {
	input.pam.pass_max_days > 365
	msg := sprintf("CIS 5.5.2: PASS_MAX_DAYS is %d, should be 365 or less", [input.pam.pass_max_days])
}

# CIS 5.5.3: Ensure password expiration warning days is 7 or more
password_aging_violations contains msg if {
	input.pam.pass_warn_age < 7
	msg := sprintf("CIS 5.5.3: PASS_WARN_AGE is %d, should be 7 or more", [input.pam.pass_warn_age])
}

# CIS 5.5.4: Ensure inactive password lock is 30 days or less
account_violations contains msg if {
	input.pam.inactive_days > 30
	msg := sprintf("CIS 5.5.4: INACTIVE is %d days, should be 30 or less", [input.pam.inactive_days])
}

account_violations contains msg if {
	input.pam.inactive_days < 0
	msg := "CIS 5.5.4: INACTIVE is not set (-1), inactive accounts will never be locked"
}

# CIS 5.5.5: Ensure all users last password change date is in the past
account_violations contains msg if {
	some user in input.pam.users_with_future_password_change
	msg := sprintf("CIS 5.5.5: User %s has a last password change date in the future", [user])
}

# CIS 5.6: Ensure system accounts are secured
account_violations contains msg if {
	some user in input.pam.system_accounts_with_login_shell
	msg := sprintf("CIS 5.6: System account %s has an interactive login shell", [user])
}

# TMOUT for idle session timeout
account_violations contains msg if {
	not input.pam.tmout_configured
	msg := "CIS 5.5.x: TMOUT is not configured for automatic session timeout"
}

account_violations contains msg if {
	input.pam.tmout_configured
	input.pam.tmout_value > 900
	msg := sprintf("CIS 5.5.x: TMOUT is %d seconds, should be 900 or less", [input.pam.tmout_value])
}

# Default umask
account_violations contains msg if {
	input.pam.default_umask != "027"
	input.pam.default_umask != "077"
	msg := sprintf("CIS 5.5.x: Default umask is %s, should be 027 or more restrictive", [input.pam.default_umask])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"pwquality_violations": count(pwquality_violations),
	"faillock_violations": count(faillock_violations),
	"password_aging_violations": count(password_aging_violations),
	"account_violations": count(account_violations),
	"controls_checked": 17,
	"section": "5.4-5.5 PAM and Password Policies",
	"benchmark": "CIS Ubuntu 22.04 v1.0.0",
}
