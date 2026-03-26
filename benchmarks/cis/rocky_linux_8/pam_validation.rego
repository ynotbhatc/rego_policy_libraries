package cis_rocky_linux_8.pam

# CIS Rocky Linux 8 Benchmark v2.0.0 - Section 5.4/5.5: PAM and User Accounts
# Password Authentication Module configuration validation

import rego.v1

default compliant := false

pwquality_configured if {
	input.pam.pwquality_installed
}

pwquality_config := {key: value |
	some line in split(input.pam.pwquality_conf_raw, "\n")
	trimmed := trim_space(line)
	not startswith(trimmed, "#")
	trimmed != ""
	parts := regex.split(`\s*=\s*`, trimmed)
	count(parts) == 2
	key := trim_space(parts[0])
	value := trim_space(parts[1])
}

check_pam_file(filename, pattern) if {
	some line in split(input.pam[filename], "\n")
	contains(line, pattern)
}

# CIS 5.4.1: pwquality installed
violations contains msg if {
	not pwquality_configured
	msg := "CIS 5.4.1: pwquality package not installed"
}

# CIS 5.4.1.1: Minimum password length
violations contains msg if {
	pwquality_configured
	not pwquality_config.minlen
	msg := "CIS 5.4.1.1: Password minimum length not configured in pwquality.conf"
}

violations contains msg if {
	pwquality_configured
	pwquality_config.minlen
	to_number(pwquality_config.minlen) < 14
	msg := sprintf("CIS 5.4.1.1: Password minimum length is %s, should be 14 or more", [pwquality_config.minlen])
}

# CIS 5.4.1.2: Password complexity
violations contains msg if {
	pwquality_configured
	not pwquality_config.minclass
	not pwquality_config.dcredit
	not pwquality_config.ucredit
	not pwquality_config.lcredit
	not pwquality_config.ocredit
	msg := "CIS 5.4.1.2: Password complexity requirements not configured"
}

violations contains msg if {
	pwquality_configured
	pwquality_config.minclass
	to_number(pwquality_config.minclass) < 4
	msg := sprintf("CIS 5.4.1.2: Password minclass is %s, should be 4", [pwquality_config.minclass])
}

# CIS 5.4.2: Account lockout (pam_faillock)
violations contains msg if {
	not check_pam_file("system_auth", "pam_faillock.so")
	not check_pam_file("password_auth", "pam_faillock.so")
	msg := "CIS 5.4.2: pam_faillock not configured in PAM"
}

violations contains msg if {
	check_pam_file("system_auth", "pam_faillock.so")
	not contains(input.pam.system_auth, "deny=")
	msg := "CIS 5.4.2: Account lockout threshold (deny) not configured"
}

violations contains msg if {
	check_pam_file("system_auth", "pam_faillock.so")
	not contains(input.pam.system_auth, "unlock_time=")
	msg := "CIS 5.4.2: Account lockout time (unlock_time) not configured"
}

# CIS 5.4.3: Password reuse limited
violations contains msg if {
	not check_pam_file("system_auth", "remember=")
	not check_pam_file("password_auth", "remember=")
	msg := "CIS 5.4.3: Password reuse limitation not configured (remember parameter missing)"
}

violations contains msg if {
	check_pam_file("system_auth", "remember=")
	system_auth_line := [line |
		some line in split(input.pam.system_auth, "\n")
		contains(line, "remember=")
	][0]
	remember_match := regex.find_n(`remember=(\d+)`, system_auth_line, 1)
	count(remember_match) > 0
	remember_value := to_number(regex.find_n(`\d+`, remember_match[0], 1)[0])
	remember_value < 5
	msg := sprintf("CIS 5.4.3: Password remember value is %d, should be 5 or more", [remember_value])
}

# CIS 5.4.4: Password hashing algorithm SHA-512
violations contains msg if {
	not check_pam_file("system_auth", "sha512")
	not check_pam_file("password_auth", "sha512")
	msg := "CIS 5.4.4: Password hashing algorithm not set to SHA-512"
}

# CIS 5.5.1.1: PASS_MIN_DAYS
violations contains msg if {
	input.pam.pass_min_days
	to_number(input.pam.pass_min_days) < 1
	msg := sprintf("CIS 5.5.1.1: PASS_MIN_DAYS is %s, should be 1 or more", [input.pam.pass_min_days])
}

# CIS 5.5.1.2: PASS_MAX_DAYS
violations contains msg if {
	input.pam.pass_max_days
	to_number(input.pam.pass_max_days) > 365
	msg := sprintf("CIS 5.5.1.2: PASS_MAX_DAYS is %s, should be 365 or less", [input.pam.pass_max_days])
}

# CIS 5.5.1.3: PASS_WARN_AGE
violations contains msg if {
	input.pam.pass_warn_age
	to_number(input.pam.pass_warn_age) < 7
	msg := sprintf("CIS 5.5.1.3: PASS_WARN_AGE is %s, should be 7 or more", [input.pam.pass_warn_age])
}

# CIS 5.5.1.4: Inactive password lock
violations contains msg if {
	input.pam.inactive_days
	to_number(input.pam.inactive_days) > 30
	to_number(input.pam.inactive_days) >= 0
	msg := sprintf("CIS 5.5.1.4: Inactive password lock is %s days, should be 30 or less", [input.pam.inactive_days])
}

violations contains msg if {
	not input.pam.inactive_days
	msg := "CIS 5.5.1.4: Inactive password lock not configured"
}

# CIS 5.5.1.5: Password change dates in the past
violations contains msg if {
	some user in input.pam.users_with_future_password_change
	msg := sprintf("CIS 5.5.1.5: User %s has password change date in the future", [user])
}

# CIS 5.5.2: System accounts secured
violations contains msg if {
	some account in input.pam.system_accounts_with_login_shell
	msg := sprintf("CIS 5.5.2: System account %s has a login shell", [account])
}

# CIS 5.5.3: Root default GID 0
violations contains msg if {
	input.pam.root_gid
	to_number(input.pam.root_gid) != 0
	msg := sprintf("CIS 5.5.3: Root account GID is %s, should be 0", [input.pam.root_gid])
}

# CIS 5.5.4: Default umask 027 or more restrictive
violations contains msg if {
	input.pam.default_umask
	umask_value := to_number(input.pam.default_umask)
	umask_value > 27
	not umask_value in [77, 177, 277, 377]
	msg := sprintf("CIS 5.5.4: Default umask is %s, should be 027 or more restrictive", [input.pam.default_umask])
}

violations contains msg if {
	not input.pam.default_umask
	msg := "CIS 5.5.4: Default umask not configured"
}

# CIS 5.5.5: Shell timeout (TMOUT)
violations contains msg if {
	input.pam.tmout
	to_number(input.pam.tmout) > 900
	msg := sprintf("CIS 5.5.5: TMOUT is %s seconds, should be 900 or less", [input.pam.tmout])
}

violations contains msg if {
	input.pam.tmout
	to_number(input.pam.tmout) == 0
	msg := "CIS 5.5.5: TMOUT is disabled (0), should be 900 seconds or less"
}

violations contains msg if {
	not input.pam.tmout
	msg := "CIS 5.5.5: TMOUT not configured"
}

compliant if {
	count(violations) == 0
}

report := {
	"compliant": compliant,
	"violations": violations,
	"total_violations": count(violations),
	"controls_checked": 17,
	"section": "5.4-5.5 PAM and User Accounts",
	"benchmark": "CIS Rocky Linux 8 v2.0.0",
}
