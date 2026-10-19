# METADATA
# title: "CIS Section 5.4: Configure PAM"
# custom:
#   class: security
#   framework: cis_rhel_9
#   source: cis
#   domains: [linux, rhel]
#   coverage:
#     checks: 28
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_rhel9.pam

import rego.v1

# CIS Section 5.4: Configure PAM
# Password Authentication Module configuration validation

default compliant := false

# Helper to check if pwquality is configured
pwquality_configured if {
    input.pam.pwquality_installed
}

# Helper to parse pwquality.conf
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

# Active (non-comment, non-blank) lines of a PAM file; a commented-out directive is not configuration.
active_pam_lines(filename) := [l |
    some line in split(input.pam[filename], "\n")
    l := trim_space(line)
    l != ""
    not startswith(l, "#")
]

# Helper to check PAM files
check_pam_file(filename, pattern) if {
    some line in active_pam_lines(filename)
    contains(line, pattern)
}

violations contains msg if {
    not pwquality_configured
    msg := "CIS 5.4.1: pwquality package not installed"
}

# CIS 5.4.1: Ensure password creation requirements are configured
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

# CIS 5.4.2: Ensure lockout for failed password attempts is configured
violations contains msg if {
    not check_pam_file("system_auth", "pam_faillock.so")
    not check_pam_file("password_auth", "pam_faillock.so")
    msg := "CIS 5.4.2: pam_faillock not configured in PAM"
}

violations contains msg if {
    check_pam_file("system_auth", "pam_faillock.so")
    not check_pam_file("system_auth", "deny=")
    msg := "CIS 5.4.2: Account lockout threshold (deny) not configured"
}

violations contains msg if {
    check_pam_file("system_auth", "pam_faillock.so")
    not check_pam_file("system_auth", "unlock_time=")
    msg := "CIS 5.4.2: Account lockout time (unlock_time) not configured"
}

# CIS 5.4.3: Ensure password reuse is limited
violations contains msg if {
    not check_pam_file("system_auth", "remember=")
    not check_pam_file("password_auth", "remember=")
    msg := "CIS 5.4.3: Password reuse limitation not configured (remember parameter missing)"
}

violations contains msg if {
    check_pam_file("system_auth", "remember=")
    system_auth_line := [line |
        some line in active_pam_lines("system_auth")
        contains(line, "remember=")
    ][0]
    remember_match := regex.find_n(`remember=(\d+)`, system_auth_line, 1)
    count(remember_match) > 0
    remember_value := to_number(regex.find_n(`\d+`, remember_match[0], 1)[0])
    remember_value < 5
    msg := sprintf("CIS 5.4.3: Password remember value is %d, should be 5 or more", [remember_value])
}

# CIS 5.4.4: Ensure password hashing algorithm is SHA-512 or yescrypt
violations contains msg if {
    not check_pam_file("system_auth", "sha512")
    not check_pam_file("system_auth", "yescrypt")
    not check_pam_file("password_auth", "sha512")
    not check_pam_file("password_auth", "yescrypt")
    msg := "CIS 5.4.4: Password hashing algorithm not set to SHA-512 or yescrypt"
}

# CIS 5.5: User Accounts and Environment

# CIS 5.5.1: Ensure minimum days between password changes is configured
violations contains msg if {
    not input.pam.pass_min_days
    msg := "CIS 5.5.1.1: evidence missing — pam.pass_min_days (PASS_MIN_DAYS) not collected"
}

violations contains msg if {
    input.pam.pass_min_days
    to_number(input.pam.pass_min_days) < 1
    msg := sprintf("CIS 5.5.1.1: PASS_MIN_DAYS is %s, should be 1 or more", [input.pam.pass_min_days])
}

# CIS 5.5.2: Ensure password expiration is 365 days or less
violations contains msg if {
    not input.pam.pass_max_days
    msg := "CIS 5.5.1.2: evidence missing — pam.pass_max_days (PASS_MAX_DAYS) not collected"
}

violations contains msg if {
    input.pam.pass_max_days
    to_number(input.pam.pass_max_days) > 365
    msg := sprintf("CIS 5.5.1.2: PASS_MAX_DAYS is %s, should be 365 or less", [input.pam.pass_max_days])
}

# CIS 5.5.3: Ensure password expiration warning days is 7 or more
violations contains msg if {
    not input.pam.pass_warn_age
    msg := "CIS 5.5.1.3: evidence missing — pam.pass_warn_age (PASS_WARN_AGE) not collected"
}

violations contains msg if {
    input.pam.pass_warn_age
    to_number(input.pam.pass_warn_age) < 7
    msg := sprintf("CIS 5.5.1.3: PASS_WARN_AGE is %s, should be 7 or more", [input.pam.pass_warn_age])
}

# CIS 5.5.4: Ensure inactive password lock is 30 days or less
# -1 (and any negative value) disables the inactive lock, so it fails like a value over 30.
violations contains msg if {
    input.pam.inactive_days
    not inactive_within_30(to_number(input.pam.inactive_days))
    msg := sprintf("CIS 5.5.1.4: Inactive password lock is %v days, should be 0 to 30 (-1 disables it)", [input.pam.inactive_days])
}

inactive_within_30(n) if {
    n >= 0
    n <= 30
}

violations contains msg if {
    not input.pam.inactive_days
    msg := "CIS 5.5.1.4: Inactive password lock not configured"
}

# CIS 5.5.5: Ensure all users last password change date is in the past
violations contains msg if {
    some user in input.pam.users_with_future_password_change
    msg := sprintf("CIS 5.5.1.5: User %s has password change date in the future", [user])
}

# CIS 5.5.2: Ensure system accounts are secured
violations contains msg if {
    some account in input.pam.system_accounts_with_login_shell
    msg := sprintf("CIS 5.5.2: System account %s has a login shell", [account])
}

# CIS 5.5.3: Ensure default group for root is GID 0
violations contains msg if {
    object.get(input.pam, "root_gid", null) == null
    msg := "CIS 5.5.3: evidence missing — pam.root_gid not collected"
}

violations contains msg if {
    input.pam.root_gid
    to_number(input.pam.root_gid) != 0
    msg := sprintf("CIS 5.5.3: Root account GID is %s, should be 0", [input.pam.root_gid])
}

# CIS 5.5.4: Ensure default user umask is 027 or more restrictive
# 027 octal = 23: the umask must set at least the group-write, other-read/write/execute bits.
umask_restrictive(u) if bits.and(octal(u), 23) == 23

violations contains msg if {
    input.pam.default_umask
    not umask_restrictive(input.pam.default_umask)
    msg := sprintf("CIS 5.5.4: Default umask is %s, should be 027 or more restrictive", [input.pam.default_umask])
}

violations contains msg if {
    not input.pam.default_umask
    msg := "CIS 5.5.4: Default umask not configured"
}

# CIS 5.5.5: Ensure default user shell timeout is configured
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

# Compliance check
compliant if {
    count(violations) == 0
}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}
