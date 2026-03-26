package cis_rhel9.pam_validation

import rego.v1

# CIS RHEL 9 Benchmark v2.0.0 - Section 5.2: PAM (Pluggable Authentication Modules)
# Validates PAM configuration for secure authentication

# =============================================================================
# CIS 5.2.1 - Ensure password creation requirements are configured
# =============================================================================

validate_pwquality_minlen if {
    to_number(input.pam.pwquality.minlen) >= 14
}

validate_pwquality_complexity if {
    # minclass OR (dcredit + ucredit + lcredit + ocredit) >= 4
    to_number(input.pam.pwquality.minclass) >= 4
}

validate_pwquality_complexity if {
    complexity_sum := (
        abs(to_number(input.pam.pwquality.dcredit)) +
        abs(to_number(input.pam.pwquality.ucredit)) +
        abs(to_number(input.pam.pwquality.lcredit)) +
        abs(to_number(input.pam.pwquality.ocredit))
    )
    complexity_sum >= 4
}

violations contains {
    "control_id": "5.2.1",
    "title": "Ensure password creation requirements are configured",
    "severity": "high",
    "description": "Password complexity requirements should be enforced",
    "status": "fail",
    "finding": sprintf("pwquality settings: minlen=%v minclass=%v dcredit=%v ucredit=%v lcredit=%v ocredit=%v", [
        input.pam.pwquality.minlen,
        input.pam.pwquality.minclass,
        input.pam.pwquality.dcredit,
        input.pam.pwquality.ucredit,
        input.pam.pwquality.lcredit,
        input.pam.pwquality.ocredit
    ]),
    "remediation": "Edit /etc/security/pwquality.conf and set minlen=14, minclass=4 (or dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1)"
} if {
    not validate_pwquality_minlen
}

violations contains {
    "control_id": "5.2.1",
    "title": "Ensure password creation requirements are configured",
    "severity": "high",
    "description": "Password complexity requirements should be enforced",
    "status": "fail",
    "finding": sprintf("pwquality complexity settings insufficient: minclass=%v dcredit=%v ucredit=%v lcredit=%v ocredit=%v", [
        input.pam.pwquality.minclass,
        input.pam.pwquality.dcredit,
        input.pam.pwquality.ucredit,
        input.pam.pwquality.lcredit,
        input.pam.pwquality.ocredit
    ]),
    "remediation": "Edit /etc/security/pwquality.conf and set minclass=4 or dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
} if {
    validate_pwquality_minlen
    not validate_pwquality_complexity
}

# =============================================================================
# CIS 5.2.2 - Ensure lockout for failed password attempts is configured
# =============================================================================

validate_faillock_deny if {
    to_number(input.pam.faillock.deny) > 0
    to_number(input.pam.faillock.deny) <= 5
}

validate_faillock_unlock_time if {
    to_number(input.pam.faillock.unlock_time) >= 900
}

violations contains {
    "control_id": "5.2.2",
    "title": "Ensure lockout for failed password attempts is configured",
    "severity": "high",
    "description": "Account lockout should be configured to prevent brute force attacks",
    "status": "fail",
    "finding": sprintf("faillock settings: deny=%v unlock_time=%v", [
        input.pam.faillock.deny,
        input.pam.faillock.unlock_time
    ]),
    "remediation": "Configure pam_faillock in /etc/pam.d/system-auth and /etc/pam.d/password-auth with deny=5 unlock_time=900"
} if {
    not validate_faillock_deny
}

violations contains {
    "control_id": "5.2.2",
    "title": "Ensure lockout for failed password attempts is configured",
    "severity": "high",
    "description": "Account lockout unlock time should be at least 15 minutes (900 seconds)",
    "status": "fail",
    "finding": sprintf("faillock unlock_time=%v is too short (should be >= 900)", [input.pam.faillock.unlock_time]),
    "remediation": "Edit /etc/security/faillock.conf and set unlock_time=900"
} if {
    validate_faillock_deny
    not validate_faillock_unlock_time
}

# =============================================================================
# CIS 5.2.3 - Ensure password reuse is limited
# =============================================================================

validate_password_remember if {
    to_number(input.pam.pwhistory.remember) >= 5
}

violations contains {
    "control_id": "5.2.3",
    "title": "Ensure password reuse is limited",
    "severity": "medium",
    "description": "Password history should prevent reuse of recent passwords",
    "status": "fail",
    "finding": sprintf("pam_pwhistory remember=%v (should be >= 5)", [input.pam.pwhistory.remember]),
    "remediation": "Configure pam_pwhistory in /etc/pam.d/system-auth and /etc/pam.d/password-auth with remember=5"
} if {
    not validate_password_remember
}

# =============================================================================
# CIS 5.2.4 - Ensure password hashing algorithm is SHA-512 or yescrypt
# =============================================================================

validate_password_hashing if {
    input.pam.password_hash_algorithm in ["sha512", "yescrypt"]
}

violations contains {
    "control_id": "5.2.4",
    "title": "Ensure password hashing algorithm is SHA-512 or yescrypt",
    "severity": "high",
    "description": "Password hashing should use strong algorithms (SHA-512 or yescrypt)",
    "status": "fail",
    "finding": sprintf("Password hashing algorithm: %v", [input.pam.password_hash_algorithm]),
    "remediation": "Edit /etc/pam.d/password-auth and /etc/pam.d/system-auth to use pam_unix.so with sha512 or yescrypt"
} if {
    not validate_password_hashing
}

# =============================================================================
# CIS 5.2.5 - Ensure all current passwords use the configured hashing algorithm
# =============================================================================

validate_all_passwords_hashed_correctly if {
    count(input.pam.users_with_weak_hashes) == 0
}

violations contains {
    "control_id": "5.2.5",
    "title": "Ensure all current passwords use the configured hashing algorithm",
    "severity": "medium",
    "description": "All user passwords should use the configured strong hashing algorithm",
    "status": "fail",
    "finding": sprintf("Users with weak password hashes: %v", [input.pam.users_with_weak_hashes]),
    "remediation": "Force affected users to change passwords: passwd --expire <username>"
} if {
    not validate_all_passwords_hashed_correctly
}

# =============================================================================
# CIS 5.2.6 - Ensure password minimum age is configured
# =============================================================================

validate_pass_min_days if {
    to_number(input.pam.login_defs.PASS_MIN_DAYS) >= 1
}

violations contains {
    "control_id": "5.2.6",
    "title": "Ensure password minimum age is configured",
    "severity": "medium",
    "description": "Minimum password age should be at least 1 day",
    "status": "fail",
    "finding": sprintf("PASS_MIN_DAYS=%v in /etc/login.defs", [input.pam.login_defs.PASS_MIN_DAYS]),
    "remediation": "Edit /etc/login.defs and set PASS_MIN_DAYS 1"
} if {
    not validate_pass_min_days
}

# =============================================================================
# CIS 5.2.7 - Ensure password maximum age is configured
# =============================================================================

validate_pass_max_days if {
    to_number(input.pam.login_defs.PASS_MAX_DAYS) <= 365
    to_number(input.pam.login_defs.PASS_MAX_DAYS) > 0
}

violations contains {
    "control_id": "5.2.7",
    "title": "Ensure password maximum age is configured",
    "severity": "medium",
    "description": "Maximum password age should be 365 days or less",
    "status": "fail",
    "finding": sprintf("PASS_MAX_DAYS=%v in /etc/login.defs", [input.pam.login_defs.PASS_MAX_DAYS]),
    "remediation": "Edit /etc/login.defs and set PASS_MAX_DAYS 365"
} if {
    not validate_pass_max_days
}

# =============================================================================
# CIS 5.2.8 - Ensure password expiration warning days is configured
# =============================================================================

validate_pass_warn_age if {
    to_number(input.pam.login_defs.PASS_WARN_AGE) >= 7
}

violations contains {
    "control_id": "5.2.8",
    "title": "Ensure password expiration warning days is configured",
    "severity": "low",
    "description": "Users should receive warning at least 7 days before password expiration",
    "status": "fail",
    "finding": sprintf("PASS_WARN_AGE=%v in /etc/login.defs", [input.pam.login_defs.PASS_WARN_AGE]),
    "remediation": "Edit /etc/login.defs and set PASS_WARN_AGE 7"
} if {
    not validate_pass_warn_age
}

# =============================================================================
# CIS 5.2.9 - Ensure inactive password lock is configured
# =============================================================================

validate_inactive_lock if {
    to_number(input.pam.useradd_defaults.INACTIVE) >= 0
    to_number(input.pam.useradd_defaults.INACTIVE) <= 30
}

violations contains {
    "control_id": "5.2.9",
    "title": "Ensure inactive password lock is configured",
    "severity": "medium",
    "description": "Accounts should be locked after password expiration period",
    "status": "fail",
    "finding": sprintf("INACTIVE=%v in /etc/default/useradd", [input.pam.useradd_defaults.INACTIVE]),
    "remediation": "Run: useradd -D -f 30"
} if {
    not validate_inactive_lock
}

# =============================================================================
# CIS 5.2.10 - Ensure all users last password change date is in the past
# =============================================================================

validate_password_change_dates if {
    count(input.pam.users_with_future_password_change) == 0
}

violations contains {
    "control_id": "5.2.10",
    "title": "Ensure all users last password change date is in the past",
    "severity": "medium",
    "description": "No user should have a future password change date",
    "status": "fail",
    "finding": sprintf("Users with future password change dates: %v", [input.pam.users_with_future_password_change]),
    "remediation": "Investigate and correct password change dates for affected users"
} if {
    not validate_password_change_dates
}

# =============================================================================
# CIS 5.2.11 - Ensure system accounts are secured
# =============================================================================

validate_system_accounts_secured if {
    count(input.pam.system_accounts_with_login_shell) == 0
}

violations contains {
    "control_id": "5.2.11",
    "title": "Ensure system accounts are secured",
    "severity": "high",
    "description": "System accounts should not have valid login shells",
    "status": "fail",
    "finding": sprintf("System accounts with valid login shells: %v", [input.pam.system_accounts_with_login_shell]),
    "remediation": "Run: usermod -s /usr/sbin/nologin <account>"
} if {
    not validate_system_accounts_secured
}

# =============================================================================
# CIS 5.2.12 - Ensure default user shell timeout is configured
# =============================================================================

validate_shell_timeout if {
    to_number(input.pam.shell_timeout.TMOUT) > 0
    to_number(input.pam.shell_timeout.TMOUT) <= 900
}

violations contains {
    "control_id": "5.2.12",
    "title": "Ensure default user shell timeout is configured",
    "severity": "medium",
    "description": "Shell timeout should be configured to automatically logout idle sessions",
    "status": "fail",
    "finding": sprintf("TMOUT=%v (should be <= 900)", [input.pam.shell_timeout.TMOUT]),
    "remediation": "Edit /etc/profile.d/tmout.sh and set TMOUT=900 readonly TMOUT export TMOUT"
} if {
    not validate_shell_timeout
}

# =============================================================================
# CIS 5.2.13 - Ensure default group for the root account is GID 0
# =============================================================================

validate_root_gid if {
    input.pam.root_user.gid == "0"
}

violations contains {
    "control_id": "5.2.13",
    "title": "Ensure default group for the root account is GID 0",
    "severity": "high",
    "description": "The root account should have GID 0",
    "status": "fail",
    "finding": sprintf("root account GID: %v (should be 0)", [input.pam.root_user.gid]),
    "remediation": "Run: usermod -g 0 root"
} if {
    not validate_root_gid
}

# =============================================================================
# CIS 5.2.14 - Ensure default user umask is configured
# =============================================================================

validate_umask if {
    input.pam.default_umask in ["027", "077"]
}

violations contains {
    "control_id": "5.2.14",
    "title": "Ensure default user umask is configured",
    "severity": "medium",
    "description": "Default umask should be 027 or more restrictive",
    "status": "fail",
    "finding": sprintf("Default umask: %v (should be 027 or 077)", [input.pam.default_umask]),
    "remediation": "Edit /etc/profile and /etc/bashrc to set umask 027"
} if {
    not validate_umask
}

# =============================================================================
# CIS 5.2.15 - Ensure user accounts are locked after 35 days of inactivity
# =============================================================================

validate_users_inactivity_lock if {
    count(input.pam.users_without_inactivity_lock) == 0
}

violations contains {
    "control_id": "5.2.16",
    "title": "Ensure user accounts are locked after 35 days of inactivity",
    "severity": "medium",
    "description": "User accounts should be automatically locked after inactivity period",
    "status": "fail",
    "finding": sprintf("Users without inactivity lock (or > 35 days): %v", [input.pam.users_without_inactivity_lock]),
    "remediation": "Run: chage --inactive 30 <username> for each affected user"
} if {
    not validate_users_inactivity_lock
}

# =============================================================================
# Summary Functions
# =============================================================================

# Collect all PAM violations
pam_violations := violations

# Count total PAM controls
total_pam_controls := 16

# Count passed PAM controls
passed_pam_controls := total_pam_controls - count(pam_violations)

# PAM compliance percentage
pam_compliance_percentage := (passed_pam_controls / total_pam_controls) * 100
