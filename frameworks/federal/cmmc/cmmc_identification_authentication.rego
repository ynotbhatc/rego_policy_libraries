package cmmc.identification_authentication

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.5: Identification & Authentication
# NIST SP 800-171 Rev 2 — 11 Practices
# =============================================================================

# 3.5.1 — Identify system users, processes, and devices. (L1)
default compliant_3_5_1 := false
compliant_3_5_1 if {
    input.identity.unique_user_accounts == true
    input.identity.shared_accounts_documented == true
    input.identity.service_accounts_identified == true
}

violation_3_5_1 contains msg if {
    not input.identity.unique_user_accounts
    msg := "3.5.1: System users do not have unique identifiers"
}
violation_3_5_1 contains msg if {
    not input.identity.service_accounts_identified
    msg := "3.5.1: System processes and service accounts are not identified"
}

# 3.5.2 — Authenticate the identities of users, processes, or devices before
#          allowing access. (L1)
default compliant_3_5_2 := false
compliant_3_5_2 if {
    input.identity.authentication_required == true
    input.identity.password_auth_enabled == true
}

violation_3_5_2 contains msg if {
    not input.identity.authentication_required
    msg := "3.5.2: Authentication is not required before granting system access"
}

# 3.5.3 — Use multifactor authentication for local and network access to
#          privileged accounts. (L2)
default compliant_3_5_3 := false
compliant_3_5_3 if {
    input.identity.mfa_privileged_accounts == true
    input.identity.mfa_network_access == true
}

violation_3_5_3 contains msg if {
    not input.identity.mfa_privileged_accounts
    msg := "3.5.3: MFA is not enforced for privileged account access"
}
violation_3_5_3 contains msg if {
    not input.identity.mfa_network_access
    msg := "3.5.3: MFA is not enforced for network access to privileged accounts"
}

# 3.5.4 — Employ replay-resistant authentication mechanisms for network access
#          to privileged and non-privileged accounts. (L2)
default compliant_3_5_4 := false
compliant_3_5_4 if {
    input.identity.replay_resistant_auth == true
    input.identity.kerberos_or_pki == true
}

violation_3_5_4 contains msg if {
    not input.identity.replay_resistant_auth
    msg := "3.5.4: Replay-resistant authentication is not implemented for network access"
}

# 3.5.5 — Employ automated tools or mechanisms to enforce CUI account
#          management, including disabling accounts after inactivity. (L2)
default compliant_3_5_5 := false
compliant_3_5_5 if {
    input.identity.automated_account_management == true
    input.identity.inactive_account_disable_days <= 35
}

violation_3_5_5 contains msg if {
    not input.identity.automated_account_management
    msg := "3.5.5: No automated tool enforcing account management policies"
}
violation_3_5_5 contains msg if {
    input.identity.inactive_account_disable_days > 35
    msg := sprintf("3.5.5: Inactive accounts disabled after %v days (must be ≤35)", [input.identity.inactive_account_disable_days])
}

# 3.5.6 — Manage system identifiers by disabling the user identifier after a
#          defined inactivity period. (L2)
default compliant_3_5_6 := false
compliant_3_5_6 if {
    input.identity.identifier_management_policy == true
    input.identity.inactive_account_disable_days <= 35
    input.identity.terminated_accounts_disabled_immediately == true
}

violation_3_5_6 contains msg if {
    not input.identity.identifier_management_policy
    msg := "3.5.6: No policy for managing and disabling inactive system identifiers"
}
violation_3_5_6 contains msg if {
    not input.identity.terminated_accounts_disabled_immediately
    msg := "3.5.6: Terminated user accounts are not disabled immediately upon separation"
}

# 3.5.7 — Enforce a minimum password complexity and change when new passwords
#          are created. (L2)
default compliant_3_5_7 := false
compliant_3_5_7 if {
    input.identity.password_min_length >= 12
    input.identity.password_complexity_uppercase == true
    input.identity.password_complexity_lowercase == true
    input.identity.password_complexity_numbers == true
    input.identity.password_complexity_special == true
}

violation_3_5_7 contains msg if {
    input.identity.password_min_length < 12
    msg := sprintf("3.5.7: Minimum password length %v is less than required 12 characters", [input.identity.password_min_length])
}
violation_3_5_7 contains msg if {
    not input.identity.password_complexity_uppercase
    msg := "3.5.7: Password policy does not require uppercase characters"
}
violation_3_5_7 contains msg if {
    not input.identity.password_complexity_numbers
    msg := "3.5.7: Password policy does not require numeric characters"
}
violation_3_5_7 contains msg if {
    not input.identity.password_complexity_special
    msg := "3.5.7: Password policy does not require special characters"
}

# 3.5.8 — Prohibit password reuse for a specified number of generations. (L2)
default compliant_3_5_8 := false
compliant_3_5_8 if {
    input.identity.password_history_count >= 5
}

violation_3_5_8 contains msg if {
    input.identity.password_history_count < 5
    msg := sprintf("3.5.8: Password history only prevents reuse of %v passwords (minimum 5 required)", [input.identity.password_history_count])
}

# 3.5.9 — Allow temporary password use with an immediate change requirement. (L2)
default compliant_3_5_9 := false
compliant_3_5_9 if {
    input.identity.temp_password_change_on_first_login == true
    input.identity.temp_password_expiry_hours <= 24
}

violation_3_5_9 contains msg if {
    not input.identity.temp_password_change_on_first_login
    msg := "3.5.9: Temporary passwords do not require immediate change on first use"
}
violation_3_5_9 contains msg if {
    input.identity.temp_password_expiry_hours > 24
    msg := sprintf("3.5.9: Temporary passwords expire after %v hours (must be ≤24)", [input.identity.temp_password_expiry_hours])
}

# 3.5.10 — Store and transmit only cryptographically protected passwords. (L2)
default compliant_3_5_10 := false
compliant_3_5_10 if {
    input.identity.passwords_hashed == true
    input.identity.hash_algorithm != "md5"
    input.identity.hash_algorithm != "sha1"
    input.identity.passwords_transmitted_encrypted == true
}

violation_3_5_10 contains msg if {
    not input.identity.passwords_hashed
    msg := "3.5.10: Passwords are not stored using cryptographic hashing"
}
violation_3_5_10 contains msg if {
    input.identity.hash_algorithm == "md5"
    msg := "3.5.10: Passwords are hashed with MD5 — must use SHA-256 or stronger"
}
violation_3_5_10 contains msg if {
    input.identity.hash_algorithm == "sha1"
    msg := "3.5.10: Passwords are hashed with SHA-1 — must use SHA-256 or stronger"
}
violation_3_5_10 contains msg if {
    not input.identity.passwords_transmitted_encrypted
    msg := "3.5.10: Passwords are transmitted without encryption"
}

# 3.5.11 — Obscure feedback of authentication information during the
#           authentication process. (L2)
default compliant_3_5_11 := false
compliant_3_5_11 if {
    input.identity.password_masking_enabled == true
    input.identity.failed_login_no_detail == true
}

violation_3_5_11 contains msg if {
    not input.identity.password_masking_enabled
    msg := "3.5.11: Authentication feedback (password echo) is not obscured"
}
violation_3_5_11 contains msg if {
    not input.identity.failed_login_no_detail
    msg := "3.5.11: Failed authentication attempts reveal excessive detail about credentials"
}

# ---------------------------------------------------------------------------
# Aggregate compliance
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        array.concat(
            [v | some v in violation_3_5_1],
            [v | some v in violation_3_5_2]
        ),
        array.concat(
            [v | some v in violation_3_5_3],
            [v | some v in violation_3_5_4]
        )
    ),
    array.concat(
        array.concat(
            [v | some v in violation_3_5_5],
            [v | some v in violation_3_5_6]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_3_5_7],
                [v | some v in violation_3_5_8]
            ),
            array.concat(
                [v | some v in violation_3_5_9],
                array.concat(
                    [v | some v in violation_3_5_10],
                    [v | some v in violation_3_5_11]
                )
            )
        )
    )
)

practices := [
    {"id": "3.5.1",  "level": 1, "compliant": compliant_3_5_1},
    {"id": "3.5.2",  "level": 1, "compliant": compliant_3_5_2},
    {"id": "3.5.3",  "level": 2, "compliant": compliant_3_5_3},
    {"id": "3.5.4",  "level": 2, "compliant": compliant_3_5_4},
    {"id": "3.5.5",  "level": 2, "compliant": compliant_3_5_5},
    {"id": "3.5.6",  "level": 2, "compliant": compliant_3_5_6},
    {"id": "3.5.7",  "level": 2, "compliant": compliant_3_5_7},
    {"id": "3.5.8",  "level": 2, "compliant": compliant_3_5_8},
    {"id": "3.5.9",  "level": 2, "compliant": compliant_3_5_9},
    {"id": "3.5.10", "level": 2, "compliant": compliant_3_5_10},
    {"id": "3.5.11", "level": 2, "compliant": compliant_3_5_11},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false
compliant if count(all_violations) == 0

compliance_report := {
    "domain": "Identification & Authentication",
    "domain_id": "3.5",
    "total_practices": 11,
    "passing": passing_count,
    "failing": 11 - passing_count,
    "compliant": compliant,
    "violations": all_violations,
}
