package hipaa.authentication

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(d)
# Technical Safeguard: Person or Entity Authentication
#
# Implement procedures to verify that a person or entity seeking access to
# ePHI is the one claimed.
#
# Input shape:
#   input.authentication        - authentication configuration
#   input.users[]               - user accounts
#   input.mfa                   - multi-factor authentication settings
#   input.password_policy       - password policy configuration
#   input.privileged_accounts[] - privileged/admin accounts
# =============================================================================

# ---------------------------------------------------------------------------
# Multi-Factor Authentication for ePHI systems
# ---------------------------------------------------------------------------

violation_mfa contains msg if {
    not input.mfa.enabled_for_phi_access
    msg := "HIPAA 164.312(d): Multi-factor authentication is not enabled for ePHI access. MFA is required for all ePHI system access."
}

violation_mfa contains msg if {
    input.mfa.enabled_for_phi_access
    not input.mfa.required_for_remote_access
    msg := "HIPAA 164.312(d): MFA is not required for remote ePHI access. Remote access must always require MFA."
}

violation_mfa contains msg if {
    input.mfa.enabled_for_phi_access
    not input.mfa.required_for_privileged_accounts
    msg := "HIPAA 164.312(d): MFA is not required for privileged accounts. All privileged ePHI system accounts must use MFA."
}

violation_mfa contains msg if {
    input.mfa.methods_allowed
    "sms" in input.mfa.methods_allowed
    not input.mfa.stronger_method_also_available
    msg := "HIPAA 164.312(d): SMS-only MFA is configured. SMS is susceptible to SIM swapping. Offer TOTP or hardware key as alternatives."
}

# ---------------------------------------------------------------------------
# Password Policy
# ---------------------------------------------------------------------------

violation_password_policy contains msg if {
    input.password_policy.minimum_length < 12
    msg := sprintf(
        "HIPAA 164.312(d): Minimum password length is %v characters. HIPAA guidance recommends minimum 12 characters for ePHI systems.",
        [input.password_policy.minimum_length]
    )
}

violation_password_policy contains msg if {
    not input.password_policy.complexity_required
    msg := "HIPAA 164.312(d): Password complexity is not required. Passwords for ePHI access must meet complexity requirements."
}

violation_password_policy contains msg if {
    input.password_policy.max_age_days > 90
    msg := sprintf(
        "HIPAA 164.312(d): Password maximum age is %v days. Passwords for ePHI access should be changed at least every 90 days.",
        [input.password_policy.max_age_days]
    )
}

violation_password_policy contains msg if {
    input.password_policy.history_count < 12
    msg := sprintf(
        "HIPAA 164.312(d): Password history enforces only %v previous passwords. Enforce at least 12 to prevent password reuse.",
        [input.password_policy.history_count]
    )
}

violation_password_policy contains msg if {
    input.password_policy.lockout_threshold > 5
    msg := sprintf(
        "HIPAA 164.312(d): Account lockout occurs after %v failed attempts. Maximum 5 failed attempts recommended for ePHI systems.",
        [input.password_policy.lockout_threshold]
    )
}

violation_password_policy contains msg if {
    not input.password_policy.lockout_enabled
    msg := "HIPAA 164.312(d): Account lockout is not enabled. Accounts must lock after repeated failed authentication attempts."
}

# ---------------------------------------------------------------------------
# Default and shared credentials
# ---------------------------------------------------------------------------

violation_credentials contains msg if {
    some user in input.users
    user.using_default_password == true
    msg := sprintf(
        "HIPAA 164.312(d): User '%v' is using a default password. Default passwords must be changed before ePHI system access.",
        [user.username]
    )
}

violation_credentials contains msg if {
    some user in input.users
    user.password_never_expires == true
    user.phi_access == true
    msg := sprintf(
        "HIPAA 164.312(d): User '%v' has a non-expiring password and ePHI access. Password expiration must be enforced for all ePHI users.",
        [user.username]
    )
}

violation_credentials contains msg if {
    some acct in input.privileged_accounts
    not acct.mfa_enrolled
    msg := sprintf(
        "HIPAA 164.312(d): Privileged account '%v' is not enrolled in MFA. All privileged accounts must use MFA.",
        [acct.username]
    )
}

# ---------------------------------------------------------------------------
# Session authentication
# ---------------------------------------------------------------------------

violation_session contains msg if {
    not input.authentication.re_authentication_for_sensitive_ops
    msg := "HIPAA 164.312(d): Re-authentication is not required for sensitive ePHI operations (delete, export). Require re-auth for high-risk actions."
}

violation_session contains msg if {
    input.authentication.concurrent_sessions_unlimited
    msg := "HIPAA 164.312(d): Unlimited concurrent sessions are permitted. Limit concurrent sessions for ePHI access to detect credential sharing."
}

# ---------------------------------------------------------------------------
# Certificate-based authentication (service accounts)
# ---------------------------------------------------------------------------

violation_service_accounts contains msg if {
    some svc in input.users
    svc.is_service_account == true
    svc.phi_access == true
    not svc.certificate_based_auth
    msg := sprintf(
        "HIPAA 164.312(d): Service account '%v' with ePHI access uses password authentication. Service accounts should use certificate-based authentication.",
        [svc.username]
    )
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if { some msg in violation_mfa }
violations contains msg if { some msg in violation_password_policy }
violations contains msg if { some msg in violation_credentials }
violations contains msg if { some msg in violation_session }
violations contains msg if { some msg in violation_service_accounts }

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

compliant if {
    count(violations) == 0
}

compliance_report := {
    "section":        "164.312(d)",
    "title":          "Person or Entity Authentication",
    "required":       true,
    "compliant":      compliant,
    "violation_count": count(violations),
    "violations":     violations,
    "controls": {
        "mfa_enabled":          count(violation_mfa) == 0,
        "password_policy":      count(violation_password_policy) == 0,
        "credential_hygiene":   count(violation_credentials) == 0,
        "session_auth":         count(violation_session) == 0,
        "service_accounts":     count(violation_service_accounts) == 0,
    },
}
