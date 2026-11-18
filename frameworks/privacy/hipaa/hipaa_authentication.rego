# METADATA
# title: "HIPAA Security Rule — 45 CFR 164.312(d)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 25
#     cited: 1
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package hipaa.authentication

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(d)
# Technical Safeguard: Person or Entity Authentication
#
# Implement procedures to verify that a person or entity seeking access to
# ePHI is the one claimed.
#
# The regulation requires authentication procedures and names no mechanism: MFA, password length, age,
# history, lockout, session limits and certificate authentication are library choices reported in
# `advisories` (not cited to 45 CFR, no effect on `compliant`). Evidence that ePHI access is authenticated is
# input.authentication.ephi_access_requires_authentication == true, or MFA enabled for ePHI access.
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

advisories contains msg if {
	not input.mfa.enabled_for_phi_access
	msg := "Advisory (library practice, not a 45 CFR requirement): Multi-factor authentication is not enabled for ePHI access. MFA is required for all ePHI system access."
}

advisories contains msg if {
	input.mfa.enabled_for_phi_access
	not input.mfa.required_for_remote_access
	msg := "Advisory (library practice, not a 45 CFR requirement): MFA is not required for remote ePHI access. Remote access must always require MFA."
}

advisories contains msg if {
	input.mfa.enabled_for_phi_access
	not input.mfa.required_for_privileged_accounts
	msg := "Advisory (library practice, not a 45 CFR requirement): MFA is not required for privileged accounts. All privileged ePHI system accounts must use MFA."
}

advisories contains msg if {
	input.mfa.methods_allowed
	"sms" in input.mfa.methods_allowed
	not input.mfa.stronger_method_also_available
	msg := "Advisory (library practice, not a 45 CFR requirement): SMS-only MFA is configured. SMS is susceptible to SIM swapping. Offer TOTP or hardware key as alternatives."
}

# ---------------------------------------------------------------------------
# Password Policy
# ---------------------------------------------------------------------------

advisories contains msg if {
	input.password_policy.minimum_length < 12
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Minimum password length is %v characters. HIPAA guidance recommends minimum 12 characters for ePHI systems.",
		[input.password_policy.minimum_length],
	)
}

advisories contains msg if {
	not is_number(object.get(input, ["password_policy", "minimum_length"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — password_policy.minimum_length not collected. Password length requirement cannot be verified."
}

advisories contains msg if {
	not is_number(object.get(input, ["password_policy", "max_age_days"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — password_policy.max_age_days not collected. Password maximum age requirement cannot be verified."
}

advisories contains msg if {
	not is_number(object.get(input, ["password_policy", "history_count"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — password_policy.history_count not collected. Password history requirement cannot be verified."
}

advisories contains msg if {
	not is_number(object.get(input, ["password_policy", "lockout_threshold"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — password_policy.lockout_threshold not collected. Password lockout threshold requirement cannot be verified."
}

advisories contains msg if {
	not input.password_policy.complexity_required
	msg := "Advisory (library practice, not a 45 CFR requirement): Password complexity is not required. Passwords for ePHI access must meet complexity requirements."
}

advisories contains msg if {
	input.password_policy.max_age_days > 90
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Password maximum age is %v days. Passwords for ePHI access should be changed at least every 90 days.",
		[input.password_policy.max_age_days],
	)
}

advisories contains msg if {
	input.password_policy.history_count < 12
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Password history enforces only %v previous passwords. Enforce at least 12 to prevent password reuse.",
		[input.password_policy.history_count],
	)
}

advisories contains msg if {
	input.password_policy.lockout_threshold > 5
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Account lockout occurs after %v failed attempts. Maximum 5 failed attempts recommended for ePHI systems.",
		[input.password_policy.lockout_threshold],
	)
}

advisories contains msg if {
	not input.password_policy.lockout_enabled
	msg := "Advisory (library practice, not a 45 CFR requirement): Account lockout is not enabled. Accounts must lock after repeated failed authentication attempts."
}

# ---------------------------------------------------------------------------
# Default and shared credentials
# ---------------------------------------------------------------------------

_authentication_evidenced if input.authentication.ephi_access_requires_authentication == true

_authentication_evidenced if input.mfa.enabled_for_phi_access == true

violation_procedure contains msg if {
	not _authentication_evidenced
	msg := "HIPAA 164.312(d): evidence missing — no procedure verifying that a person or entity seeking ePHI access is the one claimed (authentication.ephi_access_requires_authentication or mfa.enabled_for_phi_access not true)."
}

violation_credentials contains msg if {
	some user in input.users
	user.using_default_password == true
	msg := sprintf(
		"HIPAA 164.312(d): User '%v' is using a default password. Default passwords must be changed before ePHI system access.",
		[user.username],
	)
}

advisories contains msg if {
	some user in input.users
	user.password_never_expires == true
	user.phi_access == true
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): User '%v' has a non-expiring password and ePHI access. Password expiration must be enforced for all ePHI users.",
		[user.username],
	)
}

advisories contains msg if {
	some acct in input.privileged_accounts
	not acct.mfa_enrolled
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Privileged account '%v' is not enrolled in MFA. All privileged accounts must use MFA.",
		[acct.username],
	)
}

# ---------------------------------------------------------------------------
# Session authentication
# ---------------------------------------------------------------------------

advisories contains msg if {
	not input.authentication.re_authentication_for_sensitive_ops
	msg := "Advisory (library practice, not a 45 CFR requirement): Re-authentication is not required for sensitive ePHI operations (delete, export). Require re-auth for high-risk actions."
}

advisories contains msg if {
	input.authentication.concurrent_sessions_unlimited
	msg := "Advisory (library practice, not a 45 CFR requirement): Unlimited concurrent sessions are permitted. Limit concurrent sessions for ePHI access to detect credential sharing."
}

# ---------------------------------------------------------------------------
# Certificate-based authentication (service accounts)
# ---------------------------------------------------------------------------

advisories contains msg if {
	some svc in input.users
	svc.is_service_account == true
	svc.phi_access == true
	not svc.certificate_based_auth
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Service account '%v' with ePHI access uses password authentication. Service accounts should use certificate-based authentication.",
		[svc.username],
	)
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if some msg in violation_procedure
violations contains msg if some msg in violation_credentials

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "164.312(d)",
	"title": "Person or Entity Authentication",
	"required": true,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"advisories": advisories,
	"controls": {
		"authentication_procedure": count(violation_procedure) == 0,
		"credential_hygiene": count(violation_credentials) == 0,
	},
}
