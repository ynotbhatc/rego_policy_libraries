# CISA SCuBA — Secure Configuration Baseline for Microsoft Entra ID (AAD)
# 34 policies (MS.AAD.*), per the cisagov/ScubaGear baseline documents
# (TLP:CLEAR). Policy IDs are versioned individually (v1/v2 suffix);
# removed IDs (e.g. MS.AAD.5.4) are never reused and are not present here.
#
# Assessment against these baselines is required for U.S. federal civilian
# agencies by CISA Binding Operational Directive 25-01; the baselines are
# equally applicable to any M365 tenant.
#
# Input contract — input.scuba.aad.* (sources: Microsoft Graph
# /identity/conditionalAccess/policies, /policies/authorizationPolicy,
# /policies/authenticationMethodsPolicy, /roleManagement (PIM),
# /identityProtection; a tenant-facts collector must project them to the
# booleans/numbers below — field per policy, absence fails closed):
#
#   legacy_auth_blocked                        MS.AAD.1.1
#   risk.{high_risk_users_blocked, high_risk_user_alerts,
#         high_risk_signins_blocked}           MS.AAD.2.1-2.3
#   auth.{phishing_resistant_mfa_all_users, mfa_enforced_all_users,
#         authenticator: {enabled, login_context_shown},
#         methods_migration_complete, weak_methods_disabled,
#         phishing_resistant_mfa_privileged, managed_devices_required,
#         managed_devices_for_mfa_registration, device_code_blocked}
#                                              MS.AAD.3.1-3.9
#   logging.security_logs_to_soc               MS.AAD.4.1
#   apps.{registration_admin_only, user_consent_restricted,
#         admin_consent_workflow, password_addition_blocked,
#         password_lifetime_days, certificate_lifetime_days}
#                                              MS.AAD.5.1-5.7
#   passwords.expiration_disabled              MS.AAD.6.1
#   privileged.{global_admin_count, granular_roles_used, cloud_only,
#         no_permanent_active_assignments, pam_provisioning_only,
#         ga_activation_requires_approval, assignment_alerts,
#         ga_activation_alerts, role_activation_alerts}
#                                              MS.AAD.7.1-7.9
#   guests.{access_restricted, invites_restricted_to_inviter_role,
#         invite_domain_allowlist}             MS.AAD.8.1-8.3
#   ai.risky_agents_blocked                    MS.AAD.9.1
#
# OPA query path (module): /v1/data/scuba_m365/aad/compliance_report

package scuba_m365.aad

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Group 1 — Legacy Authentication ──────────────────────────────────────────

violations contains msg if {
	not input.scuba.aad.legacy_auth_blocked
	msg := "SCuBA MS.AAD.1.1v1 (SHALL): Legacy authentication is not blocked"
}

# ── Group 2 — Risk Based Policies ────────────────────────────────────────────

violations contains msg if {
	not input.scuba.aad.risk.high_risk_users_blocked
	msg := "SCuBA MS.AAD.2.1v1 (SHALL): Users detected as high risk are not blocked"
}

violations contains msg if {
	not input.scuba.aad.risk.high_risk_user_alerts
	msg := "SCuBA MS.AAD.2.2v1 (SHOULD): No administrator notification is sent when high-risk users are detected"
}

violations contains msg if {
	not input.scuba.aad.risk.high_risk_signins_blocked
	msg := "SCuBA MS.AAD.2.3v1 (SHALL): Sign-ins detected as high risk are not blocked"
}

# ── Group 3 — Strong Authentication & Secure Registration ────────────────────

violations contains msg if {
	not input.scuba.aad.auth.phishing_resistant_mfa_all_users
	msg := "SCuBA MS.AAD.3.1v1 (SHALL): Phishing-resistant MFA is not enforced for all users"
}

violations contains msg if {
	not input.scuba.aad.auth.mfa_enforced_all_users
	msg := "SCuBA MS.AAD.3.2v2 (SHALL): MFA is not enforced for all users"
}

# MS.AAD.3.3 is conditional on Microsoft Authenticator being enabled.
default authenticator_context_ok := false

authenticator_context_ok if {
	input.scuba.aad.auth.authenticator.enabled == false
}

authenticator_context_ok if {
	input.scuba.aad.auth.authenticator.enabled == true
	input.scuba.aad.auth.authenticator.login_context_shown == true
}

violations contains msg if {
	not authenticator_context_ok
	msg := "SCuBA MS.AAD.3.3v2 (SHALL): Microsoft Authenticator is enabled but not configured to show login context information"
}

violations contains msg if {
	not input.scuba.aad.auth.methods_migration_complete
	msg := "SCuBA MS.AAD.3.4v1 (SHALL): Authentication Methods Manage Migration is not set to Migration Complete"
}

violations contains msg if {
	not input.scuba.aad.auth.weak_methods_disabled
	msg := "SCuBA MS.AAD.3.5v2 (SHALL): SMS, Voice Call, or Email OTP authentication methods are not disabled"
}

violations contains msg if {
	not input.scuba.aad.auth.phishing_resistant_mfa_privileged
	msg := "SCuBA MS.AAD.3.6v1 (SHALL): Phishing-resistant MFA is not required for highly privileged roles"
}

violations contains msg if {
	not input.scuba.aad.auth.managed_devices_required
	msg := "SCuBA MS.AAD.3.7v1 (SHOULD): Managed devices are not required for authentication"
}

violations contains msg if {
	not input.scuba.aad.auth.managed_devices_for_mfa_registration
	msg := "SCuBA MS.AAD.3.8v1 (SHOULD): Managed devices are not required to register MFA"
}

violations contains msg if {
	not input.scuba.aad.auth.device_code_blocked
	msg := "SCuBA MS.AAD.3.9v1 (SHOULD): Device code authentication flow is not blocked"
}

# ── Group 4 — Centralized Log Collection ─────────────────────────────────────

violations contains msg if {
	not input.scuba.aad.logging.security_logs_to_soc
	msg := "SCuBA MS.AAD.4.1v1 (SHALL): Security logs are not sent to the security operations center for monitoring"
}

# ── Group 5 — Application Registration and Consent ───────────────────────────

violations contains msg if {
	not input.scuba.aad.apps.registration_admin_only
	msg := "SCuBA MS.AAD.5.1v1 (SHALL): Non-administrators are allowed to register applications"
}

violations contains msg if {
	not input.scuba.aad.apps.user_consent_restricted
	msg := "SCuBA MS.AAD.5.2v1 (SHALL): User consent to applications is not restricted"
}

violations contains msg if {
	not input.scuba.aad.apps.admin_consent_workflow
	msg := "SCuBA MS.AAD.5.3v1 (SHALL): Admin consent workflow for applications is not configured"
}

violations contains msg if {
	not input.scuba.aad.apps.password_addition_blocked
	msg := "SCuBA MS.AAD.5.5v1 (SHOULD): Application password (client secret) addition is not blocked"
}

default app_password_lifetime_ok := false

app_password_lifetime_ok if {
	input.scuba.aad.apps.password_lifetime_days <= 180
}

violations contains msg if {
	not app_password_lifetime_ok
	msg := "SCuBA MS.AAD.5.6v1 (SHOULD): Application password lifetime is not restricted to 180 days or less"
}

default app_cert_lifetime_ok := false

app_cert_lifetime_ok if {
	input.scuba.aad.apps.certificate_lifetime_days <= 365
}

violations contains msg if {
	not app_cert_lifetime_ok
	msg := "SCuBA MS.AAD.5.7v1 (SHOULD): Application certificate lifetime is not restricted to 365 days or less"
}

# ── Group 6 — Passwords ──────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.aad.passwords.expiration_disabled
	msg := "SCuBA MS.AAD.6.1v1 (SHALL): User password expiration is enabled (passwords SHALL NOT expire)"
}

# ── Group 7 — Highly Privileged User Access ──────────────────────────────────

default global_admin_count_ok := false

global_admin_count_ok if {
	c := input.scuba.aad.privileged.global_admin_count
	c >= 2
	c <= 8
}

violations contains msg if {
	not global_admin_count_ok
	msg := "SCuBA MS.AAD.7.1v1 (SHALL): Global Administrator role is not provisioned to a minimum of two and maximum of eight users"
}

violations contains msg if {
	not input.scuba.aad.privileged.granular_roles_used
	msg := "SCuBA MS.AAD.7.2v1 (SHALL): Privileged users are not provisioned with finer-grained roles instead of Global Administrator"
}

violations contains msg if {
	not input.scuba.aad.privileged.cloud_only
	msg := "SCuBA MS.AAD.7.3v1 (SHALL): Privileged users are not provisioned cloud-only accounts separate from on-premises/federated identities"
}

violations contains msg if {
	not input.scuba.aad.privileged.no_permanent_active_assignments
	msg := "SCuBA MS.AAD.7.4v1 (SHALL): Permanent active role assignments exist for highly privileged roles"
}

violations contains msg if {
	not input.scuba.aad.privileged.pam_provisioning_only
	msg := "SCuBA MS.AAD.7.5v1 (SHALL): Highly privileged role provisioning occurs outside of a PAM system"
}

violations contains msg if {
	not input.scuba.aad.privileged.ga_activation_requires_approval
	msg := "SCuBA MS.AAD.7.6v1 (SHALL): Global Administrator role activation does not require approval"
}

violations contains msg if {
	not input.scuba.aad.privileged.assignment_alerts
	msg := "SCuBA MS.AAD.7.7v1 (SHALL): Eligible and active highly privileged role assignments do not trigger an alert"
}

violations contains msg if {
	not input.scuba.aad.privileged.ga_activation_alerts
	msg := "SCuBA MS.AAD.7.8v1 (SHALL): Global Administrator role activation does not trigger an alert"
}

violations contains msg if {
	not input.scuba.aad.privileged.role_activation_alerts
	msg := "SCuBA MS.AAD.7.9v1 (SHOULD): Activation of other highly privileged roles does not trigger an alert"
}

# ── Group 8 — Guest User Access ──────────────────────────────────────────────

violations contains msg if {
	not input.scuba.aad.guests.access_restricted
	msg := "SCuBA MS.AAD.8.1v1 (SHOULD): Guest users do not have limited or restricted access to directory objects"
}

violations contains msg if {
	not input.scuba.aad.guests.invites_restricted_to_inviter_role
	msg := "SCuBA MS.AAD.8.2v1 (SHOULD): Guest invitations are not restricted to users with the Guest Inviter role"
}

violations contains msg if {
	not input.scuba.aad.guests.invite_domain_allowlist
	msg := "SCuBA MS.AAD.8.3v1 (SHOULD): Guest invites are not restricted to authorized external domains"
}

# ── Group 9 — AI Security ────────────────────────────────────────────────────

violations contains msg if {
	not input.scuba.aad.ai.risky_agents_blocked
	msg := "SCuBA MS.AAD.9.1v1 (SHALL): Risky AI agents are not blocked"
}

# ── Report ───────────────────────────────────────────────────────────────────

shall_violations := [v | some v in violations; contains(v, "(SHALL)")]

should_violations := [v | some v in violations; contains(v, "(SHOULD)")]

compliance_report := {
	"product": "Microsoft Entra ID",
	"baseline": "MS.AAD",
	"controls_evaluated": 34,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"shall_violation_count": count(shall_violations),
	"should_violation_count": count(should_violations),
}
