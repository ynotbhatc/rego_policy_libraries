package scuba_m365.aad_test

import data.scuba_m365.aad
import rego.v1

# Fully compliant Microsoft Entra ID (AAD) facts — every MS.AAD control satisfied.
# Each single-rule test starts from this and flips exactly one field so that
# precisely one violation fires. Values are documentation-safe (no lab IPs).
compliant_input := {"scuba": {"aad": {
	"legacy_auth_blocked": true,
	"risk": {
		"high_risk_users_blocked": true,
		"high_risk_user_alerts": true,
		"high_risk_signins_blocked": true,
	},
	"auth": {
		"phishing_resistant_mfa_all_users": true,
		"mfa_enforced_all_users": true,
		# enabled == false satisfies MS.AAD.3.3 regardless of login_context_shown
		"authenticator": {"enabled": false, "login_context_shown": false},
		"methods_migration_complete": true,
		"weak_methods_disabled": true,
		"phishing_resistant_mfa_privileged": true,
		"managed_devices_required": true,
		"managed_devices_for_mfa_registration": true,
		"device_code_blocked": true,
	},
	"logging": {"security_logs_to_soc": true},
	"apps": {
		"registration_admin_only": true,
		"user_consent_restricted": true,
		"admin_consent_workflow": true,
		"password_addition_blocked": true,
		"password_lifetime_days": 90,
		"certificate_lifetime_days": 180,
	},
	"passwords": {"expiration_disabled": true},
	"privileged": {
		"global_admin_count": 4,
		"granular_roles_used": true,
		"cloud_only": true,
		"no_permanent_active_assignments": true,
		"pam_provisioning_only": true,
		"ga_activation_requires_approval": true,
		"assignment_alerts": true,
		"ga_activation_alerts": true,
		"role_activation_alerts": true,
	},
	"guests": {
		"access_restricted": true,
		"invites_restricted_to_inviter_role": true,
		"invite_domain_allowlist": true,
	},
	"ai": {"risky_agents_blocked": true},
}}}

# ── Compliant baseline: no violations ────────────────────────────────────────

test_aad_compliant_input_no_violations if {
	v := aad.violations with input as compliant_input
	count(v) == 0
}

test_aad_compliant_flag_true if {
	aad.compliant with input as compliant_input
}

# ── Group 1 — Legacy Authentication ──────────────────────────────────────────

test_aad_1_1_legacy_auth if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/legacy_auth_blocked", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.1.1v1 (SHALL): Legacy authentication is not blocked" in v
}

# ── Group 2 — Risk Based Policies ────────────────────────────────────────────

test_aad_2_1_high_risk_users if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/risk/high_risk_users_blocked", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.2.1v1 (SHALL): Users detected as high risk are not blocked" in v
}

test_aad_2_2_high_risk_user_alerts if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/risk/high_risk_user_alerts", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.2.2v1 (SHOULD): No administrator notification is sent when high-risk users are detected" in v
}

test_aad_2_3_high_risk_signins if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/risk/high_risk_signins_blocked", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.2.3v1 (SHALL): Sign-ins detected as high risk are not blocked" in v
}

# ── Group 3 — Strong Authentication & Secure Registration ────────────────────

test_aad_3_1_phishing_resistant_all if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/phishing_resistant_mfa_all_users", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.1v1 (SHALL): Phishing-resistant MFA is not enforced for all users" in v
}

test_aad_3_2_mfa_enforced_all if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/mfa_enforced_all_users", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.2v2 (SHALL): MFA is not enforced for all users" in v
}

# Authenticator enabled but not showing login context → 3.3 fires.
test_aad_3_3_authenticator_context if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/authenticator/enabled", "value": true}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.3v2 (SHALL): Microsoft Authenticator is enabled but not configured to show login context information" in v
}

test_aad_3_4_methods_migration if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/methods_migration_complete", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.4v1 (SHALL): Authentication Methods Manage Migration is not set to Migration Complete" in v
}

test_aad_3_5_weak_methods if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/weak_methods_disabled", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.5v2 (SHALL): SMS, Voice Call, or Email OTP authentication methods are not disabled" in v
}

test_aad_3_6_phishing_resistant_privileged if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/phishing_resistant_mfa_privileged", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.6v1 (SHALL): Phishing-resistant MFA is not required for highly privileged roles" in v
}

test_aad_3_7_managed_devices if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/managed_devices_required", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.7v1 (SHOULD): Managed devices are not required for authentication" in v
}

test_aad_3_8_managed_devices_mfa_registration if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/managed_devices_for_mfa_registration", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.8v1 (SHOULD): Managed devices are not required to register MFA" in v
}

test_aad_3_9_device_code if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/auth/device_code_blocked", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.3.9v1 (SHOULD): Device code authentication flow is not blocked" in v
}

# ── Group 4 — Centralized Log Collection ─────────────────────────────────────

test_aad_4_1_security_logs if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/logging/security_logs_to_soc", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.4.1v1 (SHALL): Security logs are not sent to the security operations center for monitoring" in v
}

# ── Group 5 — Application Registration and Consent ───────────────────────────

test_aad_5_1_registration_admin_only if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/apps/registration_admin_only", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.5.1v1 (SHALL): Non-administrators are allowed to register applications" in v
}

test_aad_5_2_user_consent if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/apps/user_consent_restricted", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.5.2v1 (SHALL): User consent to applications is not restricted" in v
}

test_aad_5_3_admin_consent_workflow if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/apps/admin_consent_workflow", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.5.3v1 (SHALL): Admin consent workflow for applications is not configured" in v
}

test_aad_5_5_password_addition if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/apps/password_addition_blocked", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.5.5v1 (SHOULD): Application password (client secret) addition is not blocked" in v
}

# password_lifetime_days > 180 → 5.6 fires.
test_aad_5_6_password_lifetime if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/apps/password_lifetime_days", "value": 200}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.5.6v1 (SHOULD): Application password lifetime is not restricted to 180 days or less" in v
}

# certificate_lifetime_days > 365 → 5.7 fires.
test_aad_5_7_certificate_lifetime if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/apps/certificate_lifetime_days", "value": 400}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.5.7v1 (SHOULD): Application certificate lifetime is not restricted to 365 days or less" in v
}

# ── Group 6 — Passwords ──────────────────────────────────────────────────────

test_aad_6_1_password_expiration if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/passwords/expiration_disabled", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.6.1v1 (SHALL): User password expiration is enabled (passwords SHALL NOT expire)" in v
}

# ── Group 7 — Highly Privileged User Access ──────────────────────────────────

# global_admin_count below the 2..8 window → 7.1 fires.
test_aad_7_1_global_admin_count if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/global_admin_count", "value": 1}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.1v1 (SHALL): Global Administrator role is not provisioned to a minimum of two and maximum of eight users" in v
}

test_aad_7_2_granular_roles if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/granular_roles_used", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.2v1 (SHALL): Privileged users are not provisioned with finer-grained roles instead of Global Administrator" in v
}

test_aad_7_3_cloud_only if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/cloud_only", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.3v1 (SHALL): Privileged users are not provisioned cloud-only accounts separate from on-premises/federated identities" in v
}

test_aad_7_4_no_permanent_active if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/no_permanent_active_assignments", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.4v1 (SHALL): Permanent active role assignments exist for highly privileged roles" in v
}

test_aad_7_5_pam_provisioning if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/pam_provisioning_only", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.5v1 (SHALL): Highly privileged role provisioning occurs outside of a PAM system" in v
}

test_aad_7_6_ga_activation_approval if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/ga_activation_requires_approval", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.6v1 (SHALL): Global Administrator role activation does not require approval" in v
}

test_aad_7_7_assignment_alerts if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/assignment_alerts", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.7v1 (SHALL): Eligible and active highly privileged role assignments do not trigger an alert" in v
}

test_aad_7_8_ga_activation_alerts if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/ga_activation_alerts", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.8v1 (SHALL): Global Administrator role activation does not trigger an alert" in v
}

test_aad_7_9_role_activation_alerts if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/role_activation_alerts", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.7.9v1 (SHOULD): Activation of other highly privileged roles does not trigger an alert" in v
}

# ── Group 8 — Guest User Access ──────────────────────────────────────────────

test_aad_8_1_guest_access_restricted if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/guests/access_restricted", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.8.1v1 (SHOULD): Guest users do not have limited or restricted access to directory objects" in v
}

test_aad_8_2_invites_restricted if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/guests/invites_restricted_to_inviter_role", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.8.2v1 (SHOULD): Guest invitations are not restricted to users with the Guest Inviter role" in v
}

test_aad_8_3_invite_domain_allowlist if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/guests/invite_domain_allowlist", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.8.3v1 (SHOULD): Guest invites are not restricted to authorized external domains" in v
}

# ── Group 9 — AI Security ────────────────────────────────────────────────────

test_aad_9_1_risky_agents if {
	inp := json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/ai/risky_agents_blocked", "value": false}])
	v := aad.violations with input as inp
	count(v) == 1
	"SCuBA MS.AAD.9.1v1 (SHALL): Risky AI agents are not blocked" in v
}

# ── Report shape ─────────────────────────────────────────────────────────────

# Even on empty input every field of the report resolves (defaults fire),
# so compliance_report must be a populated object, never {}.
test_aad_report_populated_on_empty_input if {
	result := aad.compliance_report with input as {}
	is_object(result)
	count(result) > 0
}
