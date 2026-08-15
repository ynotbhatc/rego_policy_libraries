# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 5 -- Microsoft Entra admin center
#
# Section 5 is the largest in the benchmark: 63 of its 160
# recommendations, 39% of the whole. 20 are evaluated here.
#
# DROPPED FROM THE PRE-v7 LIBRARY: the "Security Defaults" check. v7.0.0
# has no Security Defaults recommendation. The check was removed rather
# than renumbered -- inventing an id is the defect this rewrite exists to
# fix.
#
# NOT EVALUATED, deliberately: 5.1.6.1 (allowed collaboration domains) and
# 5.3.4 (Global Administrator activation approval). CIS names no cmdlet
# for either and their endpoint is not established. Guessing one would
# manufacture a result; they are reported by the attestation module as
# unresolved until the live-tenant probe.
#
# Input contract (aac.m365.m365_entra_facts) -- see the module for the
# control-to-endpoint mapping. /policies/authorizationPolicy alone carries
# seven of these controls.

package cis_m365_v7.entra

import rego.v1

default compliant := false

# The most restrictive built-in guest role. Anything else grants guests
# more directory visibility than the benchmark permits.
GUEST_ROLE_RESTRICTED := "2af84b1e-32c8-42b7-82bc-daa82404023b"

default unavailable := {}

unavailable := input.entra.unavailable

default collected := false

collected if {
	input.entra.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

# ── /policies/authorizationPolicy -- seven controls ───────────────────

# CIS 5.1.2.2 -- users must not be able to register applications.
violation contains msg if {
	available("authorization_policy")
	input.entra.authorization_policy.allowed_to_create_apps == true
	msg := "CIS 5.1.2.2: users can register applications; any user can create an app registration and consent-phish other users"
}

# CIS 5.1.2.3 -- restrict non-admin users from creating tenants.
violation contains msg if {
	available("authorization_policy")
	input.entra.authorization_policy.allowed_to_create_tenants == true
	msg := "CIS 5.1.2.3: non-admin users are not restricted from creating tenants; a user can stand up an unmanaged tenant outside governance"
}

# CIS 5.1.3.1 -- users must not be able to create security groups.
violation contains msg if {
	available("authorization_policy")
	input.entra.authorization_policy.allowed_to_create_security_groups == true
	msg := "CIS 5.1.3.1: users can create security groups; group membership drives access, so unmanaged group creation undermines authorization"
}

# CIS 5.1.4.6 -- users restricted from recovering BitLocker keys.
violation contains msg if {
	available("authorization_policy")
	input.entra.authorization_policy.allowed_to_read_bitlocker_keys_for_owned_device == true
	msg := "CIS 5.1.4.6: users are not restricted from recovering BitLocker keys for their own device, which defeats disk encryption against a device thief who has the account"
}

# CIS 5.1.5.1 -- user consent to apps must not be allowed.
violation contains msg if {
	available("authorization_policy")
	count(input.entra.authorization_policy.permission_grant_policy_ids_assigned) > 0
	msg := "CIS 5.1.5.1: user consent to apps accessing company data on their behalf is still permitted; consent should be routed to an administrator"
}

# CIS 5.1.6.2 -- guest user access restricted.
violation contains msg if {
	available("authorization_policy")
	input.entra.authorization_policy.guest_user_role_id != GUEST_ROLE_RESTRICTED
	msg := sprintf("CIS 5.1.6.2: guest user access is not restricted -- guest role is '%s' rather than the most restrictive role, so guests can enumerate directory objects", [input.entra.authorization_policy.guest_user_role_id])
}

# CIS 5.1.6.3 -- guest invitations limited to admins and inviters.
violation contains msg if {
	available("authorization_policy")
	not input.entra.authorization_policy.allow_invites_from in {"adminsAndGuestInviters", "none"}
	msg := sprintf("CIS 5.1.6.3: guest user invitations are not limited -- allowInvitesFrom is '%s', so ordinary members can invite external guests", [input.entra.authorization_policy.allow_invites_from])
}

# ── Authentication methods policy ─────────────────────────────────────

# CIS 5.2.3.5 -- weak authentication methods disabled.
violation contains msg if {
	available("authentication_methods_policy")
	some m in input.entra.weak_methods_enabled
	msg := sprintf("CIS 5.2.3.5: weak authentication method '%s' is enabled; SMS and voice are phishable and interceptable", [m])
}

# CIS 5.2.3.6 -- system-preferred MFA enabled.
violation contains msg if {
	available("authentication_methods_policy")
	input.entra.system_preferred_mfa_state != "enabled"
	msg := "CIS 5.2.3.6: system-preferred multifactor authentication is not enabled, so users are not steered to their strongest registered method"
}

# CIS 5.2.3.7 -- email OTP disabled.
violation contains msg if {
	available("authentication_methods_policy")
	input.entra.email_otp_state == "enabled"
	msg := "CIS 5.2.3.7: the email OTP authentication method is enabled; a mailbox compromise then satisfies the second factor"
}

# ── Other single-endpoint controls ────────────────────────────────────

# CIS 5.1.5.2 -- admin consent workflow enabled.
violation contains msg if {
	available("admin_consent_request_policy")
	input.entra.admin_consent_workflow_enabled == false
	msg := "CIS 5.1.5.2: the admin consent workflow is not enabled, so users blocked from consenting have no governed request path and will route around it"
}

# CIS 5.1.8.1 -- password hash sync for hybrid deployments.
violation contains msg if {
	available("on_premises_synchronization")
	input.entra.on_premises_sync.configured == true
	input.entra.on_premises_sync.password_sync_enabled == false
	msg := "CIS 5.1.8.1: this is a hybrid deployment but password hash sync is not enabled, so leaked-credential detection cannot evaluate on-premises passwords"
}

# CIS 5.2.3.2 -- custom banned password list in use.
violation contains msg if {
	available("group_settings")
	input.entra.password_protection.custom_banned_list == ""
	msg := "CIS 5.2.3.2: no custom banned passwords list is configured; the global list does not cover organization-specific terms"
}

# CIS 5.2.3.3 -- password protection for on-prem Active Directory.
violation contains msg if {
	available("group_settings")
	input.entra.password_protection.on_premises_check_enabled != "True"
	msg := "CIS 5.2.3.3: password protection is not enabled for on-prem Active Directory, so weak passwords set on-premises are never evaluated"
}

# CIS 5.2.3.4 -- all member users MFA capable.
violation contains msg if {
	available("mfa_registration_report")
	some u in input.entra.mfa_registration.members_not_mfa_capable
	msg := sprintf("CIS 5.2.3.4: member user '%s' is not MFA capable -- no strong method is registered, so a Conditional Access grant requiring MFA cannot be satisfied", [u.user_principal_name])
}

# CIS 5.1.2.1 -- legacy per-user MFA must be disabled.
violation contains msg if {
	available("per_user_mfa")
	some u in input.entra.per_user_mfa.legacy_per_user_mfa
	msg := sprintf("CIS 5.1.2.1: per-user MFA is '%s' for '%s'; legacy per-user MFA should be disabled in favour of Conditional Access", [u.state, u.user_principal_name])
}

# ── Conditional Access and PIM (carried forward) ──────────────────────

enabled_policies contains p if {
	some p in input.entra.conditional_access_policies
	p.state == "enabled"
}

requires_mfa(p) if {
	some c in p.grant_controls.builtInControls
	c == "mfa"
}

targets_all_users(p) if {
	some u in p.conditions.users.includeUsers
	u == "All"
}

targets_admin_roles(p) if {
	count(p.conditions.users.includeRoles) > 0
}

default admin_mfa_enforced := false

admin_mfa_enforced if {
	some p in enabled_policies
	requires_mfa(p)
	targets_admin_roles(p)
}

default all_user_mfa_enforced := false

all_user_mfa_enforced if {
	some p in enabled_policies
	requires_mfa(p)
	targets_all_users(p)
}

default legacy_auth_blocked := false

legacy_auth_blocked if {
	some p in enabled_policies
	some c in p.conditions.clientAppTypes
	c in {"exchangeActiveSync", "other"}
	some g in p.grant_controls.builtInControls
	g == "block"
}

violation contains msg if {
	available("conditional_access_policies")
	not admin_mfa_enforced
	msg := "CIS 5.2.2.1: no enabled Conditional Access policy requires multifactor authentication for administrative roles"
}

violation contains msg if {
	available("conditional_access_policies")
	not all_user_mfa_enforced
	msg := "CIS 5.2.2.2: no enabled Conditional Access policy requires multifactor authentication for all users"
}

violation contains msg if {
	available("conditional_access_policies")
	not legacy_auth_blocked
	msg := "CIS 5.2.2.3: no enabled Conditional Access policy blocks legacy authentication; legacy protocols bypass multifactor authentication"
}

violation contains msg if {
	available("pim_role_assignments")
	input.entra.pim_available == false
	msg := "CIS 5.3.1: Privileged Identity Management is not in use; privileged role assignments are standing rather than activated on demand"
}

# ── Fail closed on every gap the collector recorded ───────────────────
FACT_CONTROLS := {
	"authorization_policy": "5.1.2.2",
	"authentication_methods_policy": "5.2.3.5",
	"admin_consent_request_policy": "5.1.5.2",
	"on_premises_synchronization": "5.1.8.1",
	"conditional_access_policies": "5.2.2.1",
	"pim_role_assignments": "5.3.1",
	"group_settings": "5.2.3.2",
	"mfa_registration_report": "5.2.3.4",
	"per_user_mfa": "5.1.2.1",
}

violation contains msg if {
	some key, reason in unavailable
	control := object.get(FACT_CONTROLS, key, "5.1.2.2")
	msg := sprintf("CIS %s: could not be evaluated -- %s (this is not a pass)", [control, reason])
}

violation contains msg if {
	not collected
	msg := "CIS 5.1.2.2: Entra facts were not collected, so whether users can register applications could not be established -- section 5 was not evaluated (this is not a pass)"
}

compliant if {
	collected
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "5",
	"name": "Microsoft Entra admin center",
	"section_total_controls": 63,
	"controls_evaluated": 20,
	"controls": [
		"5.1.2.1", "5.1.2.2", "5.1.2.3", "5.1.3.1", "5.1.4.6",
		"5.1.5.1", "5.1.5.2", "5.1.6.2", "5.1.6.3", "5.1.8.1",
		"5.2.2.1", "5.2.2.2", "5.2.2.3",
		"5.2.3.2", "5.2.3.3", "5.2.3.4", "5.2.3.5", "5.2.3.6", "5.2.3.7",
		"5.3.1",
	],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	# 5.1.2.1 is read from a /beta endpoint, which Microsoft documents as
	# subject to change and unsupported for production.
	"evidence_strength": {
		"5.1.2.1": "collected from Microsoft Graph /beta (users/{id}/authentication/requirements); CIS marks this control Manual and documents no automated procedure",
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
