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


# ── 5.2.2.x -- the Conditional Access cluster ────────────────────────
# Fourteen further controls, all evaluable from the Conditional Access
# policies already collected. CIS documents these as portal steps, so
# every one of them reaches its answer by a path the benchmark does not
# describe -- recorded in evidence_strength for the subsection rather
# than per control.
#
# Shared shape: a control is satisfied when SOME enabled policy has the
# required condition and control. A disabled or report-only policy
# enforces nothing and must not satisfy anything.

session(p) := object.get(p, "session_controls", {})

# CIS 5.2.2.4 -- sign-in frequency, non-persistent browser sessions.
default signin_frequency_enforced := false

signin_frequency_enforced if {
	some p in enabled_policies
	object.get(session(p), ["signInFrequency", "isEnabled"], false) == true
	object.get(session(p), ["persistentBrowser", "mode"], "") == "never"
}

violation contains msg if {
	available("conditional_access_policies")
	not signin_frequency_enforced
	msg := "CIS 5.2.2.4: no enabled Conditional Access policy sets a sign-in frequency with browser sessions made non-persistent, so a stolen session cookie stays valid indefinitely"
}

# CIS 5.2.2.5 -- phishing-resistant MFA for administrators.
default phishing_resistant_admin_mfa := false

phishing_resistant_admin_mfa if {
	some p in enabled_policies
	targets_admin_roles(p)
	contains(lower(object.get(p, ["grant_controls", "authenticationStrength", "displayName"], "")), "phishing-resistant")
}

violation contains msg if {
	available("conditional_access_policies")
	not phishing_resistant_admin_mfa
	msg := "CIS 5.2.2.5: phishing-resistant MFA strength is not required for administrators; a policy requiring generic MFA still admits phishable factors"
}

# CIS 5.2.2.6 / 5.2.2.7 / 5.2.2.8 -- Identity Protection risk policies.
risk_policy_exists(field) if {
	some p in enabled_policies
	count(object.get(p, ["conditions", field], [])) > 0
}

violation contains msg if {
	available("conditional_access_policies")
	not risk_policy_exists("userRiskLevels")
	msg := "CIS 5.2.2.6: no enabled Identity Protection user risk policy exists, so a user flagged as compromised is not challenged or blocked"
}

violation contains msg if {
	available("conditional_access_policies")
	not risk_policy_exists("signInRiskLevels")
	msg := "CIS 5.2.2.7: no enabled Identity Protection sign-in risk policy exists, so a risky sign-in is not challenged"
}

default signin_risk_blocked := false

signin_risk_blocked if {
	some p in enabled_policies
	levels := object.get(p, ["conditions", "signInRiskLevels"], [])
	"high" in levels
	"medium" in levels
}

violation contains msg if {
	available("conditional_access_policies")
	not signin_risk_blocked
	msg := "CIS 5.2.2.8: sign-in risk is not blocked for both medium and high risk levels"
}

# CIS 5.2.2.9 / 5.2.2.10 -- managed device required.
requires_compliant_device(p) if {
	some c in object.get(p, ["grant_controls", "builtInControls"], [])
	c in {"compliantDevice", "domainJoinedDevice"}
}

default managed_device_required := false

managed_device_required if {
	some p in enabled_policies
	requires_compliant_device(p)
	targets_all_users(p)
}

violation contains msg if {
	available("conditional_access_policies")
	not managed_device_required
	msg := "CIS 5.2.2.9: no enabled Conditional Access policy requires a managed device for authentication"
}

default managed_device_for_registration := false

managed_device_for_registration if {
	some p in enabled_policies
	requires_compliant_device(p)
	object.get(p, ["conditions", "applications", "includeUserActions"], []) != []
}

violation contains msg if {
	available("conditional_access_policies")
	not managed_device_for_registration
	msg := "CIS 5.2.2.10: no enabled Conditional Access policy requires a managed device to register security information, so an attacker can enrol their own MFA method"
}

# CIS 5.2.2.11 -- sign-in frequency for Intune enrolment.
default intune_enrolment_frequency := false

intune_enrolment_frequency if {
	some p in enabled_policies
	object.get(session(p), ["signInFrequency", "frequencyInterval"], "") == "everyTime"
}

violation contains msg if {
	available("conditional_access_policies")
	not intune_enrolment_frequency
	msg := "CIS 5.2.2.11: sign-in frequency for Intune enrollment is not set to every time"
}

# CIS 5.2.2.12 -- device code flow blocked.
default device_code_blocked := false

device_code_blocked if {
	some p in enabled_policies
	some f in object.get(p, ["conditions", "authenticationFlows", "transferMethods"], [])
	f == "deviceCodeFlow"
	some g in object.get(p, ["grant_controls", "builtInControls"], [])
	g == "block"
}

violation contains msg if {
	available("conditional_access_policies")
	not device_code_blocked
	msg := "CIS 5.2.2.12: the device code sign-in flow is not blocked; it is a common phishing vector because the victim authenticates on their own device"
}

# CIS 5.2.2.13 -- periodic reauthentication.
violation contains msg if {
	available("conditional_access_policies")
	not signin_frequency_enforced
	msg := "CIS 5.2.2.13: periodic reauthentication is not required for all users -- no enabled policy sets a sign-in frequency"
}

# CIS 5.2.2.14 / 5.2.2.15 -- named locations.
violation contains msg if {
	available("named_locations")
	count([l | some l in input.entra.named_locations; l.is_trusted == true]) == 0
	msg := "CIS 5.2.2.14: no trusted named locations are defined, so location cannot be used as a signal in Conditional Access"
}

violation contains msg if {
	available("named_locations")
	count([l |
		some l in input.entra.named_locations
		count(object.get(l, "countries_and_regions", [])) > 0
	]) == 0
	msg := "CIS 5.2.2.15: no exclusionary geographic access controls are utilized -- no country or region named location is defined"
}

# CIS 5.2.2.16 -- token protection.
default token_protection_enforced := false

token_protection_enforced if {
	some p in enabled_policies
	object.get(session(p), ["secureSignInSession", "isEnabled"], false) == true
}

violation contains msg if {
	available("conditional_access_policies")
	not token_protection_enforced
	msg := "CIS 5.2.2.16: token protection is not enforced for session tokens, so a stolen refresh token can be replayed from another device"
}

# CIS 5.2.2.17 -- authentication transfer blocked.
default auth_transfer_blocked := false

auth_transfer_blocked if {
	some p in enabled_policies
	some f in object.get(p, ["conditions", "authenticationFlows", "transferMethods"], [])
	f == "authenticationTransfer"
	some g in object.get(p, ["grant_controls", "builtInControls"], [])
	g == "block"
}

violation contains msg if {
	available("conditional_access_policies")
	not auth_transfer_blocked
	msg := "CIS 5.2.2.17: authentication transfer is not blocked, so a session can be handed from a desktop to an attacker-controlled device"
}


# ── 5.1.4.x -- device registration ───────────────────────────────────
# Five controls from one beta policy object. CIS documents these as
# portal steps; recorded in evidence_strength for the subsection.

MAX_DEVICES_PER_USER := 20

violation contains msg if {
	available("device_registration_policy")
	input.entra.device_registration.azure_ad_join_allowed_to_join == "all"
	msg := "CIS 5.1.4.1: the ability to join devices to Entra is not restricted -- every user may join a device, so an attacker with credentials can register one"
}

violation contains msg if {
	available("device_registration_policy")
	to_number(object.get(input.entra.device_registration, "user_device_quota", 0)) > MAX_DEVICES_PER_USER
	msg := sprintf("CIS 5.1.4.2: the maximum number of devices per user is %v; the benchmark expects a limit of %d or fewer", [input.entra.device_registration.user_device_quota, MAX_DEVICES_PER_USER])
}

violation contains msg if {
	available("device_registration_policy")
	input.entra.device_registration.local_admin_global_admins_enabled == true
	msg := "CIS 5.1.4.3: the Global Administrator role is added as a local administrator during Entra join, which extends tenant-wide privilege onto every joined device"
}

violation contains msg if {
	available("device_registration_policy")
	input.entra.device_registration.local_admin_registering_user_enabled == "all"
	msg := "CIS 5.1.4.4: local administrator assignment is not limited during Entra join -- the registering user becomes a local admin on the device"
}

violation contains msg if {
	available("laps_policy")
	input.entra.laps_enabled == false
	msg := "CIS 5.1.4.5: Local Administrator Password Solution is not enabled, so local administrator passwords are neither randomised nor rotated"
}

# ── 5.1.5.x -- application credential management ─────────────────────
# The app management policy expresses restrictions as a list of rules
# rather than flags, so each control asks whether a rule of its kind
# exists and is enabled.

app_restriction_present(collection, rule_type) if {
	some r in object.get(input.entra.app_management, collection, [])
	r.restrictionType == rule_type
	r.state == "enabled"
}

violation contains msg if {
	available("app_management_policy")
	not app_restriction_present("password_credentials", "passwordAddition")
	msg := "CIS 5.1.5.3: password addition is not blocked for applications, so a secret can be added to an existing app registration"
}

violation contains msg if {
	available("app_management_policy")
	not app_restriction_present("password_credentials", "passwordLifetime")
	msg := "CIS 5.1.5.4: no password lifetime restriction is enforced for applications, so an application password can exceed 180 days"
}

violation contains msg if {
	available("app_management_policy")
	not app_restriction_present("password_credentials", "symmetricKeyAddition")
	msg := "CIS 5.1.5.5: new application passwords are not required to be system-generated, so a weak secret can be supplied by hand"
}

violation contains msg if {
	available("app_management_policy")
	not app_restriction_present("key_credentials", "asymmetricKeyLifetime")
	msg := "CIS 5.1.5.6: no maximum certificate lifetime is enforced for applications, so an application certificate can exceed 180 days"
}

# ── 5.3.2 / 5.3.3 -- access reviews ──────────────────────────────────

review_covers(term) if {
	some r in input.entra.access_reviews
	contains(lower(object.get(r, "scope_query", "")), term)
}

violation contains msg if {
	available("access_reviews")
	not review_covers("guest")
	msg := "CIS 5.3.2: no access review is configured for guest users, so external access is never re-attested"
}

violation contains msg if {
	available("access_reviews")
	not review_covers("roleassignment")
	msg := "CIS 5.3.3: no access review is configured for privileged roles, so standing administrative access is never re-attested"
}


# ── Authenticator hardening and smart lockout ────────────────────────
# Five more controls, all riding on policy objects already fetched --
# they were simply not projected into the facts. CIS documents these as
# portal steps.

MAX_LOCKOUT_THRESHOLD := 10
MIN_LOCKOUT_DURATION_SECONDS := 60

# CIS 5.2.3.1 -- Authenticator must show app and location, and require
# number matching, so a push cannot be approved blind.
violation contains msg if {
	available("authentication_methods_policy")
	input.entra.authenticator.state == "enabled"
	some feature in ["number_matching_state", "show_app_information_state", "show_geographic_location_state"]
	input.entra.authenticator[feature] != "enabled"
	msg := sprintf("CIS 5.2.3.1: Microsoft Authenticator is not configured to protect against MFA fatigue -- '%s' is not enabled, so a push can be approved without seeing what is being approved", [feature])
}

# CIS 5.2.3.10 -- companion applications.
violation contains msg if {
	available("authentication_methods_policy")
	input.entra.authenticator.companion_app_allowed_state == "enabled"
	msg := "CIS 5.2.3.10: Microsoft Authenticator on companion applications is not disabled, which widens the surface on which an approval can be granted"
}

# CIS 5.2.3.8 / 5.2.3.9 -- smart lockout.
violation contains msg if {
	available("group_settings")
	input.entra.lockout.settings_present == true
	to_number(input.entra.lockout.threshold) > MAX_LOCKOUT_THRESHOLD
	msg := sprintf("CIS 5.2.3.8: the account lockout threshold is %v; the benchmark expects '10' or less", [input.entra.lockout.threshold])
}

violation contains msg if {
	available("group_settings")
	input.entra.lockout.settings_present == true
	to_number(input.entra.lockout.duration_seconds) < MIN_LOCKOUT_DURATION_SECONDS
	msg := sprintf("CIS 5.2.3.9: the account lockout duration in seconds is %v; the benchmark expects at least %d", [input.entra.lockout.duration_seconds, MIN_LOCKOUT_DURATION_SECONDS])
}

# CIS 5.1.3.4 -- Microsoft 365 group creation restricted.
violation contains msg if {
	available("group_settings")
	input.entra.group_creation.settings_present == true
	lower(object.get(input.entra.group_creation, "enabled", "")) == "true"
	input.entra.group_creation.allowed_group_id == ""
	msg := "CIS 5.1.3.4: users can create Microsoft 365 groups in Azure portals, APIs or PowerShell with no restricting group -- group membership drives access, so unmanaged creation undermines authorization"
}

# ── Fail closed on every gap the collector recorded ───────────────────
FACT_CONTROLS := {
	"authorization_policy": "5.1.2.2",
	"authentication_methods_policy": "5.2.3.5",
	"admin_consent_request_policy": "5.1.5.2",
	"on_premises_synchronization": "5.1.8.1",
	"conditional_access_policies": "5.2.2.1",
	"named_locations": "5.2.2.14",
	"device_registration_policy": "5.1.4.1",
	"laps_policy": "5.1.4.5",
	"app_management_policy": "5.1.5.3",
	"access_reviews": "5.3.2",
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
	"controls_evaluated": 50,
	"controls": [
		"5.1.2.1", "5.1.2.2", "5.1.2.3", "5.1.3.1", "5.1.3.4", "5.1.4.6",
		"5.1.4.1", "5.1.4.2", "5.1.4.3", "5.1.4.4", "5.1.4.5",
		"5.1.5.1", "5.1.5.2", "5.1.5.3", "5.1.5.4", "5.1.5.5", "5.1.5.6",
		"5.1.6.2", "5.1.6.3", "5.1.8.1",
		"5.2.2.1", "5.2.2.2", "5.2.2.3", "5.2.2.4", "5.2.2.5",
		"5.2.2.6", "5.2.2.7", "5.2.2.8", "5.2.2.9", "5.2.2.10",
		"5.2.2.11", "5.2.2.12", "5.2.2.13", "5.2.2.14", "5.2.2.15",
		"5.2.2.16", "5.2.2.17",
		"5.2.3.1", "5.2.3.2", "5.2.3.3", "5.2.3.4", "5.2.3.5", "5.2.3.6",
		"5.2.3.7", "5.2.3.8", "5.2.3.9", "5.2.3.10",
		"5.3.1", "5.3.2", "5.3.3",
	],
	"facts_present": collected,
	"unavailable_facts": unavailable,
	# 5.1.2.1 is read from a /beta endpoint, which Microsoft documents as
	# subject to change and unsupported for production.
	"evidence_strength": {
		"5.2.2.x": "the 5.2.2 Conditional Access controls are evaluated from the policies Graph returns. CIS documents them as Entra portal steps and names no cmdlet, so these reach the benchmark's answer by a path it does not describe.",
		"5.1.2.1": "collected from Microsoft Graph /beta (users/{id}/authentication/requirements); CIS marks this control Manual and documents no automated procedure",
	},
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
