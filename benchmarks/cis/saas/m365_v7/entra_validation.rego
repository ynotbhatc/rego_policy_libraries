# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Section 5 -- Microsoft Entra admin center
#
# Section 5 is the largest in the benchmark: 63 of its 160
# recommendations, 39% of the whole. 53 are evaluated here.
#
# DROPPED FROM THE PRE-v7 LIBRARY: the "Security Defaults" check. v7.0.0
# has no Security Defaults recommendation. The check was removed rather
# than renumbered -- inventing an id is the defect this rewrite exists to
# fix.
#
# NOT EVALUATED HERE. The other 10 of section 5 are carried by the ledger
# in attestation_validation.rego:
#
#   5.1.2.4, 5.2.4.1-5   requires_attestation  no app-only read path
#   5.1.2.5, 5.1.2.6,
#   5.1.3.2, 5.1.3.3     unresolved            collectability unestablished
#
# 5.1.6.1, 5.3.4 and 5.3.5 were the third category -- known automatable,
# never built. All three are evaluated here as of 2026-08-25.
#
# This comment previously asserted that 5.1.6.1 and 5.3.4 "are reported by
# the attestation module as unresolved". They were not in any of its maps,
# and 5.3.5 was named nowhere at all -- so all three were silently absent
# from the assessment. A comment is not a mechanism: the report says what
# it emits, not what a source file claims it emits. That gap is now
# enforced by scripts/check_cis_coverage.py rather than described here.
#
# Input contract (aac.m365.m365_entra_facts) -- see the module for the
# control-to-endpoint mapping. /policies/authorizationPolicy alone carries
# seven of these controls.

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 76
#     cited: 68
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_m365_v7.entra

import rego.v1

default compliant := false

# The most restrictive built-in guest role. Anything else grants guests
# more directory visibility than the benchmark permits.
GUEST_ROLE_RESTRICTED := "2af84b1e-32c8-42b7-82bc-daa82404023b"

default unavailable := {}

unavailable := input.entra.unavailable if is_object(input.entra.unavailable)

default collected := false

collected if {
	input.entra.collected == true
}

available(key) if {
	collected
	not unavailable[key]
}

# Every rule below compares a field only when it has the type the rule expects
# and iterates a list only when it is a list; a missing field or a wrong shape
# leaves the control out of `decidable`, and the evidence rules at the end of
# the file report it by id. It is never read as a pass or as a failure.

# a number, or a string holding an integer (directory settings are strings)
_number(v) := v if is_number(v)

_number(v) := to_number(v) if {
	is_string(v)
	regex.match(`^-?[0-9]+$`, v)
}

# a directory-setting boolean: true/false, or the strings "True"/"False"
_flag(v) := v if is_boolean(v)

_flag(v) := lower(v) == "true" if {
	is_string(v)
	lower(v) in {"true", "false"}
}

_ap := input.entra.authorization_policy if {
	available("authorization_policy")
	is_object(input.entra.authorization_policy)
}

# ── /policies/authorizationPolicy -- seven controls ───────────────────

# CIS 5.1.2.2 -- users must not be able to register applications.
violation contains msg if {
	_ap.allowed_to_create_apps == true
	msg := "CIS 5.1.2.2: users can register applications; any user can create an app registration and consent-phish other users"
}

# CIS 5.1.2.3 -- restrict non-admin users from creating tenants.
violation contains msg if {
	_ap.allowed_to_create_tenants == true
	msg := "CIS 5.1.2.3: non-admin users are not restricted from creating tenants; a user can stand up an unmanaged tenant outside governance"
}

# CIS 5.1.3.1 -- users must not be able to create security groups.
violation contains msg if {
	_ap.allowed_to_create_security_groups == true
	msg := "CIS 5.1.3.1: users can create security groups; group membership drives access, so unmanaged group creation undermines authorization"
}

# CIS 5.1.4.6 -- users restricted from recovering BitLocker keys.
violation contains msg if {
	_ap.allowed_to_read_bitlocker_keys_for_owned_device == true
	msg := "CIS 5.1.4.6: users are not restricted from recovering BitLocker keys for their own device, which defeats disk encryption against a device thief who has the account"
}

# CIS 5.1.5.1 -- user consent to apps must not be allowed.
# permissionGrantPoliciesAssigned holds "managePermissionGrantsForSelf.{id}" for
# each app consent policy that lets users consent for themselves; an empty set
# of those means user consent is disabled. Other entries -- the
# managePermissionGrantsForOwnedResource.* policies for group and team owners --
# are not user consent and do not fail this control.
# https://learn.microsoft.com/en-us/graph/api/resources/defaultuserrolepermissions?view=graph-rest-1.0
USER_CONSENT_PREFIX := "managepermissiongrantsforself."

_grant_ids := _ap.permission_grant_policy_ids_assigned if is_array(_ap.permission_grant_policy_ids_assigned)

violation contains msg if {
	some id in _grant_ids
	is_string(id)
	startswith(lower(id), USER_CONSENT_PREFIX)
	msg := sprintf("CIS 5.1.5.1: user consent to apps accessing company data on their behalf is still permitted (permission grant policy '%s'); consent should be routed to an administrator", [id])
}

# CIS 5.1.6.2 -- guest user access restricted.
violation contains msg if {
	is_string(_ap.guest_user_role_id)
	_ap.guest_user_role_id != GUEST_ROLE_RESTRICTED
	msg := sprintf("CIS 5.1.6.2: guest user access is not restricted -- guest role is '%s' rather than the most restrictive role, so guests can enumerate directory objects", [_ap.guest_user_role_id])
}

# CIS 5.1.6.3 -- guest invitations limited to admins and inviters.
violation contains msg if {
	is_string(_ap.allow_invites_from)
	not _ap.allow_invites_from in {"adminsAndGuestInviters", "none"}
	msg := sprintf("CIS 5.1.6.3: guest user invitations are not limited -- allowInvitesFrom is '%s', so ordinary members can invite external guests", [_ap.allow_invites_from])
}

# ── Authentication methods policy ─────────────────────────────────────

# CIS 5.2.3.5 -- weak authentication methods disabled.
violation contains msg if {
	available("authentication_methods_policy")
	is_array(input.entra.weak_methods_enabled)
	some m in input.entra.weak_methods_enabled
	msg := sprintf("CIS 5.2.3.5: weak authentication method '%s' is enabled; SMS and voice are phishable and interceptable", [m])
}

# CIS 5.2.3.6 -- system-preferred MFA enabled.
violation contains msg if {
	available("authentication_methods_policy")
	is_string(input.entra.system_preferred_mfa_state)
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
	_flag(input.entra.password_protection.on_premises_check_enabled) == false
	msg := "CIS 5.2.3.3: password protection is not enabled for on-prem Active Directory, so weak passwords set on-premises are never evaluated"
}

# CIS 5.2.3.4 -- all member users MFA capable.
violation contains msg if {
	available("mfa_registration_report")
	is_array(input.entra.mfa_registration.members_not_mfa_capable)
	some u in input.entra.mfa_registration.members_not_mfa_capable
	msg := sprintf("CIS 5.2.3.4: member user '%s' is not MFA capable -- no strong method is registered, so a Conditional Access grant requiring MFA cannot be satisfied", [object.get(u, "user_principal_name", "(unnamed)")])
}

# CIS 5.1.2.1 -- legacy per-user MFA must be disabled.
violation contains msg if {
	available("per_user_mfa")
	is_array(input.entra.per_user_mfa.legacy_per_user_mfa)
	some u in input.entra.per_user_mfa.legacy_per_user_mfa
	msg := sprintf("CIS 5.1.2.1: per-user MFA is '%s' for '%s'; legacy per-user MFA should be disabled in favour of Conditional Access", [object.get(u, "state", "(unnamed)"), object.get(u, "user_principal_name", "(unnamed)")])
}

# ── Conditional Access and PIM (carried forward) ──────────────────────

# Conditional Access policies come from Graph, which returns null for a
# condition or control a policy does not set; absent or null reads as not set.
# These controls each ask whether SOME enabled policy meets the requirement, so
# a field that is missing can only leave the requirement unmet (a failure), never
# satisfy it. The list itself must be a list.
_ca_listed if {
	available("conditional_access_policies")
	is_array(input.entra.conditional_access_policies)
}

enabled_policies contains p if {
	_ca_listed
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

# Legacy authentication is blocked only when BOTH legacy client types
# (Exchange ActiveSync and other clients: IMAP, SMTP, POP) are blocked.
legacy_client_blocked(client) if {
	some p in enabled_policies
	client in p.conditions.clientAppTypes
	some g in p.grant_controls.builtInControls
	g == "block"
}

legacy_auth_blocked if {
	legacy_client_blocked("exchangeActiveSync")
	legacy_client_blocked("other")
}

violation contains msg if {
	_ca_listed
	not admin_mfa_enforced
	msg := "CIS 5.2.2.1: no enabled Conditional Access policy requires multifactor authentication for administrative roles"
}

violation contains msg if {
	_ca_listed
	not all_user_mfa_enforced
	msg := "CIS 5.2.2.2: no enabled Conditional Access policy requires multifactor authentication for all users"
}

violation contains msg if {
	_ca_listed
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
	_ca_listed
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
	_ca_listed
	not phishing_resistant_admin_mfa
	msg := "CIS 5.2.2.5: phishing-resistant MFA strength is not required for administrators; a policy requiring generic MFA still admits phishable factors"
}

# CIS 5.2.2.6 / 5.2.2.7 / 5.2.2.8 -- Identity Protection risk policies.
risk_policy_exists(field) if {
	some p in enabled_policies
	count(object.get(p, ["conditions", field], [])) > 0
}

violation contains msg if {
	_ca_listed
	not risk_policy_exists("userRiskLevels")
	msg := "CIS 5.2.2.6: no enabled Identity Protection user risk policy exists, so a user flagged as compromised is not challenged or blocked"
}

violation contains msg if {
	_ca_listed
	not risk_policy_exists("signInRiskLevels")
	msg := "CIS 5.2.2.7: no enabled Identity Protection sign-in risk policy exists, so a risky sign-in is not challenged"
}

default signin_risk_blocked := false

signin_risk_blocked if {
	some p in enabled_policies
	levels := object.get(p, ["conditions", "signInRiskLevels"], [])
	"high" in levels
	"medium" in levels
	"block" in object.get(p, ["grant_controls", "builtInControls"], [])
}

violation contains msg if {
	_ca_listed
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
	_ca_listed
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
	_ca_listed
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
	_ca_listed
	not intune_enrolment_frequency
	msg := "CIS 5.2.2.11: sign-in frequency for Intune enrollment is not set to every time"
}

# transferMethods is a flags enum Graph serialises as one comma-separated string
# ("deviceCodeFlow,authenticationTransfer"); a list of strings is read too.
_transfer_methods(p) := {trim_space(m) | some m in parts} if {
	v := object.get(p, ["conditions", "authenticationFlows", "transferMethods"], "")
	is_string(v)
	parts := split(v, ",")
}

_transfer_methods(p) := {m | some m in v; is_string(m)} if {
	v := object.get(p, ["conditions", "authenticationFlows", "transferMethods"], "")
	is_array(v)
}

# CIS 5.2.2.12 -- device code flow blocked.
default device_code_blocked := false

device_code_blocked if {
	some p in enabled_policies
	"deviceCodeFlow" in _transfer_methods(p)
	some g in object.get(p, ["grant_controls", "builtInControls"], [])
	g == "block"
}

violation contains msg if {
	_ca_listed
	not device_code_blocked
	msg := "CIS 5.2.2.12: the device code sign-in flow is not blocked; it is a common phishing vector because the victim authenticates on their own device"
}

# CIS 5.2.2.13 -- periodic reauthentication.
violation contains msg if {
	_ca_listed
	not signin_frequency_enforced
	msg := "CIS 5.2.2.13: periodic reauthentication is not required for all users -- no enabled policy sets a sign-in frequency"
}

# CIS 5.2.2.14 / 5.2.2.15 -- named locations.
_named_locations_listed if {
	available("named_locations")
	is_array(input.entra.named_locations)
}

violation contains msg if {
	_named_locations_listed
	count([l | some l in input.entra.named_locations; l.is_trusted == true]) == 0
	msg := "CIS 5.2.2.14: no trusted named locations are defined, so location cannot be used as a signal in Conditional Access"
}

violation contains msg if {
	_named_locations_listed
	count([l |
		some l in input.entra.named_locations
		regions := object.get(l, "countries_and_regions", [])
		is_array(regions)
		count(regions) > 0
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
	_ca_listed
	not token_protection_enforced
	msg := "CIS 5.2.2.16: token protection is not enforced for session tokens, so a stolen refresh token can be replayed from another device"
}

# CIS 5.2.2.17 -- authentication transfer blocked.
default auth_transfer_blocked := false

auth_transfer_blocked if {
	some p in enabled_policies
	"authenticationTransfer" in _transfer_methods(p)
	some g in object.get(p, ["grant_controls", "builtInControls"], [])
	g == "block"
}

violation contains msg if {
	_ca_listed
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
	_number(input.entra.device_registration.user_device_quota) > MAX_DEVICES_PER_USER
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

_app_management_read if {
	available("app_management_policy")
	is_object(input.entra.app_management)
}

app_restriction_present(collection, rule_type) if {
	some r in object.get(input.entra.app_management, collection, [])
	r.restrictionType == rule_type
	r.state == "enabled"
}

violation contains msg if {
	_app_management_read
	not app_restriction_present("password_credentials", "passwordAddition")
	msg := "CIS 5.1.5.3: password addition is not blocked for applications, so a secret can be added to an existing app registration"
}

violation contains msg if {
	_app_management_read
	not app_restriction_present("password_credentials", "passwordLifetime")
	msg := "CIS 5.1.5.4: no password lifetime restriction is enforced for applications, so an application password can exceed 180 days"
}

violation contains msg if {
	_app_management_read
	not app_restriction_present("password_credentials", "symmetricKeyAddition")
	msg := "CIS 5.1.5.5: new application passwords are not required to be system-generated, so a weak secret can be supplied by hand"
}

violation contains msg if {
	_app_management_read
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
	is_array(input.entra.access_reviews)
	not review_covers("guest")
	msg := "CIS 5.3.2: no access review is configured for guest users, so external access is never re-attested"
}

violation contains msg if {
	available("access_reviews")
	is_array(input.entra.access_reviews)
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
	is_string(input.entra.authenticator[feature])
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
	_number(input.entra.lockout.threshold) > MAX_LOCKOUT_THRESHOLD
	msg := sprintf("CIS 5.2.3.8: the account lockout threshold is %v; the benchmark expects '10' or less", [input.entra.lockout.threshold])
}

violation contains msg if {
	available("group_settings")
	input.entra.lockout.settings_present == true
	_number(input.entra.lockout.duration_seconds) < MIN_LOCKOUT_DURATION_SECONDS
	msg := sprintf("CIS 5.2.3.9: the account lockout duration in seconds is %v; the benchmark expects at least %d", [input.entra.lockout.duration_seconds, MIN_LOCKOUT_DURATION_SECONDS])
}

# CIS 5.1.3.4 -- Microsoft 365 group creation restricted.
# Only EnableGroupCreation false restricts creation: GroupCreationAllowedGroupId
# names who may still create groups WHEN creation is off, it does not restrict
# anyone while it is on. With no Group.Unified setting object the directory runs
# on the template defaults, and EnableGroupCreation defaults to True, so every
# user can create groups: that is a failure, not a pass.
# https://learn.microsoft.com/en-us/entra/identity/users/groups-settings-cmdlets
violation contains msg if {
	available("group_settings")
	input.entra.group_creation.settings_present == true
	_flag(input.entra.group_creation.enabled) == true
	msg := "CIS 5.1.3.4: users can create Microsoft 365 groups in Azure portals, APIs or PowerShell -- EnableGroupCreation is True; group membership drives access, so unmanaged creation undermines authorization"
}

violation contains msg if {
	available("group_settings")
	input.entra.group_creation.settings_present == false
	msg := "CIS 5.1.3.4: users can create Microsoft 365 groups in Azure portals, APIs or PowerShell -- no Group.Unified directory setting exists, so the default (EnableGroupCreation True) applies to every user"
}

# ── CIS 5.1.6.1 -- invitations only to allowed domains ────────────────
# CIS reads the B2BManagementPolicy invitation domain policy. Compliant
# means an AllowedDomains list is PRESENT and no BlockedDomains property.
#
# The empty case is the subtle one and CIS is explicit about it: an
# AllowedDomains list with no entries is compliant, because it permits
# nothing. Absent is not the same as empty, which is why the collector
# reports presence separately from contents -- treating a missing list as
# an empty one would turn "unrestricted" into "maximally restricted".

b2b := object.get(input, ["entra", "b2b_management_policy"], {})

violation contains msg if {
	available("b2b_management_policy")
	b2b.policy_present == false
	msg := "CIS 5.1.6.1: no B2B collaboration domain policy exists, so invitations can be sent to any domain"
}

violation contains msg if {
	available("b2b_management_policy")
	b2b.policy_present == true
	b2b.allowed_domains_present == false
	msg := "CIS 5.1.6.1: collaboration invitations are not restricted to allowed domains -- the B2B policy specifies no AllowedDomains list, so any domain may be invited"
}

# A block list is an allow-everything-else posture, which CIS treats as
# non-compliant even when an allow list is also present.
violation contains msg if {
	available("b2b_management_policy")
	b2b.policy_present == true
	b2b.blocked_domains_present == true
	msg := "CIS 5.1.6.1: the B2B collaboration policy specifies BlockedDomains -- blocking named domains permits every other domain, where the benchmark requires an explicit allow list"
}

# ── CIS 5.3.4 / 5.3.5 -- approval to activate a privileged role ───────
# Both controls have the same shape against different roles, so the map
# drives the rules. CIS requires BOTH isApprovalRequired and at least one
# primary approver: a policy that requires approval from nobody cannot
# gate anything.

PIM_APPROVAL_CONTROLS := {
	"pim_approval_62e90394-69f5-4237-9190-012177145e10": {
		"control": "5.3.4",
		"role": "Global Administrator",
	},
	"pim_approval_e8611ab8-c189-46e8-94e1-60213ab1f814": {
		"control": "5.3.5",
		"role": "Privileged Role Administrator",
	},
}

violation contains msg if {
	some key, meta in PIM_APPROVAL_CONTROLS
	available(key)
	input.entra[key].is_approval_required == false
	msg := sprintf("CIS %s: activating the %s role does not require approval, so an eligible principal can elevate unilaterally", [meta.control, meta.role])
}

violation contains msg if {
	some key, meta in PIM_APPROVAL_CONTROLS
	available(key)
	input.entra[key].is_approval_required == true
	input.entra[key].primary_approver_count == 0
	msg := sprintf("CIS %s: activating the %s role requires approval but no approvers are assigned, so the requirement gates nothing", [meta.control, meta.role])
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
	"controls_evaluated": 53,
	"controls": [
		"5.1.2.1", "5.1.2.2", "5.1.2.3", "5.1.3.1", "5.1.3.4", "5.1.4.6",
		"5.1.4.1", "5.1.4.2", "5.1.4.3", "5.1.4.4", "5.1.4.5",
		"5.1.5.1", "5.1.5.2", "5.1.5.3", "5.1.5.4", "5.1.5.5", "5.1.5.6",
		"5.1.6.1", "5.1.6.2", "5.1.6.3", "5.1.8.1",
		"5.2.2.1", "5.2.2.2", "5.2.2.3", "5.2.2.4", "5.2.2.5",
		"5.2.2.6", "5.2.2.7", "5.2.2.8", "5.2.2.9", "5.2.2.10",
		"5.2.2.11", "5.2.2.12", "5.2.2.13", "5.2.2.14", "5.2.2.15",
		"5.2.2.16", "5.2.2.17",
		"5.2.3.1", "5.2.3.2", "5.2.3.3", "5.2.3.4", "5.2.3.5", "5.2.3.6",
		"5.2.3.7", "5.2.3.8", "5.2.3.9", "5.2.3.10",
		"5.3.1", "5.3.2", "5.3.3", "5.3.4", "5.3.5",
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

# ── Per-control results ──────────────────────────────────────────────
# `decidable` holds the controls of this section whose facts were all
# collected; CONTROL_EVIDENCE names the input paths each one reads ("[]"
# = every element of a list). The main report marks a control that is not
# decidable "evidence_missing" even where no violation above names it: an
# absent fact must never read as a pass. Each gate restates the condition
# of its rule above; change them together.
_AP := "entra.authorization_policy."

_CA := ["entra.conditional_access_policies"]

CONTROL_EVIDENCE := {
	"5.1.2.1": ["entra.per_user_mfa.legacy_per_user_mfa"],
	"5.1.2.2": [concat("", [_AP, "allowed_to_create_apps"])],
	"5.1.2.3": [concat("", [_AP, "allowed_to_create_tenants"])],
	"5.1.3.1": [concat("", [_AP, "allowed_to_create_security_groups"])],
	"5.1.3.4": ["entra.group_creation.enabled", "entra.group_creation.settings_present"],
	"5.1.4.1": ["entra.device_registration.azure_ad_join_allowed_to_join"],
	"5.1.4.2": ["entra.device_registration.user_device_quota"],
	"5.1.4.3": ["entra.device_registration.local_admin_global_admins_enabled"],
	"5.1.4.4": ["entra.device_registration.local_admin_registering_user_enabled"],
	"5.1.4.5": ["entra.laps_enabled"],
	"5.1.4.6": [concat("", [_AP, "allowed_to_read_bitlocker_keys_for_owned_device"])],
	"5.1.5.1": [concat("", [_AP, "permission_grant_policy_ids_assigned"])],
	"5.1.5.2": ["entra.admin_consent_workflow_enabled"],
	"5.1.5.3": ["entra.app_management.password_credentials"],
	"5.1.5.4": ["entra.app_management.password_credentials"],
	"5.1.5.5": ["entra.app_management.password_credentials"],
	"5.1.5.6": ["entra.app_management.key_credentials"],
	"5.1.6.1": ["entra.b2b_management_policy.allowed_domains_present", "entra.b2b_management_policy.blocked_domains_present", "entra.b2b_management_policy.policy_present"],
	"5.1.6.2": [concat("", [_AP, "guest_user_role_id"])],
	"5.1.6.3": [concat("", [_AP, "allow_invites_from"])],
	"5.1.8.1": ["entra.on_premises_sync.configured", "entra.on_premises_sync.password_sync_enabled"],
	"5.2.2.1": _CA, "5.2.2.2": _CA, "5.2.2.3": _CA, "5.2.2.4": _CA, "5.2.2.5": _CA, "5.2.2.6": _CA,
	"5.2.2.7": _CA, "5.2.2.8": _CA, "5.2.2.9": _CA, "5.2.2.10": _CA, "5.2.2.11": _CA, "5.2.2.12": _CA,
	"5.2.2.13": _CA, "5.2.2.16": _CA, "5.2.2.17": _CA,
	"5.2.2.14": ["entra.named_locations[].is_trusted"],
	"5.2.2.15": ["entra.named_locations[].countries_and_regions"],
	"5.2.3.1": ["entra.authenticator.number_matching_state", "entra.authenticator.show_app_information_state", "entra.authenticator.show_geographic_location_state", "entra.authenticator.state"],
	"5.2.3.2": ["entra.password_protection.custom_banned_list"],
	"5.2.3.3": ["entra.password_protection.on_premises_check_enabled"],
	"5.2.3.4": ["entra.mfa_registration.members_not_mfa_capable"],
	"5.2.3.5": ["entra.weak_methods_enabled"],
	"5.2.3.6": ["entra.system_preferred_mfa_state"],
	"5.2.3.7": ["entra.email_otp_state"],
	"5.2.3.8": ["entra.lockout.settings_present", "entra.lockout.threshold"],
	"5.2.3.9": ["entra.lockout.duration_seconds", "entra.lockout.settings_present"],
	"5.2.3.10": ["entra.authenticator.companion_app_allowed_state"],
	"5.3.1": ["entra.pim_available"],
	"5.3.2": ["entra.access_reviews[].scope_query"],
	"5.3.3": ["entra.access_reviews[].scope_query"],
	"5.3.4": ["entra.pim_approval_62e90394-69f5-4237-9190-012177145e10.is_approval_required", "entra.pim_approval_62e90394-69f5-4237-9190-012177145e10.primary_approver_count"],
	"5.3.5": ["entra.pim_approval_e8611ab8-c189-46e8-94e1-60213ab1f814.is_approval_required", "entra.pim_approval_e8611ab8-c189-46e8-94e1-60213ab1f814.primary_approver_count"],
}

_present(obj, key) if {
	v := object.get(obj, key, null)
	v != null
}

_AP_BOOLEANS := {
	"5.1.2.2": "allowed_to_create_apps",
	"5.1.2.3": "allowed_to_create_tenants",
	"5.1.3.1": "allowed_to_create_security_groups",
	"5.1.4.6": "allowed_to_read_bitlocker_keys_for_owned_device",
}

decidable contains id if {
	some id, field in _AP_BOOLEANS
	is_boolean(_ap[field])
}

decidable contains "5.1.5.1" if {
	every id in _grant_ids {
		is_string(id)
	}
}

decidable contains "5.1.6.2" if is_string(_ap.guest_user_role_id)

decidable contains "5.1.6.3" if is_string(_ap.allow_invites_from)

decidable contains "5.2.3.5" if {
	available("authentication_methods_policy")
	is_array(input.entra.weak_methods_enabled)
}

decidable contains "5.2.3.6" if {
	available("authentication_methods_policy")
	is_string(input.entra.system_preferred_mfa_state)
}

decidable contains "5.2.3.7" if {
	available("authentication_methods_policy")
	is_string(input.entra.email_otp_state)
}

AUTHENTICATOR_FEATURES := ["number_matching_state", "show_app_information_state", "show_geographic_location_state"]

decidable contains "5.2.3.1" if {
	available("authentication_methods_policy")
	is_string(input.entra.authenticator.state)
	input.entra.authenticator.state != "enabled"
}

decidable contains "5.2.3.1" if {
	available("authentication_methods_policy")
	input.entra.authenticator.state == "enabled"
	every feature in AUTHENTICATOR_FEATURES {
		is_string(input.entra.authenticator[feature])
	}
}

decidable contains "5.2.3.10" if {
	available("authentication_methods_policy")
	is_string(input.entra.authenticator.companion_app_allowed_state)
}

decidable contains "5.1.5.2" if {
	available("admin_consent_request_policy")
	is_boolean(input.entra.admin_consent_workflow_enabled)
}

decidable contains "5.1.8.1" if {
	available("on_premises_synchronization")
	input.entra.on_premises_sync.configured == false
}

decidable contains "5.1.8.1" if {
	available("on_premises_synchronization")
	input.entra.on_premises_sync.configured == true
	is_boolean(input.entra.on_premises_sync.password_sync_enabled)
}

decidable contains "5.2.3.2" if {
	available("group_settings")
	is_string(input.entra.password_protection.custom_banned_list)
}

decidable contains "5.2.3.3" if {
	available("group_settings")
	is_boolean(_flag(input.entra.password_protection.on_premises_check_enabled))
}

# no directory setting object: the tenant runs on the service defaults, so only
# the settings_present flag itself has to have been collected. For lockout the
# defaults (10 attempts, 60 seconds) meet 5.2.3.8 / 5.2.3.9, so the rules apply
# no check; for group creation the default lets every user create groups and
# 5.1.3.4 fails (see its rule).
# https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout
_setting_decidable(obj, _) if {
	available("group_settings")
	input.entra[obj].settings_present == false
}

_setting_decidable(obj, field) if {
	available("group_settings")
	input.entra[obj].settings_present == true
	_setting_readable(obj, field)
}

_setting_readable("lockout", field) if is_number(_number(input.entra.lockout[field]))

_setting_readable("group_creation", field) if is_boolean(_flag(input.entra.group_creation[field]))

decidable contains "5.2.3.8" if _setting_decidable("lockout", "threshold")

decidable contains "5.2.3.9" if _setting_decidable("lockout", "duration_seconds")

decidable contains "5.1.3.4" if _setting_decidable("group_creation", "enabled")

decidable contains "5.2.3.4" if {
	available("mfa_registration_report")
	is_array(input.entra.mfa_registration.members_not_mfa_capable)
}

decidable contains "5.1.2.1" if {
	available("per_user_mfa")
	is_array(input.entra.per_user_mfa.legacy_per_user_mfa)
}

# a policy list the rules cannot read leaves every requirement unmet, which the rules report as failures
decidable contains id if {
	some id in [
		"5.2.2.1", "5.2.2.2", "5.2.2.3", "5.2.2.4", "5.2.2.5", "5.2.2.6", "5.2.2.7", "5.2.2.8",
		"5.2.2.9", "5.2.2.10", "5.2.2.11", "5.2.2.12", "5.2.2.13", "5.2.2.16", "5.2.2.17",
	]
	_ca_listed
	is_array(input.entra.conditional_access_policies)
}

decidable contains id if {
	some id in ["5.2.2.14", "5.2.2.15"]
	available("named_locations")
	is_array(input.entra.named_locations)
}

decidable contains "5.3.1" if {
	available("pim_role_assignments")
	is_boolean(input.entra.pim_available)
}

decidable contains "5.1.4.1" if {
	available("device_registration_policy")
	is_string(input.entra.device_registration.azure_ad_join_allowed_to_join)
}

# an absent quota reads as 0 and passes, so the quota itself must have been collected
decidable contains "5.1.4.2" if {
	available("device_registration_policy")
	is_number(_number(input.entra.device_registration.user_device_quota))
}

decidable contains "5.1.4.3" if {
	available("device_registration_policy")
	is_boolean(input.entra.device_registration.local_admin_global_admins_enabled)
}

decidable contains "5.1.4.4" if {
	available("device_registration_policy")
	is_string(input.entra.device_registration.local_admin_registering_user_enabled)
}

decidable contains "5.1.4.5" if {
	available("laps_policy")
	is_boolean(input.entra.laps_enabled)
}

decidable contains id if {
	some id in ["5.1.5.3", "5.1.5.4", "5.1.5.5", "5.1.5.6"]
	available("app_management_policy")
	is_object(input.entra.app_management)
}

decidable contains id if {
	some id in ["5.3.2", "5.3.3"]
	available("access_reviews")
	is_array(input.entra.access_reviews)
}

decidable contains "5.1.6.1" if {
	available("b2b_management_policy")
	b2b.policy_present == false
}

decidable contains "5.1.6.1" if {
	available("b2b_management_policy")
	b2b.policy_present == true
	is_boolean(b2b.allowed_domains_present)
	is_boolean(b2b.blocked_domains_present)
}

decidable contains meta.control if {
	some key, meta in PIM_APPROVAL_CONTROLS
	available(key)
	input.entra[key].is_approval_required == false
}

decidable contains meta.control if {
	some key, meta in PIM_APPROVAL_CONTROLS
	available(key)
	input.entra[key].is_approval_required == true
	is_number(input.entra[key].primary_approver_count)
}

# ── Evidence gaps, reported by control id ─────────────────────────────
# A gap names every control it blocks (authorization_policy alone blocks
# seven), so the per-control results and an exporter reading the ids agree on
# what was not evaluated. A key this module does not know is reported on its
# own, attributed to no control.
FACT_CONTROLS := {
	"authorization_policy": ["5.1.2.2", "5.1.2.3", "5.1.3.1", "5.1.4.6", "5.1.5.1", "5.1.6.2", "5.1.6.3"],
	"authentication_methods_policy": ["5.2.3.1", "5.2.3.5", "5.2.3.6", "5.2.3.7", "5.2.3.10"],
	"admin_consent_request_policy": ["5.1.5.2"],
	"on_premises_synchronization": ["5.1.8.1"],
	"conditional_access_policies": [
		"5.2.2.1", "5.2.2.2", "5.2.2.3", "5.2.2.4", "5.2.2.5", "5.2.2.6", "5.2.2.7", "5.2.2.8",
		"5.2.2.9", "5.2.2.10", "5.2.2.11", "5.2.2.12", "5.2.2.13", "5.2.2.16", "5.2.2.17",
	],
	"named_locations": ["5.2.2.14", "5.2.2.15"],
	"device_registration_policy": ["5.1.4.1", "5.1.4.2", "5.1.4.3", "5.1.4.4"],
	"laps_policy": ["5.1.4.5"],
	"app_management_policy": ["5.1.5.3", "5.1.5.4", "5.1.5.5", "5.1.5.6"],
	"access_reviews": ["5.3.2", "5.3.3"],
	"pim_role_assignments": ["5.3.1"],
	"group_settings": ["5.1.3.4", "5.2.3.2", "5.2.3.3", "5.2.3.8", "5.2.3.9"],
	"mfa_registration_report": ["5.2.3.4"],
	"per_user_mfa": ["5.1.2.1"],
	"b2b_management_policy": ["5.1.6.1"],
	"pim_approval_62e90394-69f5-4237-9190-012177145e10": ["5.3.4"],
	"pim_approval_e8611ab8-c189-46e8-94e1-60213ab1f814": ["5.3.5"],
}

_section_controls := _natural_sort(object.keys(CONTROL_EVIDENCE))

# ids in benchmark order
_natural_sort(ids) := [pair[1] | some pair in sort([[key, id] |
	some id in ids
	parts := split(id, ".")
	key := concat(".", [sprintf("%03d", [to_number(x)]) | some x in parts])
])]

_gap(ids, why) := sprintf("CIS %s: evidence missing -- %s (this is not a pass)", [concat("/", ids), why])

_source_gaps contains [_section_controls, "Entra facts were not collected (entra.collected is not true)"] if not collected

_source_gaps contains [FACT_CONTROLS[key], sprintf("entra.unavailable.%s: %v", [key, reason])] if {
	collected
	some key, reason in unavailable
}

_gap_ids contains id if {
	some g in _source_gaps
	some id in g[0]
}

# a source gap names each control it leaves undecided in a message of its own, so the
# violation count is never smaller than the number of controls that are not a pass
_evidence_gaps contains _gap([id], concat("; ", sort(whys))) if {
	some id in _gap_ids
	not id in decidable
	whys := {g[1] | some g in _source_gaps; id in g[0]}
}

_evidence_gaps contains msg if {
	some key, reason in unavailable
	not FACT_CONTROLS[key]
	msg := sprintf("M365 section 5 (Entra): unrecognised unavailable key '%s' (%v) -- this module reads no fact of that name, so it is attributed to no control (this is not a pass)", [key, reason])
}

_evidence_gaps contains _gap([id], why) if {
	some id, paths in CONTROL_EVIDENCE
	not id in decidable
	not id in _gap_ids
	why := sprintf("%s not collected or not of the expected type", [concat(", ", paths)])
}

violation contains msg if some msg in _evidence_gaps
