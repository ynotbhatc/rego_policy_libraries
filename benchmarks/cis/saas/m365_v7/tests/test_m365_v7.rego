package cis_m365_v7_test

import data.cis_m365_v7.admin_center
import data.cis_m365_v7.defender
import data.cis_m365_v7.entra
import data.cis_m365_v7.exchange
import data.cis_m365_v7.main
import data.cis_m365_v7.purview
import data.cis_m365_v7.sharepoint
import rego.v1

# ── Fail-closed behaviour ─────────────────────────────────────────────
# The defect class this library exists to avoid is a green result that was
# never actually established. Absent facts must produce a violation and a
# false `compliant`, never silence.

test_admin_center_absent_facts_is_not_a_pass if {
	r := admin_center.compliance_report with input as {}
	r.compliant == false
	r.facts_present == false
	count(r.violations) == 1
}

test_defender_absent_facts_is_not_a_pass if {
	# Section 2 now spans 17 controls across two fact sources (DNS for
	# SPF/DKIM/DMARC, Exchange PowerShell for the policy controls), so
	# empty input raises a violation per source rather than exactly one.
	r := defender.compliance_report with input as {}
	r.compliant == false
	count(r.violations) >= 2
}

test_entra_absent_facts_is_not_a_pass if {
	r := entra.compliance_report with input as {}
	r.compliant == false
}

test_sharepoint_unreachable_settings_is_not_a_pass if {
	r := sharepoint.compliance_report with input as {"sharepoint": {"settings_reachable": false}}
	r.compliant == false
}

test_reports_never_collapse_to_empty_object if {
	# A single undefined field turns the whole object into {} at the OPA
	# endpoint. Assert every report is populated under empty input.
	count(admin_center.compliance_report) > 0 with input as {}
	count(defender.compliance_report) > 0 with input as {}
	count(purview.compliance_report) > 0 with input as {}
	count(entra.compliance_report) > 0 with input as {}
	count(exchange.compliance_report) > 0 with input as {}
	count(sharepoint.compliance_report) > 0 with input as {}
	count(main.compliance_report) > 0 with input as {}
}

# ── CIS 1.1.3 -- between two and four global admins ───────────────────

admins(n) := {"admin_center": {
	"collected": true, "unavailable": {},
	"global_admin_count": n,
	"global_admins": [{"id": sprintf("u%d", [i])} | some i in numbers.range(1, n)],
}}

test_1_1_3_too_few_global_admins if {
	r := admin_center.compliance_report with input as admins(1)
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 1.1.3")
}

test_1_1_3_too_many_global_admins if {
	r := admin_center.compliance_report with input as admins(6)
	r.compliant == false
}

test_1_1_3_three_global_admins_passes if {
	r := admin_center.compliance_report with input as admins(3)
	r.compliant == true
	count(r.violations) == 0
}

# ── CIS 2.1.8 / 2.1.9 / 2.1.10 -- SPF, DKIM, DMARC ────────────────────

domains(spf, dkim, dmarc) := {"exchange": {"verified_domains": [{
	"id": "example.com",
	"spf_present": spf,
	"dkim_present": dkim,
	"dmarc_present": dmarc,
}]}}

test_2_1_8_missing_spf if {
	r := defender.compliance_report with input as domains(false, true, true)
	some v in r.violations
	contains(v, "CIS 2.1.8")
}

test_2_1_9_missing_dkim if {
	r := defender.compliance_report with input as domains(true, false, true)
	some v in r.violations
	contains(v, "CIS 2.1.9")
}

test_2_1_10_missing_dmarc if {
	r := defender.compliance_report with input as domains(true, true, false)
	some v in r.violations
	contains(v, "CIS 2.1.10")
}

test_mail_authentication_controls_satisfied if {
	# A domains-only fixture establishes SPF/DKIM/DMARC and nothing else.
	# With 17 controls in the section it cannot make the whole section
	# compliant, so assert on the three controls it actually covers.
	r := defender.compliance_report with input as domains(true, true, true)
	every v in r.violations {
		not contains(v, "CIS 2.1.8")
		not contains(v, "CIS 2.1.9")
		not contains(v, "CIS 2.1.10")
	}
}

# ── CIS 3.1.1 -- unified audit log ────────────────────────────────────

test_3_1_1_audit_log_unavailable if {
	r := purview.compliance_report with input as {"purview": {"audit_log_accessible": false}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 3.1.1")
}

test_3_1_1_audit_log_available_satisfies_its_control if {
	# Section 3 now spans 5 controls across two fact sources, so an
	# audit-log-only fixture cannot make the section compliant. Assert on
	# the control it actually establishes.
	r := purview.compliance_report with input as {"purview": {"audit_log_accessible": true}}
	every v in r.violations { not contains(v, "CIS 3.1.1") }
}

# ── CIS 5.2.2.x / 5.3.1 -- Conditional Access and PIM ─────────────────

ca_tenant(policies, pim) := {"entra": {
	"collected": true,
	"unavailable": {},
	"conditional_access_policies": policies,
	"pim_role_assignments": [],
	"pim_available": pim,
}}

mfa_all_users := {
	"id": "p1",
	"state": "enabled",
	"conditions": {"users": {"includeUsers": ["All"], "includeRoles": []}, "clientAppTypes": ["all"]},
	"grant_controls": {"builtInControls": ["mfa"]},
}

mfa_admins := {
	"id": "p2",
	"state": "enabled",
	"conditions": {"users": {"includeUsers": [], "includeRoles": ["62e90394-role"]}, "clientAppTypes": ["all"]},
	"grant_controls": {"builtInControls": ["mfa"]},
}

block_legacy := {
	"id": "p3",
	"state": "enabled",
	"conditions": {"users": {"includeUsers": ["All"], "includeRoles": []}, "clientAppTypes": ["exchangeActiveSync", "other"]},
	"grant_controls": {"builtInControls": ["block"]},
}

test_5_2_2_2_no_mfa_for_all_users if {
	r := entra.compliance_report with input as ca_tenant([mfa_admins, block_legacy], true)
	some v in r.violations
	contains(v, "CIS 5.2.2.2")
}

test_5_2_2_3_legacy_auth_not_blocked if {
	r := entra.compliance_report with input as ca_tenant([mfa_all_users, mfa_admins], true)
	some v in r.violations
	contains(v, "CIS 5.2.2.3")
}

test_5_3_1_pim_not_in_use if {
	r := entra.compliance_report with input as ca_tenant([mfa_all_users, mfa_admins, block_legacy], false)
	some v in r.violations
	contains(v, "CIS 5.3.1")
}

test_entra_conditional_access_controls_satisfied if {
	# Section 5 now spans 20 controls; a Conditional-Access-only fixture
	# cannot make the whole section compliant. Assert that the three CA
	# controls stop firing, which is what this fixture establishes.
	r := entra.compliance_report with input as ca_tenant([mfa_all_users, mfa_admins, block_legacy], true)
	every v in r.violations {
		not contains(v, "CIS 5.2.2.1")
		not contains(v, "CIS 5.2.2.2")
		not contains(v, "CIS 5.2.2.3")
	}
}

# A policy that is present but disabled must not satisfy the control.
test_disabled_policy_does_not_satisfy_control if {
	disabled := object.union(mfa_all_users, {"state": "disabled"})
	r := entra.compliance_report with input as ca_tenant([disabled], true)
	some v in r.violations
	contains(v, "CIS 5.2.2.2")
}

# ── CIS 6.1.1 -- mailbox auditing ─────────────────────────────────────

test_6_1_1_audit_disabled_read_directly if {
	# Now a direct read of the tenant flag, not a per-user proxy.
	r := exchange.compliance_report with input as {"exchange": {
		"collected": true, "unavailable": {},
		"organization_config": {"AuditDisabled": true},
	}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 6.1.1")
}

test_6_5_4_smtp_auth_enabled if {
	r := exchange.compliance_report with input as {"exchange": {
		"collected": true, "unavailable": {},
		"transport_config": {"SmtpClientAuthenticationDisabled": false},
	}}
	some v in r.violations
	contains(v, "CIS 6.5.4")
}

test_6_1_3_audit_bypass_flagged if {
	r := exchange.compliance_report with input as {"exchange": {
		"collected": true, "unavailable": {},
		"audit_bypass_associations": [{"Identity": "svc@c.com"}],
	}}
	some v in r.violations
	contains(v, "CIS 6.1.3")
}

test_6_2_2_scl_bypass_whitelist_flagged if {
	r := exchange.compliance_report with input as {"exchange": {
		"collected": true, "unavailable": {},
		"transport_rules": [{"Name": "allow-partner", "State": "Enabled",
			"SetSCL": -1, "SenderDomainIs": ["partner.com"]}],
	}}
	some v in r.violations
	contains(v, "CIS 6.2.2")
}

test_6_1_2_declares_its_sampling_limit if {
	# 6.1.1 is now measured directly, but 6.1.2 is still sampled -- that
	# limit has to stay visible in the report.
	r := exchange.compliance_report with input as {}
	contains(r.evidence_strength["6.1.2"], "sampled")
}

# ── CIS 7.2.x -- SharePoint sharing ───────────────────────────────────

sp(props) := {"sharepoint": {
	"collected": true,
	"unavailable": {},
	"tenant": props,
}}

test_7_2_1_legacy_auth_enabled if {
	r := sharepoint.compliance_report with input as sp({"LegacyAuthProtocolsEnabled": true})
	some v in r.violations
	contains(v, "CIS 7.2.1")
}

test_7_2_6_most_permissive_sharing if {
	r := sharepoint.compliance_report with input as sp({"SharingCapability": "ExternalUserAndGuestSharing"})
	some v in r.violations
	contains(v, "CIS 7.2.6")
}

test_7_2_7_anonymous_default_link if {
	r := sharepoint.compliance_report with input as sp({"DefaultSharingLinkType": "AnonymousAccess"})
	some v in r.violations
	contains(v, "CIS 7.2.7")
}

test_7_2_11_default_link_permission_edit if {
	r := sharepoint.compliance_report with input as sp({"DefaultLinkPermission": "Edit"})
	some v in r.violations
	contains(v, "CIS 7.2.11")
}

test_sharepoint_hardened_passes if {
	r := sharepoint.compliance_report with input as sp({
		"LegacyAuthProtocolsEnabled": false,
		"EnableAzureADB2BIntegration": true,
		"SharingCapability": "Disabled",
		"OneDriveSharingCapability": "Disabled",
		"PreventExternalUsersFromResharing": true,
		"DefaultSharingLinkType": "Internal",
		"SharingDomainRestrictionMode": "AllowList",
		"ExternalUserExpirationRequired": true,
		"EmailAttestationRequired": true,
		"DefaultLinkPermission": "View",
		"DisallowInfectedFileDownload": true,
	})
	r.compliant == true
}

# A property PnP did not return must block its control, not read as null
# and pass -- the property name could be wrong or renamed.
test_7_2_8_missing_property_blocks_its_control if {
	r := sharepoint.compliance_report with input as {"sharepoint": {
		"collected": true,
		"unavailable": {"SharingDomainRestrictionMode": "Get-PnPTenant did not return the property"},
		"tenant": {},
	}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 7.2.8")
	contains(v, "not a pass")
}

test_sharepoint_declares_the_cmdlet_deviation if {
	r := sharepoint.compliance_report with input as {}
	contains(r.evidence_strength.section, "Get-PnPTenant")
	contains(r.evidence_strength.section, "Windows-only")
}

# ── Orchestrator accounting ───────────────────────────────────────────

test_orchestrator_reports_partial_coverage_honestly if {
	r := main.compliance_report with input as {}
	r.benchmark_total_controls == 160
	r.controls_evaluated == 96
	r.controls_not_evaluated == 64
	count(r.sections_not_evaluated) == 1
}

test_orchestrator_exposes_no_bare_compliant_field if {
	# Reading `compliant` from a 14-of-160 assessment would be misleading,
	# so the orchestrator must not offer one. Assert on the key set --
	# referencing a statically-absent field is a compile error, not a test.
	r := main.compliance_report with input as {}
	not "compliant" in object.keys(r)
	"assessed_controls_compliant" in object.keys(r)
}

test_orchestrator_scopes_its_verdict_to_evaluated_controls if {
	r := main.compliance_report with input as {}
	r.assessed_controls_compliant == false
	contains(r.interpretation, "partial assessment")
}

test_every_evaluated_id_is_reported if {
	r := main.compliance_report with input as {}
	count(r.evaluated_control_ids) == r.controls_evaluated
}

# ── Section 1 -- admin center ─────────────────────────────────────────

import data.cis_m365_v7.admin_center as ac
import data.cis_m365_v7.attestation as att
import data.cis_m365_v7.intune as intune

ac_input(extra) := {"admin_center": object.union({"collected": true, "unavailable": {}}, extra)}

test_1_1_1_on_prem_synced_admin if {
	r := ac.compliance_report with input as ac_input({"global_admins": [
		{"user_principal_name": "a@c.com", "on_premises_sync_enabled": true},
	], "global_admin_count": 3})
	some v in r.violations
	contains(v, "CIS 1.1.1")
}

test_1_2_1_public_group_flagged if {
	r := ac.compliance_report with input as ac_input({"public_groups": [{"display_name": "All Co"}]})
	some v in r.violations
	contains(v, "CIS 1.2.1")
}

test_1_3_1_password_expiry_configured if {
	r := ac.compliance_report with input as ac_input({"domains": [
		{"id": "c.com", "is_verified": true, "password_validity_period_in_days": 90},
	]})
	some v in r.violations
	contains(v, "CIS 1.3.1")
}

test_1_3_1_never_expires_passes if {
	r := ac.compliance_report with input as ac_input({"domains": [
		{"id": "c.com", "is_verified": true, "password_validity_period_in_days": 2147483647},
	]})
	every v in r.violations { not contains(v, "CIS 1.3.1") }
}

# The whole point of the `unavailable` contract: a denied endpoint must
# raise a violation naming the control it blocked, never pass silently.
test_unavailable_fact_raises_the_blocked_control if {
	r := ac.compliance_report with input as {"admin_center": {
		"collected": true,
		"unavailable": {"domains": "permission denied -- scope missing"},
	}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 1.3.1")
	contains(v, "not a pass")
}

test_admin_center_absent_facts_is_not_a_pass if {
	r := ac.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

# ── Section 4 -- Intune ───────────────────────────────────────────────

test_4_1_secure_by_default_off if {
	r := intune.compliance_report with input as {"intune": {
		"collected": true, "unavailable": {}, "secure_by_default": false,
		"enrollment_platform_restrictions": [{"display_name": "d", "platforms": {}}],
	}}
	some v in r.violations
	contains(v, "CIS 4.1")
}

test_4_2_personal_enrollment_permitted if {
	r := intune.compliance_report with input as {"intune": {
		"collected": true, "unavailable": {}, "secure_by_default": true,
		"enrollment_platform_restrictions": [{"display_name": "Default", "platforms": {
			"iosRestriction": {"personal_device_enrollment_blocked": false},
		}}],
	}}
	some v in r.violations
	contains(v, "CIS 4.2")
}

test_intune_missing_permission_is_not_a_pass if {
	r := intune.compliance_report with input as {"intune": {
		"collected": true,
		"unavailable": {"device_management_settings": "permission denied -- scope missing"},
	}}
	r.compliant == false
}

# ── Attestation ───────────────────────────────────────────────────────

test_uncollectable_controls_are_reported_not_omitted if {
	r := att.compliance_report with input as {}
	r.compliant == false
	r.requires_attestation_count == 6
	r.unresolved_count == 10
	# An omitted control is indistinguishable from a passing one.
	count(r.violations) == 16
}

test_complete_attestation_satisfies_the_control if {
	r := att.compliance_report with input as {"attestations": [{
		"control_id": "5.2.4.1", "observed": "All",
		"attested_by": "operator@example.com", "attested_on": "2026-08-14",
		"evidence_ref": "screenshot-001.png",
	}]}
	every v in r.violations { not contains(v, "CIS 5.2.4.1") }
}

test_attestation_missing_provenance_is_inadmissible if {
	r := att.compliance_report with input as {"attestations": [{
		"control_id": "5.2.4.1", "observed": "All", "attested_by": "operator@example.com",
	}]}
	some v in r.violations
	contains(v, "CIS 5.2.4.1")
	contains(v, "not admissible")
}

test_attestation_marks_its_evidence_source if {
	r := att.compliance_report with input as {}
	r.evidence_source == "attested"
}

# ── Regression: reports must not collapse to {} without input ─────────
# A top-level assignment that reads `input` is undefined when no input is
# supplied at all, which silently collapses compliance_report to {} at the
# OPA endpoint. Both new modules hit this during development.

test_new_section_reports_survive_undefined_input if {
	count(ac.compliance_report) > 0
	count(intune.compliance_report) > 0
	count(att.compliance_report) > 0
}

# ── Section 5 -- the authorizationPolicy cluster ──────────────────────
# One endpoint carries seven controls, so a single fixture exercises all
# of them and a regression in the fetch shows up across the section.

entra_input(extra) := {"entra": object.union({"collected": true, "unavailable": {}}, extra)}

permissive_authz := {"authorization_policy": {
	"allowed_to_create_apps": true,
	"allowed_to_create_security_groups": true,
	"allowed_to_create_tenants": true,
	"allowed_to_read_bitlocker_keys_for_owned_device": true,
	"permission_grant_policy_ids_assigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
	"guest_user_role_id": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
	"allow_invites_from": "everyone",
}}

hardened_authz := {"authorization_policy": {
	"allowed_to_create_apps": false,
	"allowed_to_create_security_groups": false,
	"allowed_to_create_tenants": false,
	"allowed_to_read_bitlocker_keys_for_owned_device": false,
	"permission_grant_policy_ids_assigned": [],
	"guest_user_role_id": "2af84b1e-32c8-42b7-82bc-daa82404023b",
	"allow_invites_from": "adminsAndGuestInviters",
}}

test_authorization_policy_cluster_fires_all_seven if {
	r := entra.compliance_report with input as entra_input(permissive_authz)
	every c in ["5.1.2.2", "5.1.2.3", "5.1.3.1", "5.1.4.6", "5.1.5.1", "5.1.6.2", "5.1.6.3"] {
		some v in r.violations
		contains(v, sprintf("CIS %s", [c]))
	}
}

test_authorization_policy_cluster_silent_when_hardened if {
	r := entra.compliance_report with input as entra_input(hardened_authz)
	every v in r.violations {
		every c in ["5.1.2.2", "5.1.2.3", "5.1.3.1", "5.1.4.6", "5.1.5.1", "5.1.6.2", "5.1.6.3"] {
			not contains(v, sprintf("CIS %s", [c]))
		}
	}
}

test_5_2_3_5_weak_methods_enabled if {
	r := entra.compliance_report with input as entra_input({"weak_methods_enabled": ["sms"]})
	some v in r.violations
	contains(v, "CIS 5.2.3.5")
}

test_5_2_3_7_email_otp_enabled if {
	r := entra.compliance_report with input as entra_input({"email_otp_state": "enabled"})
	some v in r.violations
	contains(v, "CIS 5.2.3.7")
}

test_5_2_3_4_member_not_mfa_capable if {
	r := entra.compliance_report with input as entra_input({"mfa_registration": {
		"members_total": 2,
		"members_not_mfa_capable": [{"user_principal_name": "a@c.com"}],
	}})
	some v in r.violations
	contains(v, "CIS 5.2.3.4")
}

test_5_1_2_1_legacy_per_user_mfa_flagged if {
	r := entra.compliance_report with input as entra_input({"per_user_mfa": {
		"users_checked": 1,
		"legacy_per_user_mfa": [{"user_principal_name": "a@c.com", "state": "enforced"}],
		"api_version": "beta",
	}})
	some v in r.violations
	contains(v, "CIS 5.1.2.1")
}

# 5.1.8.1 only applies to hybrid tenants -- a cloud-only tenant must not
# be marked non-compliant for a control that does not apply to it.
test_5_1_8_1_not_raised_for_cloud_only_tenant if {
	r := entra.compliance_report with input as entra_input({"on_premises_sync": {
		"configured": false, "password_sync_enabled": null,
	}})
	every v in r.violations { not contains(v, "CIS 5.1.8.1") }
}

test_5_1_8_1_raised_for_hybrid_without_hash_sync if {
	r := entra.compliance_report with input as entra_input({"on_premises_sync": {
		"configured": true, "password_sync_enabled": false,
	}})
	some v in r.violations
	contains(v, "CIS 5.1.8.1")
}

test_entra_declares_the_beta_evidence_caveat if {
	r := entra.compliance_report with input as {}
	contains(r.evidence_strength["5.1.2.1"], "beta")
}

test_entra_unavailable_fact_names_the_blocked_control if {
	r := entra.compliance_report with input as {"entra": {
		"collected": true,
		"unavailable": {"authorization_policy": "permission denied -- scope missing"},
	}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 5.1.2.2")
	contains(v, "not a pass")
}

# ── Section 8 -- Teams ────────────────────────────────────────────────

import data.cis_m365_v7.teams as teams

teams_input(extra) := {"teams": object.union({"collected": true, "unavailable": {}}, extra)}

test_8_1_1_unapproved_storage_provider if {
	r := teams.compliance_report with input as teams_input({"client_configuration": {"AllowDropBox": true}})
	some v in r.violations
	contains(v, "CIS 8.1.1")
}

test_8_2_2_unmanaged_teams_users_allowed if {
	r := teams.compliance_report with input as teams_input({"federation_configuration": {"AllowTeamsConsumer": true}})
	some v in r.violations
	contains(v, "CIS 8.2.2")
}

test_8_2_1_open_federation_with_no_allow_list if {
	r := teams.compliance_report with input as teams_input({"federation_configuration": {
		"AllowFederatedUsers": true, "AllowedDomains": [],
	}})
	some v in r.violations
	contains(v, "CIS 8.2.1")
}

test_8_2_1_not_raised_when_an_allow_list_exists if {
	r := teams.compliance_report with input as teams_input({"federation_configuration": {
		"AllowFederatedUsers": true, "AllowedDomains": ["partner.com"],
	}})
	every v in r.violations { not contains(v, "CIS 8.2.1") }
}

test_8_5_1_anonymous_join_in_global_policy if {
	r := teams.compliance_report with input as teams_input({"meeting_policies": [
		{"Identity": "Global", "AllowAnonymousUsersToJoinMeeting": true},
	]})
	some v in r.violations
	contains(v, "CIS 8.5.1")
}

# The reason all policies are checked, not just Global: a hardened Global
# policy does not protect users assigned a permissive one.
test_permissive_non_global_policy_is_not_masked_by_a_clean_global if {
	r := teams.compliance_report with input as teams_input({"meeting_policies": [
		{"Identity": "Global", "AllowAnonymousUsersToJoinMeeting": false},
		{"Identity": "Tag:Contractors", "AllowAnonymousUsersToJoinMeeting": true},
	]})
	some v in r.violations
	contains(v, "CIS 8.5.1")
	contains(v, "Contractors")
}

test_8_5_4_pstn_bypasses_lobby if {
	r := teams.compliance_report with input as teams_input({"meeting_policies": [
		{"Identity": "Global", "AllowPSTNUsersToBypassLobby": true},
	]})
	some v in r.violations
	contains(v, "CIS 8.5.4")
}

test_8_6_1_security_reporting_disabled if {
	r := teams.compliance_report with input as teams_input({"messaging_policies": [
		{"Identity": "Global", "AllowSecurityEndUserReporting": false},
	]})
	some v in r.violations
	contains(v, "CIS 8.6.1")
}

test_teams_absent_facts_is_not_a_pass if {
	r := teams.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
}

test_teams_unavailable_fact_names_the_blocked_control if {
	r := teams.compliance_report with input as {"teams": {
		"collected": true,
		"unavailable": {"meeting_policies": "Teams PowerShell module is not installed"},
	}}
	some v in r.violations
	contains(v, "CIS 8.5.1")
	contains(v, "not a pass")
}

# Section 8 follows CIS's own cmdlets, unlike section 7 -- the note should
# say so rather than claiming a deviation that does not exist here.
test_teams_declares_it_followed_the_documented_cmdlets if {
	r := teams.compliance_report with input as {}
	contains(r.evidence_strength.section, "cmdlets CIS documents")
}

test_teams_report_survives_undefined_input if {
	count(teams.compliance_report) > 0
}

# ── Section 2 -- Defender policy controls (Exchange Online PowerShell) ─

def_input(extra) := {"defender": object.union({"collected": true, "unavailable": {}}, extra)}

test_2_1_1_safe_links_not_enabled_for_office if {
	r := defender.compliance_report with input as def_input({"safe_links_policies": [
		{"Name": "Default", "EnableSafeLinksForOffice": false},
	]})
	some v in r.violations
	contains(v, "CIS 2.1.1")
}

test_2_1_2_attachment_type_filter_disabled if {
	r := defender.compliance_report with input as def_input({"malware_filter_policies": [
		{"Identity": "Default", "EnableFileFilter": false},
	]})
	some v in r.violations
	contains(v, "CIS 2.1.2")
}

test_2_1_4_no_safe_attachments_policy if {
	r := defender.compliance_report with input as def_input({"safe_attachment_policies": []})
	some v in r.violations
	contains(v, "CIS 2.1.4")
}

test_2_1_12_ip_allow_list_in_use if {
	r := defender.compliance_report with input as def_input({"connection_filter_policies": [
		{"Name": "Default", "IPAllowList": ["203.0.113.10"]},
	]})
	some v in r.violations
	contains(v, "CIS 2.1.12")
}

test_2_1_14_allowed_sender_domains if {
	r := defender.compliance_report with input as def_input({"content_filter_policies": [
		{"Name": "Default", "AllowedSenderDomains": ["partner.com"]},
	]})
	some v in r.violations
	contains(v, "CIS 2.1.14")
}

test_2_4_4_teams_zap_off if {
	r := defender.compliance_report with input as def_input({"teams_protection_policy": {"ZapEnabled": false}})
	some v in r.violations
	contains(v, "CIS 2.4.4")
}

# A tenant without Defender for Office 365 has no ATP cmdlets at all. That
# must report as unevaluable, not as compliance -- the absence of a policy
# you cannot query is not evidence the control is met.
test_tenant_without_defender_reports_unevaluable_not_compliant if {
	r := defender.compliance_report with input as {"defender": {
		"collected": true,
		"unavailable": {"safe_attachment_policies": "exchange cmdlet returned no output (blocks 2.1.4)"},
	}}
	r.compliant == false
	some v in r.violations
	contains(v, "CIS 2.1.4")
	contains(v, "not a pass")
}

test_defender_report_survives_undefined_input if {
	count(defender.compliance_report) > 0
}

# ── Section 3 -- DLP and sensitivity labels ───────────────────────────

pv(extra) := {"purview_ps": object.union({"collected": true, "unavailable": {}}, extra)}

test_3_2_1_no_enforcing_dlp_policy if {
	r := purview.compliance_report with input as pv({"dlp_policies": []})
	some v in r.violations
	contains(v, "CIS 3.2.1")
}

# A policy in Test mode reports matches but prevents nothing, so it must
# not satisfy a control asking for DLP to be enabled.
test_3_2_1_test_mode_policy_does_not_satisfy_the_control if {
	r := purview.compliance_report with input as pv({"dlp_policies": [
		{"Name": "Pilot", "Enabled": true, "Mode": "TestWithNotifications"},
	]})
	some v in r.violations
	contains(v, "CIS 3.2.1")
}

test_3_2_2_dlp_does_not_cover_teams if {
	r := purview.compliance_report with input as pv({"dlp_policies": [
		{"Name": "Default", "Enabled": true, "Mode": "Enforce", "TeamsLocation": []},
	]})
	some v in r.violations
	contains(v, "CIS 3.2.2")
}

test_3_3_1_no_published_label_policy if {
	r := purview.compliance_report with input as pv({"label_policies": []})
	some v in r.violations
	contains(v, "CIS 3.3.1")
}

test_purview_ps_unavailable_is_not_a_pass if {
	r := purview.compliance_report with input as {"purview_ps": {
		"collected": true,
		"unavailable": {"dlp_policies": "purview access denied (blocks 3.2.1, 3.2.2, 3.2.3)"},
	}}
	some v in r.violations
	contains(v, "CIS 3.2.1")
	contains(v, "not a pass")
}

# ── Section 1 controls sourced from the Exchange collector ────────────

test_1_3_6_customer_lockbox_disabled if {
	r := ac.compliance_report with input as {
		"admin_center": {"collected": true, "unavailable": {}},
		"exchange": {"collected": true, "unavailable": {}, "organization_config": {"CustomerLockBoxEnabled": false}},
	}
	some v in r.violations
	contains(v, "CIS 1.3.6")
}

test_1_3_9_bookings_without_auth if {
	r := ac.compliance_report with input as {
		"admin_center": {"collected": true, "unavailable": {}},
		"exchange": {"collected": true, "unavailable": {}, "organization_config": {"BookingsEnabled": true, "BookingsAuthEnabled": false}},
	}
	some v in r.violations
	contains(v, "CIS 1.3.9")
}
