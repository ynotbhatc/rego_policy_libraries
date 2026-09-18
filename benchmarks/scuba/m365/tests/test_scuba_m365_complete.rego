# Unit tests for the SCuBA M365 master orchestrator
# (benchmarks/scuba/m365/scuba_m365_complete.rego, package scuba_m365.main).
#
# These tests exercise the AGGREGATE report only — the orchestrator that
# concatenates the seven product modules (aad, defender, exo, powerbi,
# powerplatform, sharepoint, teams) into one compliance_report. The fixture
# below is a fully-compliant tenant across all 104 policies; individual
# product-module behaviour is covered by the sibling test_*_validation files.
#
# Package is scuba_m365.main_test so it never collides with the existing
# scuba_m365_test package in this directory; the fixture is embedded here
# (not imported) so concurrent edits to sibling files cannot break it.

package scuba_m365.main_test

import data.scuba_m365.main
import rego.v1

# ── Fully-compliant tenant fixture (all 104 policies satisfied) ──────────────

compliant_input := {
	"tenant_name": "example.onmicrosoft.com",
	"assessment_date": "2026-09-16",
	"scuba": {
		"aad": {
			"legacy_auth_blocked": true,
			"risk": {
				"high_risk_users_blocked": true,
				"high_risk_user_alerts": true,
				"high_risk_signins_blocked": true,
			},
			"auth": {
				"phishing_resistant_mfa_all_users": true,
				"mfa_enforced_all_users": true,
				"authenticator": {"enabled": true, "login_context_shown": true},
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
				"certificate_lifetime_days": 365,
			},
			"passwords": {"expiration_disabled": true},
			"privileged": {
				"global_admin_count": 3,
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
		},
		"defender": {
			"presets": {
				"standard_strict_enabled": true,
				"eop_all_users": true,
				"atp_all_users": true,
				"eop_sensitive_strict": true,
				"atp_sensitive_strict": true,
			},
			"impersonation": {
				"user_protection_sensitive": true,
				"domain_protection_owned": true,
				"domain_protection_partners": true,
			},
			"safe_attachments": {"spo_odb_teams_enabled": true},
			"dlp": {
				"custom_pii_policy": true,
				"applied_all_workloads": true,
				"block_everyone_action": true,
				"user_notifications": true,
				"restricted_apps_list": true,
				"restricted_apps_blocked": true,
			},
			"alerts": {
				"required_exo_alerts_enabled": true,
				"routed_to_monitored_target": true,
			},
			"audit": {
				"unified_logging_enabled": true,
				"retention_meets_m2131": true,
			},
		},
		"exo": {
			"auto_forwarding_disabled": true,
			"spf_fail_policy_all_domains": true,
			"dkim_enabled_all_domains": true,
			"dmarc": {
				"published_all_domains": true,
				"policy_reject": true,
				"rua_includes_cisa": true,
				"agency_poc_included": true,
			},
			"smtp_auth_disabled": true,
			"sharing": {
				"contacts_not_all_domains": true,
				"calendar_not_all_domains": true,
			},
			"external_sender_warnings": true,
			"mailbox_auditing_enabled": true,
		},
		"powerbi": {
			"publish_to_web_disabled": true,
			"guest_access_disabled": true,
			"external_invitations_disabled": true,
			"service_principals": {
				"api_restricted_to_groups": true,
				"profiles_restricted_to_groups": true,
			},
			"resourcekey_auth_blocked": true,
			"python_r_interactions_disabled": true,
			"sensitivity_labels_enabled": true,
		},
		"powerplatform": {
			"environment_creation": {
				"production_restricted_to_admins": true,
				"trial_restricted_to_admins": true,
			},
			"dlp": {
				"default_environment_policy": true,
				"nondefault_environments_covered": true,
			},
			"tenant_isolation": {
				"enabled": true,
				"connection_allowlist": true,
			},
			"apps_csp_enforced": true,
			"power_pages_creation_restricted": true,
			"share_with_everyone_disabled": true,
		},
		"sharepoint": {
			"external_sharing": {
				"spo_restricted": true,
				"odb_restricted": true,
				"domain_allowlist": true,
			},
			"default_sharing": {
				"scope_specific_people": true,
				"permission_view_only": true,
			},
			"anyone_links": {"expiration_days": 30, "view_only": true},
			"verification_code_reauth_days": 30,
		},
		"teams": {
			"meetings": {
				"external_control_blocked": true,
				"anonymous_start_blocked": true,
				"lobby_for_anonymous_and_dialin": true,
				"internal_auto_admit": true,
				"dialin_lobby_enforced": true,
				"recording_disabled": true,
				"no_always_record": true,
			},
			"external_access": {
				"per_domain_only": true,
				"unmanaged_inbound_blocked": true,
				"unmanaged_outbound_blocked": true,
			},
			"email_integration_disabled": true,
			"apps": {
				"microsoft_apps_approved_only": true,
				"third_party_approved_only": true,
				"custom_approved_only": true,
			},
		},
	},
}

# ── Case 1: empty input still yields a populated, well-formed report ─────────
# Guards the undefined→{} collapse across every aggregated module: even with
# zero facts the orchestrator must emit a populated object whose `compliant`
# is a real boolean (fail-closed to false), never `undefined`.

test_empty_input_yields_populated_object_with_boolean_compliant if {
	r := main.compliance_report with input as {}
	is_object(r)
	count(r) > 0
	is_boolean(r.compliant)
	is_boolean(r.shall_compliant)
	r.compliant == false
}

# ── Case 2: fully-compliant tenant → empty aggregate violations ──────────────

test_fully_compliant_tenant_has_empty_aggregate_violations if {
	r := main.compliance_report with input as compliant_input
	r.compliant == true
	r.shall_compliant == true
	count(r.violations) == 0
	r.violation_count == 0
}

# ── Case 3: a product-module violation propagates into the aggregate ─────────
# Flip one SharePoint SHALL control off; assert the exact message text surfaces
# in the AGGREGATE `violations` array (not just the per-module report) and that
# it flips the top-level compliant/shall_compliant to false.

test_single_product_violation_propagates_to_aggregate if {
	broken := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/sharepoint/external_sharing/spo_restricted",
		"value": false,
	}])
	r := main.compliance_report with input as broken
	r.compliant == false
	r.shall_compliant == false
	r.violation_count == 1
	count(r.violations) == 1
	some v in r.violations
	contains(v, "MS.SHAREPOINT.1.1")
}

# ── Case 4: per-product summary is present and cross-foots to the aggregate ──
# product_summary is keyed by each report's `baseline`; a duplicate key would
# collapse an entry, so the count of 7 also proves distinct baselines. The sums
# prove the aggregate counts are exactly the sum of the seven product reports.

test_product_summary_present_and_cross_foots_to_aggregate if {
	r := main.compliance_report with input as {}
	count(r.product_summary) == 7
	sum([s.violation_count | some s in r.product_summary]) == r.violation_count
	sum([s.shall_violation_count | some s in r.product_summary]) == r.shall_violation_count
	sum([s.should_violation_count | some s in r.product_summary]) == r.should_violation_count
}

# ── Aggregate accounting: policies_evaluated == BASELINE_TOTAL_POLICIES ───────

test_accounting_balanced_on_empty_input if {
	r := main.compliance_report with input as {}
	r.policies_evaluated == 104
	r.total_controls == 104
	r.accounting_balanced == true
}
