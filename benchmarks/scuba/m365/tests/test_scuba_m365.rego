package scuba_m365_test

import data.scuba_m365.aad
import data.scuba_m365.defender
import data.scuba_m365.exo
import data.scuba_m365.main
import data.scuba_m365.powerbi
import data.scuba_m365.powerplatform
import data.scuba_m365.sharepoint
import data.scuba_m365.teams
import rego.v1

# ── Fail-closed: absent facts fire every policy in every module ──────────────

test_aad_empty_input_fails_all_34 if {
	r := aad.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 34
}

test_defender_empty_input_fails_all_19 if {
	r := defender.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 19
}

test_exo_empty_input_fails_all_12 if {
	r := exo.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 12
}

test_powerbi_empty_input_fails_all_8 if {
	r := powerbi.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 8
}

test_powerplatform_empty_input_fails_all_9 if {
	r := powerplatform.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 9
}

test_sharepoint_empty_input_fails_all_8 if {
	r := sharepoint.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 8
}

test_teams_empty_input_fails_all_14 if {
	r := teams.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 14
}

# ── Main aggregation: coverage accounting and totals ─────────────────────────

test_main_empty_input_reports_104_violations if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.shall_compliant == false
	r.violation_count == 104
	r.policies_evaluated == 104
	r.accounting_balanced == true
}

test_main_shall_should_partition if {
	r := main.compliance_report with input as {}
	(r.shall_violation_count + r.should_violation_count) == r.violation_count
	# Verified split from the baseline documents' machine-readable
	# criticality comments: 59 SHALL, 45 SHOULD.
	r.shall_violation_count == 59
	r.should_violation_count == 45
}

test_main_report_wellformed_on_empty_input if {
	r := main.compliance_report with input as {}
	is_object(r)
	count(r.product_summary) == 7
}

# ── Fully compliant tenant ───────────────────────────────────────────────────

compliant_aad := {
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
}

compliant_input := {
	"tenant_name": "example.onmicrosoft.com",
	"assessment_date": "2026-09-16",
	"scuba": {
		"aad": compliant_aad,
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

test_fully_compliant_tenant if {
	r := main.compliance_report with input as compliant_input
	r.compliant == true
	r.shall_compliant == true
	r.violation_count == 0
	r.tenant_name == "example.onmicrosoft.com"
}

# ── Conditional and boundary controls ────────────────────────────────────────

test_authenticator_disabled_satisfies_aad_3_3 if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/aad/auth/authenticator",
		"value": {"enabled": false},
	}])
	r := aad.compliance_report with input as modified
	not any_violation_contains(r.violations, "MS.AAD.3.3")
}

test_authenticator_enabled_without_context_fails_aad_3_3 if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/aad/auth/authenticator",
		"value": {"enabled": true, "login_context_shown": false},
	}])
	r := aad.compliance_report with input as modified
	any_violation_contains(r.violations, "MS.AAD.3.3")
}

test_nine_global_admins_fails_aad_7_1 if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/aad/privileged/global_admin_count",
		"value": 9,
	}])
	r := aad.compliance_report with input as modified
	any_violation_contains(r.violations, "MS.AAD.7.1")
}

test_one_global_admin_fails_aad_7_1 if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/aad/privileged/global_admin_count",
		"value": 1,
	}])
	r := aad.compliance_report with input as modified
	any_violation_contains(r.violations, "MS.AAD.7.1")
}

test_anyone_link_60_days_fails_sharepoint_3_1 if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/sharepoint/anyone_links/expiration_days",
		"value": 60,
	}])
	r := sharepoint.compliance_report with input as modified
	any_violation_contains(r.violations, "MS.SHAREPOINT.3.1")
}

test_dmarc_not_reject_is_shall_violation if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/exo/dmarc/policy_reject",
		"value": false,
	}])
	r := main.compliance_report with input as modified
	r.compliant == false
	r.shall_compliant == false
	r.shall_violation_count == 1
	r.should_violation_count == 0
}

test_should_only_violation_keeps_shall_compliant if {
	modified := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/scuba/teams/meetings/recording_disabled",
		"value": false,
	}])
	r := main.compliance_report with input as modified
	r.compliant == false
	r.shall_compliant == true
	r.should_violation_count == 1
}

any_violation_contains(violations, needle) if {
	some v in violations
	contains(v, needle)
}
