package nist.sp800_53.access_control_logic_test

# Behaviour tests for the AC checks changed after the 2026-11-17 audit: AC-3 (any approved model),
# AC-7 / AC-11 / AC-14 (organization-defined parameters), AC-11(1), and AC-15 (withdrawn, never a finding).

import data.nist.sp800_53.access_control as ac
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

# --- AC-3 -------------------------------------------------------------------

test_ac3_rbac_alone_passes if {
	rr1 := ac.compliance_report with input as {"ac_controls": {"access_enforcement": {"role_based_access_control": true}}}
	count(_finding(rr1, "AC-3")) == 0
}

test_ac3_abac_alone_passes if {
	rr2 := ac.compliance_report with input as {"ac_controls": {"access_enforcement": {"attribute_based_access_control": true}}}
	count(_finding(rr2, "AC-3")) == 0
}

test_ac3_mac_without_dac_or_rbac_passes if {
	r := ac.compliance_report with input as {"ac_controls": {"access_enforcement": {"mandatory_access_control": true, "discretionary_access_control": false}}}
	count(_finding(r, "AC-3")) == 0
}

test_ac3_no_model_enforced_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"access_enforcement": {"mandatory_access_control": false, "role_based_access_control": false}}}
	f := _finding(r, "AC-3")
	count(f) == 1
	not contains(f[0], "evidence missing")
}

test_ac3_missing_evidence_fails if {
	rr3 := ac.compliance_report with input as {"ac_controls": {}}
	f := _finding(rr3, "AC-3")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ac3_string_true_is_not_evidence if {
	rr4 := ac.compliance_report with input as {"ac_controls": {"access_enforcement": {"role_based_access_control": "true"}}}
	count(_finding(rr4, "AC-3")) == 1
}

# --- AC-7 -------------------------------------------------------------------

test_ac7_within_org_limit_passes if {
	r := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": true, "maximum_attempts": 10, "lockout_duration": 30, "odp": {"max_attempts": 10, "lockout_duration": 30}}}}
	count(_finding(r, "AC-7")) == 0
}

test_ac7_org_limit_not_nist_fixed_five if {
	# 8 attempts would have failed the old hard-coded "max 5"; the organisation defined 10.
	r := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": true, "maximum_attempts": 8, "odp": {"max_attempts": 10}}}}
	count(_finding(r, "AC-7")) == 0
}

test_ac7_above_org_limit_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": true, "maximum_attempts": 6, "odp": {"max_attempts": 3}}}}
	count(_finding(r, "AC-7")) == 1
}

test_ac7_lockout_shorter_than_org_period_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": true, "maximum_attempts": 3, "lockout_duration": 5, "odp": {"max_attempts": 3, "lockout_duration": 30}}}}
	count(_finding(r, "AC-7")) == 1
}

test_ac7_no_lockout_action_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": false, "maximum_attempts": 3, "odp": {"max_attempts": 3}}}}
	count(_finding(r, "AC-7")) == 1
}

test_ac7_missing_odp_is_missing_evidence if {
	rr5 := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": true, "maximum_attempts": 3, "lockout_duration": 30}}}
	f := _finding(rr5, "AC-7")
	count(f) == 1
	contains(f[0], "evidence missing")
	contains(f[0], "odp.max_attempts")
}

test_ac7_missing_configured_value_is_missing_evidence if {
	rr6 := ac.compliance_report with input as {"ac_controls": {"logon_attempts": {"lockout_configured": true, "odp": {"max_attempts": 3}}}}
	f := _finding(rr6, "AC-7")
	count(f) == 1
	contains(f[0], "maximum_attempts")
}

# --- AC-11 / AC-11(1) -------------------------------------------------------

test_ac11_within_org_period_passes if {
	r := ac.compliance_report with input as {"ac_controls": {"session_lock": {"inactivity_timeout": 1800, "authentication_required": true, "pattern_hiding": true, "odp": {"inactivity_timeout": 1800}}}}
	count(_finding(r, "AC-11")) == 0
	count(_finding(r, "AC-11(1)")) == 0
}

test_ac11_longer_than_org_period_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"session_lock": {"inactivity_timeout": 1800, "authentication_required": true, "odp": {"inactivity_timeout": 900}}}}
	count(_finding(r, "AC-11")) == 1
}

test_ac11_lock_not_retained_until_reauth_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"session_lock": {"inactivity_timeout": 600, "authentication_required": false, "odp": {"inactivity_timeout": 900}}}}
	count(_finding(r, "AC-11")) == 1
}

test_ac11_missing_odp_is_missing_evidence if {
	rr7 := ac.compliance_report with input as {"ac_controls": {"session_lock": {"inactivity_timeout": 600, "authentication_required": true}}}
	f := _finding(rr7, "AC-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ac11_pattern_hiding_is_its_own_enhancement if {
	r := ac.compliance_report with input as {"ac_controls": {"session_lock": {"inactivity_timeout": 600, "authentication_required": true, "pattern_hiding": false, "odp": {"inactivity_timeout": 900}}}}
	count(_finding(r, "AC-11")) == 0
	count(_finding(r, "AC-11(1)")) == 1
}

test_ac11_1_missing_evidence_fails if {
	rr8 := ac.compliance_report with input as {"ac_controls": {}}
	count(_finding(rr8, "AC-11(1)")) == 1
}

# --- AC-14 ------------------------------------------------------------------

test_ac14_org_approved_list_passes if {
	r := ac.compliance_report with input as {"ac_controls": {"permitted_actions": {"unauthenticated_functions": ["status_page", "password_reset_start", "docs"], "organization_approved_functions": ["status_page", "password_reset_start", "docs"], "rationale_documented": true}}}
	count(_finding(r, "AC-14")) == 0
}

test_ac14_unapproved_function_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"permitted_actions": {"unauthenticated_functions": ["status_page", "admin_console"], "organization_approved_functions": ["status_page"], "rationale_documented": true}}}
	f := _finding(r, "AC-14")
	count(f) == 1
	contains(f[0], "admin_console")
}

test_ac14_rationale_not_documented_fails if {
	r := ac.compliance_report with input as {"ac_controls": {"permitted_actions": {"unauthenticated_functions": [], "organization_approved_functions": [], "rationale_documented": false}}}
	count(_finding(r, "AC-14")) == 1
}

test_ac14_missing_approved_list_is_missing_evidence if {
	rr9 := ac.compliance_report with input as {"ac_controls": {"permitted_actions": {"unauthenticated_functions": ["system_status"], "rationale_documented": true}}}
	f := _finding(rr9, "AC-14")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- AC-15 withdrawn ----------------------------------------------------------

test_ac15_withdrawn_never_a_finding if {
	rr10 := ac.compliance_report with input as {"ac_controls": {}}
	count(_finding(rr10, "AC-15")) == 0
	r := ac.compliance_report with input as {}
	every v in r.violations {
		not contains(v, "AC-15")
	}
	not "AC-15" in ac.evaluated_controls
}

# --- report contract ---------------------------------------------------------

test_ac_one_finding_per_evaluated_id_on_empty_input if {
	r := ac.compliance_report with input as {}
	r.controls_evaluated == 49
	count(r.violations) == 49
	every id in ac.evaluated_controls {
		count(_finding(r, id)) == 1
	}
}

# --- NIST SP 800-53B Moderate enhancements and fail-closed existing rules ------------------------------------

_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

_pass := {"ac_controls": {
	"policy": {"documented": true, "disseminated": true, "reviewed_updated": true},
	"procedures": {"implementation_documented": true},
	"account_management": {
		"approval_process": true, "regular_reviews": true, "timely_removal": true, "automated_tools": true,
		"temporary_accounts": {"automated_expiry_enforced": true, "max_lifetime_hours": 72, "odp": {"max_lifetime_hours": 72}},
		"disable_accounts": {"inactivity_threshold_days": 35, "max_days_to_disable": 1, "odp": {"inactivity_days": 35, "disable_within_days": 1}},
		"automated_audit": {"creation": true, "modification": true, "enabling": true, "disabling": true, "removal": true},
		"inactivity_logout": {"enforced": true, "logout_after_minutes": 15, "odp": {"logout_after_minutes": 30}},
		"high_risk_individuals": {"max_hours_to_disable": 0, "odp": {"disable_within_hours": 1, "significant_risks": ["termination for cause"]}},
	},
	"access_enforcement": {"role_based_access_control": true},
	"information_flow": {"flow_control_policies": true, "automated_enforcement": true, "security_labels": true},
	"separation_duties": {"critical_functions_divided": true, "documented_assignments": true},
	"least_privilege": {
		"minimum_access_granted": true, "privileged_functions_authorized": true, "non_privileged_access_default": true,
		"privileged_functions_logged": true, "non_privileged_execution_prevented": true,
		"privileged_accounts": {"accounts_outside_authorized_roles": 0, "odp": {"authorized_roles": ["sysadmin"]}},
		"privilege_review": {"days_since_last": 30, "unremediated_findings": 0, "odp": {"frequency_days": 90}},
	},
	"logon_attempts": {"lockout_configured": true, "maximum_attempts": 3, "odp": {"max_attempts": 3}},
	"use_notification": {"banner_displayed": true, "acknowledgment_required": true, "monitoring_consent": true},
	"logon_notification": {"timestamp_displayed": true, "unsuccessful_attempts_displayed": true, "location_displayed": true},
	"session_control": {"limits_configured": true, "per_account_limits": true},
	"session_lock": {"inactivity_timeout": 900, "authentication_required": true, "pattern_hiding": true, "odp": {"inactivity_timeout": 900}},
	"session_termination": {"automatic_termination": true, "user_initiated": true},
	"permitted_actions": {"unauthenticated_functions": [], "organization_approved_functions": [], "rationale_documented": true},
	"security_attributes": {"attribute_binding": true, "attribute_association": true, "transmission_preservation": true},
	"remote_access": {
		"authorized_only": true, "monitored_controlled": true, "encrypted_connections": true, "unmanaged_access_points": 0,
		"privileged_commands": {"restricted_to_defined_needs": true, "assessable_evidence_produced": true, "rationale_in_security_plan": true, "odp": {"needs": ["break-glass recovery"]}},
	},
	"wireless_access": {"authorized_only": true, "encrypted_authentication": true, "components_with_unused_wireless_enabled": 0},
	"mobile_devices": {
		"usage_restrictions": true, "connection_requirements": true, "configuration_requirements": true,
		"encryption": {"devices_without_required_encryption": 0, "odp": {"method": "full-device"}},
	},
	"external_systems": {
		"authorized_only": true, "security_requirements": true, "user_agreements": true,
		"limits_on_authorized_use": {"systems_without_verification_or_agreement": 0},
		"portable_storage": {"restrictions_enforced": true, "odp": {"restrictions": ["encrypted devices only"]}},
	},
	"information_sharing": {"user_discretion_limited": true, "automated_guidance": true},
	"public_content": {"authorized_personnel_only": true, "review_process": true, "removal_procedures": true},
	"data_mining": {"detection_techniques": true, "warning_notifications": true, "response_procedures": true},
	"decisions": {"security_attributes_used": true, "consistent_enforcement": true, "documented_criteria": true},
	"reference_monitor": {"tamper_proof": true, "always_invoked": true, "small_verifiable": true},
}}

test_all_pass_fixture_is_compliant if {
	fx := _pass
	r := ac.compliance_report with input as fx
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_every_finding_is_evidence_missing if {
	r := ac.compliance_report with input as {}
	count(r.violations) == count(ac.evaluated_controls)
	_ids(r) == ac.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# [id, override that fails only that id, override that removes that id's evidence]
_new_cases := [
	["AC-2(2)", {"account_management": {"temporary_accounts": {"max_lifetime_hours": 168}}}, {"account_management": {"temporary_accounts": {"odp": {"max_lifetime_hours": null}}}}],
	["AC-2(3)", {"account_management": {"disable_accounts": {"max_days_to_disable": 5}}}, {"account_management": {"disable_accounts": {"inactivity_threshold_days": null}}}],
	["AC-2(4)", {"account_management": {"automated_audit": {"removal": false}}}, {"account_management": {"automated_audit": {"enabling": null}}}],
	["AC-2(5)", {"account_management": {"inactivity_logout": {"logout_after_minutes": 60}}}, {"account_management": {"inactivity_logout": {"odp": null}}}],
	["AC-2(13)", {"account_management": {"high_risk_individuals": {"max_hours_to_disable": 24}}}, {"account_management": {"high_risk_individuals": {"odp": {"significant_risks": []}}}}],
	["AC-6(5)", {"least_privilege": {"privileged_accounts": {"accounts_outside_authorized_roles": 2}}}, {"least_privilege": {"privileged_accounts": {"odp": null}}}],
	["AC-6(7)", {"least_privilege": {"privilege_review": {"days_since_last": 120}}}, {"least_privilege": {"privilege_review": {"unremediated_findings": null}}}],
	["AC-6(9)", {"least_privilege": {"privileged_functions_logged": false}}, {"least_privilege": {"privileged_functions_logged": null}}],
	["AC-6(10)", {"least_privilege": {"non_privileged_execution_prevented": false}}, {"least_privilege": {"non_privileged_execution_prevented": null}}],
	["AC-17(3)", {"remote_access": {"unmanaged_access_points": 1}}, {"remote_access": {"unmanaged_access_points": null}}],
	["AC-17(4)", {"remote_access": {"privileged_commands": {"assessable_evidence_produced": false}}}, {"remote_access": {"privileged_commands": {"odp": {"needs": null}}}}],
	["AC-18(3)", {"wireless_access": {"components_with_unused_wireless_enabled": 3}}, {"wireless_access": {"components_with_unused_wireless_enabled": null}}],
	["AC-19(5)", {"mobile_devices": {"encryption": {"devices_without_required_encryption": 4}}}, {"mobile_devices": {"encryption": {"odp": {"method": "some"}}}}],
	["AC-20(1)", {"external_systems": {"limits_on_authorized_use": {"systems_without_verification_or_agreement": 1}}}, {"external_systems": {"limits_on_authorized_use": null}}],
	["AC-20(2)", {"external_systems": {"portable_storage": {"restrictions_enforced": false}}}, {"external_systems": {"portable_storage": {"restrictions_enforced": null}}}],
]

test_new_ids_are_evaluated if {
	every c in _new_cases {
		c[0] in ac.evaluated_controls
	}
	count(_new_cases) == 15
}

test_each_new_id_failing_case_flips_only_that_id if {
	every c in _new_cases {
		fx := object.union(_pass, {"ac_controls": c[1]})
		r := ac.compliance_report with input as fx
		_ids(r) == {c[0]}
		not contains(concat("", r.violations), "evidence missing")
	}
}

test_each_new_id_missing_evidence_flips_only_that_id if {
	every c in _new_cases {
		fx := object.union(_pass, {"ac_controls": c[2]})
		r := ac.compliance_report with input as fx
		_ids(r) == {c[0]}
		contains(concat("", r.violations), "evidence missing")
	}
}

test_new_numeric_fact_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ac_controls": {"remote_access": {"unmanaged_access_points": "1"}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-17(3)"}
	contains(concat("", r.violations), "evidence missing — input.ac_controls.remote_access.unmanaged_access_points")
}

test_new_odp_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ac_controls": {"account_management": {"inactivity_logout": {"odp": {"logout_after_minutes": "30"}}}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-2(5)"}
	contains(concat("", r.violations), "evidence missing")
}

test_new_boolean_as_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"ac_controls": {"least_privilege": {"privileged_functions_logged": "true"}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-6(9)"}
	contains(concat("", r.violations), "evidence missing")
}

test_enhancement_failure_leaves_base_passing if {
	fx := object.union(_pass, {"ac_controls": {"account_management": {"automated_audit": {"creation": false}, "inactivity_logout": {"enforced": false}}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-2(4)", "AC-2(5)"}
}

# Existing rules: an absent or non-boolean fact is evidence missing; a false fact is the rule's own finding.
test_existing_boolean_as_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"ac_controls": {"use_notification": {"banner_displayed": "true"}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-8"}
	contains(concat("", r.violations), "evidence missing — input.ac_controls.use_notification.banner_displayed")
}

test_existing_false_fact_is_not_evidence_missing if {
	fx := object.union(_pass, {"ac_controls": {"use_notification": {"banner_displayed": false}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-8"}
	not contains(concat("", r.violations), "evidence missing")
}

test_ac11_authentication_required_absent_is_evidence_missing if {
	fx := object.union(_pass, {"ac_controls": {"session_lock": {"authentication_required": null}}})
	r := ac.compliance_report with input as fx
	_ids(r) == {"AC-11"}
	contains(concat("", r.violations), "evidence missing — input.ac_controls.session_lock.authentication_required")
}
