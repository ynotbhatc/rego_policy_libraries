package nist.sp800_53.configuration_management_logic_test

# CM family: all-pass fixture, empty input (one finding per evaluated id), one flip and one evidence-missing case
# per Moderate- and High-baseline id, type traps, and the strict absent/non-boolean/false split of CM-1 to CM-11.
# Every test binds its own input (no `with` inside helpers).

import rego.v1

_freq := {"days_since_last": 30, "odp": {"frequency_days": 90}}

_pass := {"cm_controls": {
	"policy": {"documented": true},
	"baseline_config": {
		"maintained": true,
		"automation": {"automated": true, "components_not_covered": 0},
		"previous_versions": {"retained_count": 3, "odp": {"retained_count": 2}},
		"high_risk_travel": {"devices_issued_without_defined_config": 0, "returned_devices_without_controls": 0},
	},
	"change_control": {
		"process_exists": true,
		"testing": {"changes_without_test_record": 0},
		"representatives": {"security_member": true, "privacy_member": true},
		"automation": {
			"documents_proposed_changes": true,
			"notifies_approval_authorities": true,
			"prohibits_unapproved_changes": true,
			"documents_all_changes": true,
			"notifies_on_completion": true,
			"highlight_after_days": 5,
			"odp": {"time_period_days": 7},
		},
		"cryptography": {"mechanisms_not_under_cm": 0},
	},
	"security_impact_analysis": {
		"performed": true,
		"control_verification": {"changes_without_verification": 0},
		"test_environment": {"separate": true, "changes_not_analyzed": 0},
	},
	"access_restrictions_for_change": {
		"enforced": true,
		"automation": {"enforced": true, "audit_records_generated": true},
		"production_privileges": {"unapproved_holders": 0, "review": _freq},
	},
	"configuration_settings": {
		"documented": true,
		"automation": {"automated": true, "components_not_managed": 0},
		"unauthorized_changes": {"response_configured": true, "detected_without_response": 0},
	},
	"least_functionality": {
		"enforced": true,
		"periodic_review": object.union(_freq, {"unnecessary_items_enabled": 0}),
		"program_execution": {"prevention_enforced": true},
		"authorized_software": {"list_defined": true, "deny_all_permit_by_exception": true, "list_review": _freq},
	},
	"system_component_inventory": {
		"maintained": true,
		"updates": {"changes_not_reflected": 0},
		"unauthorized_detection": {"automated": true, "scan": {"days_since_last": 1, "odp": {"frequency_days": 7}}, "detected_without_action": 0},
		"automation": {"automated": true, "components_not_covered": 0},
		"accountability": {"components_without_responsible_individual": 0},
	},
	"config_management_plan": {"documented": true},
	"software_usage_restrictions": {"enforced": true},
	"user_installed_software": {"restricted": true},
	"information_location": {
		"locations_documented": true,
		"users_with_access_documented": true,
		"location_changes_documented": true,
		"automated_discovery": {"tool_in_use": true, "components_not_scanned": 0},
	},
	"data_action_map": {"documented": true, "data_actions_not_mapped": 0},
	"signed_components": {"signature_verification_enforced": true, "installed_without_verified_signature": 0},
}}

# Control ids that have a finding ("NIST CM-2(3): ..." -> "CM-2(3)").
_failing(r) := {id |
	some v in r.violations
	id := substring(v, 5, indexof(v, ":") - 5)
}

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.configuration_management.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.configuration_management.evaluated_controls == {
		"CM-1", "CM-2", "CM-2(2)", "CM-2(3)", "CM-2(7)", "CM-3", "CM-3(1)", "CM-3(2)", "CM-3(4)", "CM-3(6)", "CM-4",
		"CM-4(1)", "CM-4(2)", "CM-5", "CM-5(1)", "CM-5(5)", "CM-6", "CM-6(1)", "CM-6(2)", "CM-7", "CM-7(1)", "CM-7(2)",
		"CM-7(5)", "CM-8", "CM-8(1)", "CM-8(2)", "CM-8(3)", "CM-8(4)", "CM-9", "CM-10", "CM-11", "CM-12", "CM-12(1)",
		"CM-13", "CM-14",
	}
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.configuration_management.compliance_report with input as {}
	ids := data.nist.sp800_53.configuration_management.evaluated_controls with input as {}
	count(r.violations) == count(ids)
	_failing(r) == ids
	r.compliant == false
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# --- original rules: absent is evidence missing, false keeps the original message --------------------------------

test_cm2_false_keeps_original_message if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"maintained": false}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-2: Baseline configuration not established or maintained for the system"}
}

test_cm2_base_absent_is_evidence_missing_and_enhancements_unaffected if {
	inp := json.remove(_pass, ["cm_controls/baseline_config/maintained"])
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-2: evidence missing — input.cm_controls.baseline_config.maintained not collected"}
}

# --- each enhancement and CM-12: one flip, one evidence-missing case -----------------------------------------------

test_cm2_2_components_not_covered_flips_only_cm2_2 if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"automation": {"components_not_covered": 4}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-2(2)"}
	not contains(concat("", r.violations), "evidence missing")
}

test_cm2_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"automation": {"automated": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-2(2)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.baseline_config.automation.automated")
}

test_cm2_3_too_few_versions_flips_only_cm2_3 if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"previous_versions": {"retained_count": 1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-2(3): 1 previous baseline configuration versions retained; the organization-defined number is 2"}
}

test_cm2_3_missing_odp_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"previous_versions": {"odp": {"retained_count": null}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-2(3)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.baseline_config.previous_versions.odp.retained_count")
}

test_cm2_3_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"previous_versions": {"retained_count": "5"}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-2(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm2_7_returned_without_controls_flips_only_cm2_7 if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"high_risk_travel": {"returned_devices_without_controls": 2}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-2(7)"}
}

test_cm2_7_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"baseline_config": {"high_risk_travel": {"devices_issued_without_defined_config": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-2(7)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm3_2_untested_changes_flip_only_cm3_2 if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"testing": {"changes_without_test_record": 3}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-3(2): 3 changes finalized without a test, validation and documentation record"}
}

test_cm3_2_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"testing": {"changes_without_test_record": "1"}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm3_2_negative_count_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"testing": {"changes_without_test_record": -1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm3_4_no_privacy_member_flips_only_cm3_4 if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"representatives": {"privacy_member": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(4)"}
}

test_cm3_4_boolean_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"representatives": {"security_member": "true"}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(4)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.change_control.representatives.security_member")
}

test_cm4_2_unverified_changes_flip_only_cm4_2 if {
	inp := object.union(_pass, {"cm_controls": {"security_impact_analysis": {"control_verification": {"changes_without_verification": 1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-4(2)"}
}

test_cm4_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"security_impact_analysis": {"control_verification": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-4(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm7_1_review_overdue_flips_only_cm7_1 if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"periodic_review": {"days_since_last": 120}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-7(1): least functionality last reviewed 120 days ago; the organization-defined frequency is 90 days"}
}

test_cm7_1_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"periodic_review": {"odp": {"frequency_days": "90"}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-7(1)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.least_functionality.periodic_review.odp.frequency_days")
}

test_cm7_2_not_enforced_flips_only_cm7_2 if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"program_execution": {"prevention_enforced": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-7(2)"}
}

test_cm7_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"program_execution": {"prevention_enforced": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-7(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm7_5_not_deny_all_flips_only_cm7_5 if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"authorized_software": {"deny_all_permit_by_exception": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-7(5)"}
}

test_cm7_5_missing_review_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"authorized_software": {"list_review": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-7(5)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm8_1_unreflected_changes_flip_only_cm8_1 if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"updates": {"changes_not_reflected": 6}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(1)"}
}

test_cm8_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"updates": {"changes_not_reflected": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm8_3_detected_without_action_flips_only_cm8_3 if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"unauthorized_detection": {"detected_without_action": 1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(3)"}
}

test_cm8_3_scan_age_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"unauthorized_detection": {"scan": {"days_since_last": null}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(3)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.system_component_inventory.unauthorized_detection.scan.days_since_last")
}

test_cm12_changes_undocumented_flips_only_cm12 if {
	inp := object.union(_pass, {"cm_controls": {"information_location": {"location_changes_documented": false}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-12"}
}

test_cm12_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"information_location": {"locations_documented": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-12"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm12_1_components_not_scanned_flips_only_cm12_1 if {
	inp := object.union(_pass, {"cm_controls": {"information_location": {"automated_discovery": {"components_not_scanned": 2}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-12(1)"}
}

test_cm12_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"information_location": {"automated_discovery": {"tool_in_use": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-12(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_unmet_and_missing_share_one_finding if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"authorized_software": {"list_defined": false, "list_review": {"days_since_last": null}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	count(r.violations) == 1
	msg := concat("", r.violations)
	contains(msg, "authorized software programs not identified")
	contains(msg, "evidence missing — input.cm_controls.least_functionality.authorized_software.list_review.days_since_last not collected")
}

# --- CM-1 to CM-11 are strict: only true passes; absent, null, "true", 1 or an object is evidence missing --------

test_cm1_null_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"policy": {"documented": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-1: evidence missing — input.cm_controls.policy.documented not collected"}
}

test_cm5_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"access_restrictions_for_change": {"enforced": "true"}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-5: evidence missing — input.cm_controls.access_restrictions_for_change.enforced not collected"}
}

test_cm11_number_one_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"user_installed_software": {"restricted": 1}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-11: evidence missing — input.cm_controls.user_installed_software.restricted not collected"}
}

test_cm7_string_yes_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"least_functionality": {"enforced": "yes"}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-7"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm9_string_false_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"config_management_plan": {"documented": "false"}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-9"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm10_false_keeps_original_message if {
	inp := object.union(_pass, {"cm_controls": {"software_usage_restrictions": {"enforced": false}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-10: Software usage restrictions (licensing/copy controls) not enforced"}
}

# --- CM-13, CM-14 and the High-baseline enhancements: one flip, one evidence-missing case --------------------------

test_cm13_unmapped_actions_flip_only_cm13 if {
	inp := object.union(_pass, {"cm_controls": {"data_action_map": {"data_actions_not_mapped": 2}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-13: 2 system data actions not in the data action map"}
}

test_cm13_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"data_action_map": {"documented": "true"}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-13: evidence missing — input.cm_controls.data_action_map.documented not collected"}
}

test_cm14_not_enforced_flips_only_cm14 if {
	inp := object.union(_pass, {"cm_controls": {"signed_components": {"signature_verification_enforced": false}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-14"}
	not contains(concat("", r.violations), "evidence missing")
}

test_cm14_count_null_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"signed_components": {"installed_without_verified_signature": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-14"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.signed_components.installed_without_verified_signature")
}

test_cm3_1_highlight_later_than_odp_flips_only_cm3_1 if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"automation": {"highlight_after_days": 10}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-3(1): undecided proposed changes highlighted after 10 days; the organization-defined time period is 7 days"}
}

test_cm3_1_not_prohibiting_flips_only_cm3_1 if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"automation": {"prohibits_unapproved_changes": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(1)"}
	not contains(concat("", r.violations), "evidence missing")
}

test_cm3_1_odp_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"automation": {"odp": {"time_period_days": "7"}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(1)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.change_control.automation.odp.time_period_days")
}

test_cm3_6_mechanisms_not_under_cm_flip_only_cm3_6 if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"cryptography": {"mechanisms_not_under_cm": 1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(6)"}
}

test_cm3_6_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"change_control": {"cryptography": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-3(6)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm4_1_no_separate_environment_flips_only_cm4_1 if {
	inp := object.union(_pass, {"cm_controls": {"security_impact_analysis": {"test_environment": {"separate": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-4(1)"}
}

test_cm4_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"security_impact_analysis": {"test_environment": {"changes_not_analyzed": "0"}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-4(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm5_1_no_audit_records_flips_only_cm5_1 if {
	inp := object.union(_pass, {"cm_controls": {"access_restrictions_for_change": {"automation": {"audit_records_generated": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-5(1)"}
}

test_cm5_1_missing_is_evidence_missing_and_base_unaffected if {
	inp := object.union(_pass, {"cm_controls": {"access_restrictions_for_change": {"automation": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-5(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm5_5_review_overdue_flips_only_cm5_5 if {
	inp := object.union(_pass, {"cm_controls": {"access_restrictions_for_change": {"production_privileges": {"review": {"days_since_last": 100}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-5(5): production change privileges last reviewed 100 days ago; the organization-defined frequency is 90 days"}
}

test_cm5_5_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"access_restrictions_for_change": {"production_privileges": {"review": {"odp": null}}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-5(5)"}
	contains(concat("", r.violations), "evidence missing — input.cm_controls.access_restrictions_for_change.production_privileges.review.odp.frequency_days")
}

test_cm6_1_components_not_managed_flip_only_cm6_1 if {
	inp := object.union(_pass, {"cm_controls": {"configuration_settings": {"automation": {"components_not_managed": 3}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-6(1)"}
}

test_cm6_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"configuration_settings": {"automation": {"automated": null}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-6(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm6_2_changes_without_response_flip_only_cm6_2 if {
	inp := object.union(_pass, {"cm_controls": {"configuration_settings": {"unauthorized_changes": {"detected_without_response": 1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-6(2)"}
}

test_cm6_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"configuration_settings": {"unauthorized_changes": {"response_configured": 1}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-6(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm8_2_not_automated_flips_only_cm8_2 if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"automation": {"automated": false}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(2)"}
}

test_cm8_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"automation": null}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cm8_4_no_responsible_individual_flips_only_cm8_4 if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"accountability": {"components_without_responsible_individual": 4}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	r.violations == {"NIST CM-8(4): 4 inventory components with no responsible and accountable individual identified"}
}

test_cm8_4_negative_count_is_evidence_missing if {
	inp := object.union(_pass, {"cm_controls": {"system_component_inventory": {"accountability": {"components_without_responsible_individual": -2}}}})
	r := data.nist.sp800_53.configuration_management.compliance_report with input as inp
	_failing(r) == {"CM-8(4)"}
	contains(concat("", r.violations), "evidence missing")
}
