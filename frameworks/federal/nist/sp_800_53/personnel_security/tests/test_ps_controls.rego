package nist.sp800_53.personnel_security_logic_test

# Logic tests for the PS family: all-pass fixture, fail-closed on empty input, one id per failing case,
# type traps, and the evaluated id list. Every test binds its own input (no `with` inside helpers).

import rego.v1

_ids(vs) := {m[0][1] |
	some v in vs
	m := regex.find_all_string_submatch_n(`^NIST ([A-Z]{2}-[0-9]+(?:\([0-9]+\))?): `, v, 1)
	count(m) == 1
}

# Empty input yields evidence missing for fact controls and a missing attestation for organizational ones.
_fail_closed_message(v) if contains(v, "evidence missing")

_fail_closed_message(v) if contains(v, "not attested")

_pass := {"ps_controls": {
	"policy": {
		"documented": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"procedures": {
		"documented": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"official": {"designated": true},
	"position_risk": {
		"screening_criteria_established": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
		"positions_without_designation": 0,
	},
	"screening": {
		"unscreened_with_access": 0,
		"rescreening_overdue": 0,
		"special_protection": {
			"individuals_without_valid_authorization": 0,
			"individuals_not_meeting_criteria": 0,
			"odp": {"criteria": ["polygraph for compartmented programs"]},
		},
	},
	"termination": {
		"exit_interviews_conducted": true,
		"property_retrieved": true,
		"access_retained": true,
		"max_hours_to_disable": 30,
		"odp": {"disable_within_hours": 365},
		"active_credentials_after_termination": 0,
		"automated_actions": {
			"enabled": true,
			"terminations_without_automated_action": 0,
			"odp": {"mechanisms": ["HR feed to identity provider"], "actions": ["notify", "disable_access"]},
		},
	},
	"transfer": {
		"access_need_reviewed": true,
		"access_modified": true,
		"max_days_to_initiate": 30,
		"odp": {
			"initiate_within_days": 365,
			"notify_within_hours": 365,
		},
		"max_hours_to_notify": 30,
	},
	"access_agreements": {
		"documented": true,
		"resign_required": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
		"unsigned_with_access": 0,
	},
	"external_personnel": {
		"requirements_established": true,
		"compliance_required": true,
		"requirements_documented": true,
		"compliance_monitored": true,
		"max_hours_to_notify": 30,
		"odp": {"notify_within_hours": 365},
	},
	"sanctions": {
		"process_employed": true,
		"max_hours_to_notify": 30,
		"odp": {"notify_within_hours": 365},
	},
	"position_descriptions": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
}}

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.personnel_security.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
	r.controls_evaluated == 11
}

test_empty_input_one_finding_per_control if {
	vs := data.nist.sp800_53.personnel_security.violation with input as {}
	ec := data.nist.sp800_53.personnel_security.evaluated_controls with input as {}
	count(vs) == count(ec)
	_ids(vs) == ec
	every v in vs {
		_fail_closed_message(v)
	}
	r := data.nist.sp800_53.personnel_security.compliance_report with input as {}
	r.compliant == false
}

test_non_object_family_root_fails_closed if {
	vs := data.nist.sp800_53.personnel_security.violation with input as {"ps_controls": "yes"}
	count(vs) == 11
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.personnel_security.evaluated_controls == {"PS-1", "PS-2", "PS-3", "PS-3(3)", "PS-4", "PS-4(2)", "PS-5", "PS-6", "PS-7", "PS-8", "PS-9"}
}

test_ps1_failing_case_flips_only_ps1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/documented", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	count(vs) == 1
}

test_ps2_failing_case_flips_only_ps2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_risk/screening_criteria_established", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-2"}
	count(vs) == 1
}

test_ps3_failing_case_flips_only_ps3 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/screening/unscreened_with_access", "value": 3}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-3"}
	count(vs) == 1
}

test_ps4_failing_case_flips_only_ps4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/exit_interviews_conducted", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4"}
	count(vs) == 1
}

test_ps5_failing_case_flips_only_ps5 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/transfer/access_need_reviewed", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-5"}
	count(vs) == 1
}

test_ps6_failing_case_flips_only_ps6 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/access_agreements/documented", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-6"}
	count(vs) == 1
}

test_ps7_failing_case_flips_only_ps7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/external_personnel/requirements_established", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-7"}
	count(vs) == 1
}

test_ps8_failing_case_flips_only_ps8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/sanctions/process_employed", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-8"}
	count(vs) == 1
}

test_ps9_failing_case_flips_only_ps9 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_descriptions/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-9"}
	count(vs) == 1
}

test_ps1_procedures_documented_flips_only_ps1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/procedures/documented", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	count(vs) == 1
}

test_ps1_official_designated_flips_only_ps1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/official/designated", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	count(vs) == 1
}

test_ps1_policy_days_since_last_flips_only_ps1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	count(vs) == 1
}

test_ps1_procedures_days_since_last_flips_only_ps1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/procedures/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	count(vs) == 1
}

test_ps2_position_risk_days_since_last_flips_only_ps2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_risk/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-2"}
	count(vs) == 1
}

test_ps2_position_risk_positions_without_designation_flips_only_ps2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_risk/positions_without_designation", "value": 3}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-2"}
	count(vs) == 1
}

test_ps3_screening_rescreening_overdue_flips_only_ps3 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/screening/rescreening_overdue", "value": 3}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-3"}
	count(vs) == 1
}

test_ps4_termination_property_retrieved_flips_only_ps4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/property_retrieved", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4"}
	count(vs) == 1
}

test_ps4_termination_access_retained_flips_only_ps4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/access_retained", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4"}
	count(vs) == 1
}

test_ps4_termination_max_hours_to_disable_flips_only_ps4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/max_hours_to_disable", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4"}
	count(vs) == 1
}

test_ps4_termination_active_credentials_after_termination_flips_only_ps4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/active_credentials_after_termination", "value": 3}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4"}
	count(vs) == 1
}

test_ps5_transfer_access_modified_flips_only_ps5 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/transfer/access_modified", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-5"}
	count(vs) == 1
}

test_ps5_transfer_max_days_to_initiate_flips_only_ps5 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/transfer/max_days_to_initiate", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-5"}
	count(vs) == 1
}

test_ps5_transfer_max_hours_to_notify_flips_only_ps5 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/transfer/max_hours_to_notify", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-5"}
	count(vs) == 1
}

test_ps6_access_agreements_resign_required_flips_only_ps6 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/access_agreements/resign_required", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-6"}
	count(vs) == 1
}

test_ps6_access_agreements_days_since_last_flips_only_ps6 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/access_agreements/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-6"}
	count(vs) == 1
}

test_ps6_access_agreements_unsigned_with_access_flips_only_ps6 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/access_agreements/unsigned_with_access", "value": 3}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-6"}
	count(vs) == 1
}

test_ps7_external_personnel_compliance_required_flips_only_ps7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/external_personnel/compliance_required", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-7"}
	count(vs) == 1
}

test_ps7_external_personnel_requirements_documented_flips_only_ps7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/external_personnel/requirements_documented", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-7"}
	count(vs) == 1
}

test_ps7_external_personnel_compliance_monitored_flips_only_ps7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/external_personnel/compliance_monitored", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-7"}
	count(vs) == 1
}

test_ps7_external_personnel_max_hours_to_notify_flips_only_ps7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/external_personnel/max_hours_to_notify", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-7"}
	count(vs) == 1
}

test_ps8_sanctions_max_hours_to_notify_flips_only_ps8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/sanctions/max_hours_to_notify", "value": 400}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-8"}
	count(vs) == 1
}

test_numeric_fact_as_string_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/days_since_last", "value": "1"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	some v in vs
	contains(v, "evidence missing")
	contains(v, "policy.days_since_last")
}

test_numeric_fact_as_null_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/days_since_last", "value": null}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	some v in vs
	contains(v, "evidence missing")
	contains(v, "policy.days_since_last")
}

test_boolean_fact_as_string_true_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/documented", "value": "true"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
}

test_boolean_fact_as_one_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/documented", "value": 1}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
}

test_ps1_lists_every_unmet_element if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/documented", "value": false}, {"op": "replace", "path": "/ps_controls/procedures/days_since_last", "value": 999}, {"op": "remove", "path": "/ps_controls/official/designated"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-1"}
	count(vs) == 1
	some v in vs
	contains(v, "evidence missing")
	contains(v, "input.ps_controls.official.designated")
	contains(v, "policy not documented")
	contains(v, "999 days ago")
}

test_ps1_review_within_frequency_passes if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/policy/days_since_last", "value": 365}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	count(vs) == 0
}

test_attestation_attested_as_string_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_descriptions/attestation/attested", "value": "true"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-9"}
	some v in vs
	contains(v, "not attested")
}

test_attestation_empty_by_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_descriptions/attestation/by", "value": ""}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-9"}
	some v in vs
	contains(v, "not attested")
}

test_attestation_missing_date_is_a_finding if {
	inp := json.patch(_pass, [{"op": "remove", "path": "/ps_controls/position_descriptions/attestation/date"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-9"}
	some v in vs
	contains(v, "not attested")
}

test_attestation_bare_true_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/position_descriptions/attestation", "value": true}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-9"}
	some v in vs
	contains(v, "not attested")
}

# --- NIST / FedRAMP High-baseline enhancements -----------------------------------------------------------------

# [id, JSON patch that fails only that id, JSON patch that removes that id's evidence]
_high_cases := [
	["PS-3(3)", [{"op": "replace", "path": "/ps_controls/screening/special_protection/individuals_not_meeting_criteria", "value": 2}], [{"op": "replace", "path": "/ps_controls/screening/special_protection/odp/criteria", "value": []}]],
	["PS-4(2)", [{"op": "replace", "path": "/ps_controls/termination/automated_actions/terminations_without_automated_action", "value": 1}], [{"op": "replace", "path": "/ps_controls/termination/automated_actions/odp/actions", "value": ["email the manager"]}]],
]

test_each_high_id_failing_case_flips_only_that_id if {
	every c in _high_cases {
		inp := json.patch(_pass, c[1])
		vs := data.nist.sp800_53.personnel_security.violation with input as inp
		_ids(vs) == {c[0]}
		count(vs) == 1
		not contains(concat("", vs), "evidence missing")
	}
}

test_each_high_id_missing_evidence_flips_only_that_id if {
	every c in _high_cases {
		inp := json.patch(_pass, c[2])
		vs := data.nist.sp800_53.personnel_security.violation with input as inp
		_ids(vs) == {c[0]}
		count(vs) == 1
		contains(concat("", vs), "evidence missing")
	}
}

test_ps4_2_disabled_mechanism_flips_only_ps4_2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/automated_actions/enabled", "value": false}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4(2)"}
}

test_ps4_2_enabled_as_string_true_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/termination/automated_actions/enabled", "value": "true"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-4(2)"}
	contains(concat("", vs), "evidence missing")
}

test_ps3_3_count_as_string_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/screening/special_protection/individuals_without_valid_authorization", "value": "0"}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-3(3)"}
	contains(concat("", vs), "evidence missing")
}

test_ps3_3_count_as_null_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/ps_controls/screening/special_protection/individuals_not_meeting_criteria", "value": null}])
	vs := data.nist.sp800_53.personnel_security.violation with input as inp
	_ids(vs) == {"PS-3(3)"}
	contains(concat("", vs), "evidence missing")
}
