package nist.sp800_53.awareness_training_logic_test

# AT family: one finding per base control, fail closed, organization-defined frequencies and periods.

import data.nist.sp800_53.awareness_training as at
import rego.v1

# The ids that have a finding in a report ("NIST AT-2: ..." -> "AT-2").
_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

_freq(days, odp) := {"days_since_last": days, "odp": {"frequency_days": odp}}

_pass := {"at_controls": {
	"policy_procedures": {
		"policy_documented": true,
		"procedures_documented": true,
		"official_designated": true,
		"policy_review": _freq(200, 365),
		"procedures_review": _freq(100, 365),
	},
	"literacy_training": {
		"initial_training_for_new_users": true,
		"training_on_system_changes_and_events": true,
		"awareness_techniques_employed": true,
		"lessons_learned_incorporated": true,
		"refresher": _freq(300, 365),
		"content_update": _freq(30, 365),
		"insider_threat": {"module_in_curriculum": true, "users_not_completed": 0},
		"social_engineering": {"module_in_curriculum": true, "users_not_completed": 0},
	},
	"role_based_training": {
		"trained_before_access": true,
		"training_on_system_changes": true,
		"lessons_learned_incorporated": true,
		"refresher": _freq(300, 365),
		"content_update": _freq(30, 365),
	},
	"training_records": {"documented_and_monitored": true, "retention_days": 1825, "odp": {"retention_days": 1825}},
	"training_feedback": {"provided_to_designated_personnel": true, "days_since_last": 80, "odp": {"frequency_days": 90}},
}}

test_all_pass_fixture_is_compliant if {
	fx := _pass
	r := at.compliance_report with input as fx
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_the_catalog if {
	at.evaluated_controls == {"AT-1", "AT-2", "AT-2(2)", "AT-2(3)", "AT-3", "AT-4", "AT-6"}
}

test_empty_input_one_finding_per_control if {
	r := at.compliance_report with input as {}
	r.compliant == false
	count(r.violations) == count(at.evaluated_controls)
	_ids(r) == at.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# --- each control: one failing case flips exactly that id -------------------------------------------------------

test_at1_procedures_not_documented_flips_only_at1 if {
	fx := object.union(_pass, {"at_controls": {"policy_procedures": {"procedures_documented": false}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-1"}
	contains(concat("", r.violations), "procedures not documented")
}

test_at1_lists_every_unmet_element_in_one_finding if {
	fx := object.union(_pass, {"at_controls": {"policy_procedures": {"official_designated": false, "policy_review": {"days_since_last": 400}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-1"}
	count(r.violations) == 1
	msg := concat("", r.violations)
	contains(msg, "no official designated")
	contains(msg, "policy last reviewed 400 days ago")
}

test_at2_refresher_overdue_flips_only_at2 if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"refresher": {"days_since_last": 400}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2"}
	contains(concat("", r.violations), "organization-defined frequency is 365 days")
}

test_at3_not_trained_before_access_flips_only_at3 if {
	fx := object.union(_pass, {"at_controls": {"role_based_training": {"trained_before_access": false}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-3"}
}

test_at4_short_retention_flips_only_at4 if {
	fx := object.union(_pass, {"at_controls": {"training_records": {"retention_days": 365}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-4"}
	contains(concat("", r.violations), "retained for 365 days")
}

test_at6_feedback_overdue_flips_only_at6 if {
	fx := object.union(_pass, {"at_controls": {"training_feedback": {"days_since_last": 91}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-6"}
}

# --- type traps -------------------------------------------------------------------------------------------------

test_numeric_fact_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"refresher": {"days_since_last": "1"}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2"}
	msg := concat("", r.violations)
	contains(msg, "evidence missing")
	contains(msg, "refresher.days_since_last")
}

test_numeric_fact_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"training_records": {"odp": {"retention_days": null}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-4"}
	contains(concat("", r.violations), "evidence missing — input.at_controls.training_records.odp.retention_days")
}

test_string_organization_frequency_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"training_feedback": {"odp": {"frequency_days": "1"}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-6"}
	contains(concat("", r.violations), "evidence missing")
}

# A boolean of the wrong type is missing evidence (per-control results classify it as evidence_missing).
test_boolean_as_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"policy_procedures": {"policy_documented": "true"}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-1"}
	contains(concat("", r.violations), "evidence missing — input.at_controls.policy_procedures.policy_documented")
}

test_boolean_as_one_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"lessons_learned_incorporated": 1}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2"}
	contains(concat("", r.violations), "evidence missing")
}

test_boolean_false_is_a_finding_not_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"policy_procedures": {"policy_documented": false}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-1"}
	msg := concat("", r.violations)
	contains(msg, "policy_documented is not true")
	not contains(msg, "evidence missing")
}

# --- AT-2(2) / AT-2(3) ------------------------------------------------------------------------------------------

test_at2_2_module_missing_from_curriculum_flips_only_at2_2 if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"insider_threat": {"module_in_curriculum": false}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2(2)"}
	not contains(concat("", r.violations), "evidence missing")
}

test_at2_2_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"insider_threat": {"users_not_completed": null}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2(2)"}
	contains(concat("", r.violations), "evidence missing — input.at_controls.literacy_training.insider_threat.users_not_completed")
}

test_at2_3_users_not_completed_flips_only_at2_3 if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"social_engineering": {"users_not_completed": 12}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2(3)"}
	contains(concat("", r.violations), "12 users have not completed")
}

test_at2_3_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"social_engineering": null}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_at2_3_count_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"social_engineering": {"users_not_completed": "0"}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_at2_2_boolean_as_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"literacy_training": {"insider_threat": {"module_in_curriculum": "true"}}}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-2(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_section_not_an_object_is_evidence_missing if {
	fx := object.union(_pass, {"at_controls": {"training_feedback": "yes"}})
	r := at.compliance_report with input as fx
	_ids(r) == {"AT-6"}
	contains(concat("", r.violations), "evidence missing")
}
