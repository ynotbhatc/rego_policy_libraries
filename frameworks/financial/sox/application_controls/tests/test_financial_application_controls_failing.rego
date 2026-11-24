package sox.application_controls_test

import rego.v1

iv_true := {
	"data_type_validation": {"enforced": true},
	"format_validation": {"comprehensive": true},
	"range_validation": {"implemented": true},
	"business_rule_validation": {"active": true},
	"cross_field_validation": {"configured": true},
}

test_failing_controls_do_not_make_compliant_undefined if {
	data.sox.application_controls.application_controls_compliant == false
}

test_score_defined_when_every_control_fails if {
	s := data.sox.application_controls.application_controls_score
	s == 0
}

test_risk_level_defined_when_controls_fail if {
	data.sox.application_controls.application_controls_risk_level == "CRITICAL"
}

# Each family now has five checks: the area attestation plus its four detailed checks (the score and the
# findings read the same list).
test_findings_populated_for_failing_controls if {
	f := data.sox.application_controls.get_input_control_findings
	count(f) == 5
}

test_partial_pass_scores_partially if {
	s := data.sox.application_controls.input_controls_score with data.sox.input_validation as iv_true
	s == 0.2
	f := data.sox.application_controls.get_input_control_findings with data.sox.input_validation as iv_true
	count(f) == 4
	not "Input validation controls need comprehensive implementation" in f
}

test_effectiveness_report_fully_populated_on_failure if {
	r := data.sox.application_controls.application_controls_effectiveness
	r.overall_score == 0
	count(r.control_categories) == 7
	count(r.control_categories.input_controls.key_findings) == 5
	r.control_categories.input_controls.effectiveness == "INEFFECTIVE"
}

# ── Audit 2026-11-23: score, findings and counts come from one set of checks ─

all_true(prefix_free) := {area: {control: {field: true |
	some field in fields
} |
	some control, fields in controls
} |
	some area, controls in prefix_free
}

detail := {
	"input_validation": {
		"data_type_validation": ["enforced"], "format_validation": ["comprehensive"],
		"range_validation": ["implemented"], "business_rule_validation": ["active"],
		"cross_field_validation": ["configured"],
	},
	"data_entry": {
		"mandatory_field_validation": ["enforced"], "duplicate_detection": ["automated"],
		"real_time_validation": ["enabled"], "error_highlighting": ["implemented"],
		"confirmation_screens": ["required"],
	},
	"authorization": {
		"transaction_authorization": ["required"], "authorization_limits": ["enforced"],
		"maker_checker": ["implemented"], "authorization_matrix": ["current"],
		"override_controls": ["restricted"],
	},
	"input_completeness": {
		"batch_totals": ["verified"], "record_counts": ["validated"],
		"hash_totals": ["checked"], "missing_data": ["identified"],
	},
}

detail_true := all_true(detail)

test_empty_data_counts_add_up if {
	c := data.sox.application_controls.control_counts
	c.total_controls == 35
	c.failed_controls == 35
	c.passed_controls == 0
}

# Before: the four detailed input checks true and the area flag absent scored 100% for the family with no
# finding, while the verdict failed. The area attestation is now one of the scored checks.
test_missing_area_attestation_is_scored_and_reported if {
	s := data.sox.application_controls.input_controls_score with data.sox.input_validation as detail_true.input_validation
		with data.sox.data_entry as detail_true.data_entry
		with data.sox.authorization as detail_true.authorization
		with data.sox.input_completeness as detail_true.input_completeness
	s == 0.8
	f := data.sox.application_controls.get_input_control_findings with data.sox.input_validation as detail_true.input_validation
		with data.sox.data_entry as detail_true.data_entry
		with data.sox.authorization as detail_true.authorization
		with data.sox.input_completeness as detail_true.input_completeness
	f == ["Input controls are not attested as in place (sox.application_controls.input_validation.comprehensive)"]
	c := data.sox.application_controls.control_counts with data.sox.input_validation as detail_true.input_validation
		with data.sox.data_entry as detail_true.data_entry
		with data.sox.authorization as detail_true.authorization
		with data.sox.input_completeness as detail_true.input_completeness
	c.passed_controls == 4
	c.failed_controls == 31
	c.passed_controls + c.failed_controls == c.total_controls
}

# Only the boolean true is evidence.
test_string_evidence_does_not_pass if {
	stringy := object.union(iv_true, {"data_type_validation": {"enforced": "yes"}})
	not data.sox.application_controls.input_validation_comprehensive with data.sox.input_validation as stringy
	data.sox.application_controls.input_validation_comprehensive with data.sox.input_validation as iv_true
}

# The financial-application family is scored, so it gates the verdict as well.
test_financial_application_family_gates_verdict if {
	not data.sox.application_controls.application_controls_compliant with data.sox.application_controls.input_controls_effective as true
		with data.sox.application_controls.processing_controls_accurate as true
		with data.sox.application_controls.output_controls_complete as true
		with data.sox.application_controls.data_integrity_maintained as true
		with data.sox.application_controls.error_handling_robust as true
		with data.sox.application_controls.transaction_logging_complete as true
		with data.sox.application_controls.financial_application_controls_effective as false
	data.sox.application_controls.application_controls_compliant with data.sox.application_controls.input_controls_effective as true
		with data.sox.application_controls.processing_controls_accurate as true
		with data.sox.application_controls.output_controls_complete as true
		with data.sox.application_controls.data_integrity_maintained as true
		with data.sox.application_controls.error_handling_robust as true
		with data.sox.application_controls.transaction_logging_complete as true
		with data.sox.application_controls.financial_application_controls_effective as true
}
