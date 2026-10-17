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

test_findings_populated_for_failing_controls if {
	f := data.sox.application_controls.get_input_control_findings
	count(f) == 4
}

test_partial_pass_scores_partially if {
	s := data.sox.application_controls.input_controls_score with data.sox.input_validation as iv_true
	s == 0.25
	f := data.sox.application_controls.get_input_control_findings with data.sox.input_validation as iv_true
	count(f) == 3
	not "Input validation controls need comprehensive implementation" in f
}

test_effectiveness_report_fully_populated_on_failure if {
	r := data.sox.application_controls.application_controls_effectiveness
	r.overall_score == 0
	count(r.control_categories) == 7
	count(r.control_categories.input_controls.key_findings) == 4
	r.control_categories.input_controls.effectiveness == "INEFFECTIVE"
}
