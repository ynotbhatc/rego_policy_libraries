package fisma.continuous_monitoring_fixes_test

import rego.v1

cm := data.fisma.continuous_monitoring

test_assessment_defined_when_non_compliant if {
	a := cm.continuous_monitoring_assessment with input as {}
	a.continuous_monitoring_compliant == false
	count(a.program_areas) == 6
	a.total_gaps == 6
}

test_score_zero_when_all_fail if cm.continuous_monitoring_score == 0 with input as {}

test_maturity_defined_when_all_fail if cm.continuous_monitoring_maturity_level == "LEVEL_1_INITIAL" with input as {}

test_partial_pass_scored_not_zeroed if {
	s := cm.continuous_monitoring_score with input as {}
		with data.fisma.continuous_monitoring.iscm_program_established as true
		with data.fisma.continuous_monitoring.reporting_requirements_met as true
		with data.fisma.continuous_monitoring.incident_response_integrated as true
	s == 50
}

test_partial_pass_assessment_marks_passing_areas if {
	a := cm.continuous_monitoring_assessment with input as {}
		with data.fisma.continuous_monitoring.iscm_program_established as true
	some area in a.program_areas
	area.area == "ISCM Program"
	area.compliant == true
}
