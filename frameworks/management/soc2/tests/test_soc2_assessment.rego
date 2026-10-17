package soc2_test

import rego.v1

# Validation fix pass 2026-10-17: soc2_assessment (consumer endpoint) had no tests.
# NOTE: `compliant` is scoped to the Security criterion by the module docstring; whether it
# should also require the other TSC / overall_soc2_compliant is an open decision, not asserted here.

test_assessment_fully_populated_and_not_compliant_on_empty_input if {
	r := data.soc2.soc2_assessment with input as {}
	r.compliant == false
	r.score == 0
	r.criteria_evaluated == 5
	r.criteria_passing == 0
	r.tsc_results == {
		"security": false,
		"availability": false,
		"processing_integrity": false,
		"confidentiality": false,
		"privacy": false,
	}
}

test_assessment_score_counts_passing_criteria if {
	passing := data.soc2.soc2_tsc_passing with input as {}
	passing == 0
}
