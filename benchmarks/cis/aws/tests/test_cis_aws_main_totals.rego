package cis_aws_test

import rego.v1

# Decisions 2026-10-19: roll-up totals come from the controls actually evaluated.
test_main_total_is_evaluated_control_count if {
	r := data.cis_aws.main.compliance_report with input as {"x": 1}
	r.total_controls == 19
	r.passed_controls + r.failed_controls == r.total_controls
}

test_main_empty_input_fails_all_evaluated_controls if {
	r := data.cis_aws.main.compliance_report with input as {}
	r.failed_controls == 19
	r.passed_controls == 0
}
