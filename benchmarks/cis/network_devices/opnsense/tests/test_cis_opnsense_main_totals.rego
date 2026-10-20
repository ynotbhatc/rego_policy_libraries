package cis_opnsense_test

import rego.v1

# Roll-up totals come from the controls actually evaluated (29 in v1.0.0).
test_main_total_is_evaluated_control_count if {
	r := data.cis_opnsense.main.compliance_report with input as {"x": 1}
	r.total_controls == 29
	r.passed_controls + r.failed_controls == r.total_controls
}

test_main_empty_input_fails_all_evaluated_controls if {
	r := data.cis_opnsense.main.compliance_report with input as {}
	r.failed_controls == 29
	r.passed_controls == 0
}
