package nerc_cip.no_input_test

# OPA queried with no input document at all (not {}): the report is defined and fails exactly as on {}.
# A test without `with input` evaluates with no input document.

import rego.v1

test_report_is_defined_without_an_input_document if {
	r := data.nerc_cip.main.compliance_report
	e := data.nerc_cip.main.compliance_report with input as {}
	r.compliant == false
	r.total_controls == e.total_controls
	r.failed_controls == e.failed_controls
	r.passed_controls == e.passed_controls
}
