package nist.sp800_53.pii_processing_transparency_test

import rego.v1

# Smoke tests for pii_processing_transparency/pt_controls.rego: the module loads, the report is well formed, and empty input
# is not compliant (fail closed).

test_pt_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.pii_processing_transparency with input as {}
	is_object(m)
}

test_pt_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.pii_processing_transparency.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_pt_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.pii_processing_transparency.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
