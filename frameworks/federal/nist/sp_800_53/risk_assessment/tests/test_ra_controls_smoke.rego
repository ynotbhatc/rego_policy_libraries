package nist.sp800_53.risk_assessment_test

import rego.v1

# Smoke tests for risk_assessment/ra_controls.rego: the module loads, the report is well formed, and empty input
# is not compliant (fail closed).

test_ra_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.risk_assessment with input as {}
	is_object(m)
}

test_ra_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.risk_assessment.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ra_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.risk_assessment.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
