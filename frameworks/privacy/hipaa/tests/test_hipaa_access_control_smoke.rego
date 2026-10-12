package hipaa.access_control_test

import rego.v1

# Generated smoke test for frameworks/privacy/hipaa/hipaa_access_control.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_access_control_loads_on_empty_input if {
	m := data.hipaa.access_control with input as {}
	is_object(m)
}

test_hipaa_access_control_report_wellformed_on_empty_input if {
	report := data.hipaa.access_control.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_access_control_fail_closed_on_empty_input if {
	report := data.hipaa.access_control.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_hipaa_access_control_violations_on_empty_input if {
	v := data.hipaa.access_control.violations with input as {}
	count(v) > 0
}
