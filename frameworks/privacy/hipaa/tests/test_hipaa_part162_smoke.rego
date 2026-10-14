package hipaa.part162_test

import rego.v1

# Generated smoke test for frameworks/privacy/hipaa/hipaa_part162.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_part162_loads_on_empty_input if {
	m := data.hipaa.part162 with input as {}
	is_object(m)
}

test_hipaa_part162_report_wellformed_on_empty_input if {
	report := data.hipaa.part162.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_part162_fail_closed_on_empty_input if {
	report := data.hipaa.part162.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_hipaa_part162_violations_on_empty_input if {
	v := data.hipaa.part162.violations with input as {}
	count(v) > 0
}
