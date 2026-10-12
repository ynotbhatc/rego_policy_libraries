package hipaa.main_test

import rego.v1

# Generated smoke test for frameworks/privacy/hipaa/hipaa_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_main_loads_on_empty_input if {
	m := data.hipaa.main with input as {}
	is_object(m)
}

test_hipaa_main_report_wellformed_on_empty_input if {
	report := data.hipaa.main.report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_main_fail_closed_on_empty_input if {
	report := data.hipaa.main.report with input as {}
	not object.get(report, "compliant", false) == true
}
