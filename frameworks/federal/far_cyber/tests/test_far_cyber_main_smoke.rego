package far_cyber.main_test

import rego.v1

# Generated smoke test for frameworks/federal/far_cyber/far_cyber_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_far_cyber_main_loads_on_empty_input if {
	m := data.far_cyber.main with input as {}
	is_object(m)
}

test_far_cyber_main_report_wellformed_on_empty_input if {
	report := data.far_cyber.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_far_cyber_main_fail_closed_on_empty_input if {
	report := data.far_cyber.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_far_cyber_main_violations_on_empty_input if {
	v := data.far_cyber.main.violations with input as {}
	count(v) > 0
}
