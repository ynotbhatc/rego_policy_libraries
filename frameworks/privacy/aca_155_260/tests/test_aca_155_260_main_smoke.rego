package aca_155_260.main_test

import rego.v1

# Generated smoke test for frameworks/privacy/aca_155_260/aca_155_260_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_aca_155_260_main_loads_on_empty_input if {
	m := data.aca_155_260.main with input as {}
	is_object(m)
}

test_aca_155_260_main_report_wellformed_on_empty_input if {
	report := data.aca_155_260.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_aca_155_260_main_fail_closed_on_empty_input if {
	report := data.aca_155_260.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_aca_155_260_main_violations_on_empty_input if {
	v := data.aca_155_260.main.violations with input as {}
	count(v) > 0
}
