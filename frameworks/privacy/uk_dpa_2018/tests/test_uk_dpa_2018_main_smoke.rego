package uk_dpa_2018.main_test

import rego.v1

# Generated smoke test for frameworks/privacy/uk_dpa_2018/uk_dpa_2018_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_uk_dpa_2018_main_loads_on_empty_input if {
	m := data.uk_dpa_2018.main with input as {}
	is_object(m)
}

test_uk_dpa_2018_main_report_wellformed_on_empty_input if {
	report := data.uk_dpa_2018.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_uk_dpa_2018_main_fail_closed_on_empty_input if {
	report := data.uk_dpa_2018.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_uk_dpa_2018_main_violations_on_empty_input if {
	v := data.uk_dpa_2018.main.violations with input as {}
	count(v) > 0
}
