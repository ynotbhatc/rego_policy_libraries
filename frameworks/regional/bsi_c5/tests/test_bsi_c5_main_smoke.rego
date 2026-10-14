package bsi_c5.main_test

import rego.v1

# Generated smoke test for frameworks/regional/bsi_c5/bsi_c5_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_bsi_c5_main_loads_on_empty_input if {
	m := data.bsi_c5.main with input as {}
	is_object(m)
}

test_bsi_c5_main_report_wellformed_on_empty_input if {
	report := data.bsi_c5.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_bsi_c5_main_fail_closed_on_empty_input if {
	report := data.bsi_c5.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_bsi_c5_main_violations_on_empty_input if {
	v := data.bsi_c5.main.violations with input as {}
	count(v) > 0
}
