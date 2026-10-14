package nrc_73_54.main_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nrc_73_54/nrc_73_54_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nrc_73_54_main_loads_on_empty_input if {
	m := data.nrc_73_54.main with input as {}
	is_object(m)
}

test_nrc_73_54_main_report_wellformed_on_empty_input if {
	report := data.nrc_73_54.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nrc_73_54_main_fail_closed_on_empty_input if {
	report := data.nrc_73_54.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_nrc_73_54_main_violations_on_empty_input if {
	v := data.nrc_73_54.main.violations with input as {}
	count(v) > 0
}
