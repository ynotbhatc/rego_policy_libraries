package maritime_33cfr101f.main_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/maritime_33cfr101f/maritime_33cfr101f_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_maritime_33cfr101f_main_loads_on_empty_input if {
	m := data.maritime_33cfr101f.main with input as {}
	is_object(m)
}

test_maritime_33cfr101f_main_report_wellformed_on_empty_input if {
	report := data.maritime_33cfr101f.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_maritime_33cfr101f_main_fail_closed_on_empty_input if {
	report := data.maritime_33cfr101f.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_maritime_33cfr101f_main_violations_on_empty_input if {
	v := data.maritime_33cfr101f.main.violations with input as {}
	count(v) > 0
}
