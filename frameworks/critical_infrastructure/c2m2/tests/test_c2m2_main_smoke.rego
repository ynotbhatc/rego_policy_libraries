package c2m2.main_test

import rego.v1

# Smoke test for frameworks/critical_infrastructure/c2m2/c2m2_main.rego in the scripts/gen_tests.py format (written with the module, not by the generator). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_c2m2_main_loads_on_empty_input if {
	m := data.c2m2.main with input as {}
	is_object(m)
}

test_c2m2_main_report_wellformed_on_empty_input if {
	report := data.c2m2.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_c2m2_main_fail_closed_on_empty_input if {
	report := data.c2m2.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_c2m2_main_violations_on_empty_input if {
	v := data.c2m2.main.violations with input as {}
	count(v) > 0
}
