package dfars_7012.main_test

import rego.v1

# Smoke test in the shape scripts/gen_tests.py writes (docs/TEST_GENERATION.md).

test_dfars_7012_main_loads_on_empty_input if {
	m := data.dfars_7012.main with input as {}
	is_object(m)
}

test_dfars_7012_main_report_wellformed_on_empty_input if {
	report := data.dfars_7012.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_dfars_7012_main_fail_closed_on_empty_input if {
	report := data.dfars_7012.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_dfars_7012_main_violations_on_empty_input if {
	v := data.dfars_7012.main.violations with input as {}
	count(v) > 0
}
