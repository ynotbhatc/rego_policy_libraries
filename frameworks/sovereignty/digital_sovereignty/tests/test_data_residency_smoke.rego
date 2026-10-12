package digital_sovereignty.data_residency_test

import rego.v1

# Generated smoke test for frameworks/sovereignty/digital_sovereignty/data_residency.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_data_residency_loads_on_empty_input if {
	m := data.digital_sovereignty.data_residency with input as {}
	is_object(m)
}

test_data_residency_report_wellformed_on_empty_input if {
	report := data.digital_sovereignty.data_residency.report with input as {}
	is_object(report)
	count(report) > 0
}

test_data_residency_fail_closed_on_empty_input if {
	report := data.digital_sovereignty.data_residency.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_data_residency_violations_on_empty_input if {
	v := data.digital_sovereignty.data_residency.violations with input as {}
	count(v) > 0
}
