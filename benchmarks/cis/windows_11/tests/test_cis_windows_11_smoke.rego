package cis.windows_11_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_11/cis_windows_11.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_11_loads_on_empty_input if {
	m := data.cis.windows_11 with input as {}
	is_object(m)
}

test_cis_windows_11_report_wellformed_on_empty_input if {
	report := data.cis.windows_11.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_windows_11_fail_closed_on_empty_input if {
	report := data.cis.windows_11.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_windows_11_violations_on_empty_input if {
	v := data.cis.windows_11.violations with input as {}
	count(v) > 0
}
