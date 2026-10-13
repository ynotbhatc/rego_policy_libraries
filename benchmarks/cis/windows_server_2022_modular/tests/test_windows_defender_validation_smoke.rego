package cis_windows_server_2022.windows_defender_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2022_modular/windows_defender_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_windows_defender_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2022.windows_defender with input as {}
	is_object(m)
}

test_windows_defender_validation_report_wellformed_on_empty_input if {
	report := data.cis_windows_server_2022.windows_defender.report with input as {}
	is_object(report)
	count(report) > 0
}

test_windows_defender_validation_fail_closed_on_empty_input if {
	report := data.cis_windows_server_2022.windows_defender.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_windows_defender_validation_violations_on_empty_input if {
	v := data.cis_windows_server_2022.windows_defender.violations with input as {}
	count(v) > 0
}
