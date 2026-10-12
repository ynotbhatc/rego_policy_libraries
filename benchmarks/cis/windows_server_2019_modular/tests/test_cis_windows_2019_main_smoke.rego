package cis_windows_server_2019.main_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/cis_windows_2019_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_2019_main_loads_on_empty_input if {
	m := data.cis_windows_server_2019.main with input as {}
	is_object(m)
}

test_cis_windows_2019_main_report_wellformed_on_empty_input if {
	report := data.cis_windows_server_2019.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_windows_2019_main_fail_closed_on_empty_input if {
	report := data.cis_windows_server_2019.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
