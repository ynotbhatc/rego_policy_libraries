package stig.windows_server_2022.main_test

import rego.v1

# Generated smoke test for benchmarks/stig/windows_server_2022/stig_windows_server_2022_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_windows_server_2022_main_loads_on_empty_input if {
	m := data.stig.windows_server_2022.main with input as {}
	is_object(m)
}

test_stig_windows_server_2022_main_report_wellformed_on_empty_input if {
	report := data.stig.windows_server_2022.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_stig_windows_server_2022_main_fail_closed_on_empty_input if {
	report := data.stig.windows_server_2022.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_stig_windows_server_2022_main_violations_on_empty_input if {
	v := data.stig.windows_server_2022.main.violations with input as {}
	count(v) > 0
}
