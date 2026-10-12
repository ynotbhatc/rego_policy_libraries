package cis_windows_server_2022.account_policies_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2022_modular/account_policies_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_account_policies_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2022.account_policies with input as {}
	is_object(m)
}

test_account_policies_validation_report_wellformed_on_empty_input if {
	report := data.cis_windows_server_2022.account_policies.report with input as {}
	is_object(report)
	count(report) > 0
}

test_account_policies_validation_fail_closed_on_empty_input if {
	report := data.cis_windows_server_2022.account_policies.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_account_policies_validation_violations_on_empty_input if {
	v := data.cis_windows_server_2022.account_policies.violations with input as {}
	count(v) > 0
}
