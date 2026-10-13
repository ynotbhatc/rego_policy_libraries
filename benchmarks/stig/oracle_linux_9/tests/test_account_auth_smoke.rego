package stig.oracle_linux_9.account_auth_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_linux_9/account_auth.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_account_auth_loads_on_empty_input if {
	m := data.stig.oracle_linux_9.account_auth with input as {}
	is_object(m)
}

test_account_auth_report_wellformed_on_empty_input if {
	report := data.stig.oracle_linux_9.account_auth.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_account_auth_violations_on_empty_input if {
	v := data.stig.oracle_linux_9.account_auth.violations with input as {}
	count(v) > 0
}
