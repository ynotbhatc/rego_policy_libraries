package cis_oracle.user_account_management_test

import rego.v1

# Generated smoke test for benchmarks/cis/databases/oracle_legacy/modules/user_account_management.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_user_account_management_loads_on_empty_input if {
	m := data.cis_oracle.user_account_management with input as {}
	is_object(m)
}

test_user_account_management_report_wellformed_on_empty_input if {
	report := data.cis_oracle.user_account_management.report with input as {}
	is_object(report)
	count(report) > 0
}

