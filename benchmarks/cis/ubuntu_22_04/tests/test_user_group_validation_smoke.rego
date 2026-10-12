package cis_ubuntu_22_04.user_group_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/user_group_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_user_group_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_22_04.user_group with input as {}
	is_object(m)
}

test_user_group_validation_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_22_04.user_group.report with input as {}
	is_object(report)
	count(report) > 0
}

