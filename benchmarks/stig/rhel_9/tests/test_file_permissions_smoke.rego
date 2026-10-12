package stig.rhel_9.file_permissions_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_9/file_permissions.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_file_permissions_loads_on_empty_input if {
	m := data.stig.rhel_9.file_permissions with input as {}
	is_object(m)
}

test_file_permissions_report_wellformed_on_empty_input if {
	report := data.stig.rhel_9.file_permissions.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_file_permissions_violations_on_empty_input if {
	v := data.stig.rhel_9.file_permissions.violations with input as {}
	count(v) > 0
}
