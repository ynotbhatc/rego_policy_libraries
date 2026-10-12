package cis_rhel9.ssh_test

import rego.v1

# Generated smoke test for benchmarks/cis/rhel_9/ssh_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ssh_validation_loads_on_empty_input if {
	m := data.cis_rhel9.ssh with input as {}
	is_object(m)
}

test_ssh_validation_report_wellformed_on_empty_input if {
	report := data.cis_rhel9.ssh.report with input as {}
	is_object(report)
	count(report) > 0
}

