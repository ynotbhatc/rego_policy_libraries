package stig.oracle_linux_9.network_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_linux_9/network.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_network_loads_on_empty_input if {
	m := data.stig.oracle_linux_9.network with input as {}
	is_object(m)
}

test_network_report_wellformed_on_empty_input if {
	report := data.stig.oracle_linux_9.network.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_network_violations_on_empty_input if {
	v := data.stig.oracle_linux_9.network.violations with input as {}
	count(v) > 0
}
