package stig.oracle_linux_9.ssh_config_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_linux_9/ssh_config.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ssh_config_loads_on_empty_input if {
	m := data.stig.oracle_linux_9.ssh_config with input as {}
	is_object(m)
}

test_ssh_config_report_wellformed_on_empty_input if {
	report := data.stig.oracle_linux_9.ssh_config.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ssh_config_fail_closed_on_empty_input if {
	report := data.stig.oracle_linux_9.ssh_config.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_ssh_config_violations_on_empty_input if {
	v := data.stig.oracle_linux_9.ssh_config.violations with input as {}
	count(v) > 0
}
