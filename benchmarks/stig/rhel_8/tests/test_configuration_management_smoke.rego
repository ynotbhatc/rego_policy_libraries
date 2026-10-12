package stig.rhel_8.configuration_management_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_8/configuration_management.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_configuration_management_loads_on_empty_input if {
	m := data.stig.rhel_8.configuration_management with input as {}
	is_object(m)
}

test_configuration_management_report_wellformed_on_empty_input if {
	report := data.stig.rhel_8.configuration_management.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_configuration_management_fail_closed_on_empty_input if {
	report := data.stig.rhel_8.configuration_management.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_configuration_management_violations_on_empty_input if {
	v := data.stig.rhel_8.configuration_management.violations with input as {}
	count(v) > 0
}
