package stig.rhel_10.services_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_10/services.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_services_loads_on_empty_input if {
	m := data.stig.rhel_10.services with input as {}
	is_object(m)
}

test_services_report_wellformed_on_empty_input if {
	report := data.stig.rhel_10.services.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_services_fail_closed_on_empty_input if {
	report := data.stig.rhel_10.services.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_services_violations_on_empty_input if {
	v := data.stig.rhel_10.services.violations with input as {}
	count(v) > 0
}
