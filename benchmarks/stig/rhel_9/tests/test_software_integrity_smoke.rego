package stig.rhel_9.software_integrity_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_9/software_integrity.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_software_integrity_loads_on_empty_input if {
	m := data.stig.rhel_9.software_integrity with input as {}
	is_object(m)
}

test_software_integrity_report_wellformed_on_empty_input if {
	report := data.stig.rhel_9.software_integrity.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_software_integrity_fail_closed_on_empty_input if {
	report := data.stig.rhel_9.software_integrity.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_software_integrity_violations_on_empty_input if {
	v := data.stig.rhel_9.software_integrity.violations with input as {}
	count(v) > 0
}
