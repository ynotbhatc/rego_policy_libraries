package cis_debian_11.auditd_test

import rego.v1

# Generated smoke test for benchmarks/cis/debian_11/auditd_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_auditd_validation_loads_on_empty_input if {
	m := data.cis_debian_11.auditd with input as {}
	is_object(m)
}

test_auditd_validation_report_wellformed_on_empty_input if {
	report := data.cis_debian_11.auditd.report with input as {}
	is_object(report)
	count(report) > 0
}

test_auditd_validation_fail_closed_on_empty_input if {
	report := data.cis_debian_11.auditd.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_auditd_validation_violations_on_empty_input if {
	v := data.cis_debian_11.auditd.violations with input as {}
	count(v) > 0
}
