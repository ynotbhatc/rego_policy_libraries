package cis.postgresql_14_test

import rego.v1

# Generated smoke test for benchmarks/cis/postgresql/cis_postgresql_14.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_postgresql_14_loads_on_empty_input if {
	m := data.cis.postgresql_14 with input as {}
	is_object(m)
}

test_cis_postgresql_14_report_wellformed_on_empty_input if {
	report := data.cis.postgresql_14.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_postgresql_14_fail_closed_on_empty_input if {
	report := data.cis.postgresql_14.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_postgresql_14_violations_on_empty_input if {
	v := data.cis.postgresql_14.violations with input as {}
	count(v) > 0
}
