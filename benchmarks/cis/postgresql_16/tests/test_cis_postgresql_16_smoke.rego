package cis.postgresql_16_test

import rego.v1

# Smoke tests in the same form as the other PostgreSQL versions: on empty input the module loads, reports and fails closed.

test_cis_postgresql_16_loads_on_empty_input if {
	m := data.cis.postgresql_16 with input as {}
	is_object(m)
}

test_cis_postgresql_16_report_wellformed_on_empty_input if {
	report := data.cis.postgresql_16.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_postgresql_16_fail_closed_on_empty_input if {
	report := data.cis.postgresql_16.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_postgresql_16_violations_on_empty_input if {
	v := data.cis.postgresql_16.violations with input as {}
	count(v) > 0
	"CIS PostgreSQL 16: FAIL-CLOSED - facts 'input.postgresql' were not supplied; the server was not evaluated" in v
}
