package cis.postgresql_18_test

import rego.v1

# Smoke tests in the same form as the other PostgreSQL versions: on empty input the module loads, reports and fails closed.

test_cis_postgresql_18_loads_on_empty_input if {
	m := data.cis.postgresql_18 with input as {}
	is_object(m)
}

test_cis_postgresql_18_report_wellformed_on_empty_input if {
	report := data.cis.postgresql_18.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_postgresql_18_fail_closed_on_empty_input if {
	report := data.cis.postgresql_18.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_postgresql_18_violations_on_empty_input if {
	v := data.cis.postgresql_18.violations with input as {}
	count(v) > 0
	"CIS PostgreSQL 18: FAIL-CLOSED - facts 'input.postgresql' were not supplied; the server was not evaluated" in v
}
