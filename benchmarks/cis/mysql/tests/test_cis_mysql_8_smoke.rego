package cis.mysql_8_test

import rego.v1

# Generated smoke test for benchmarks/cis/mysql/cis_mysql_8.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_mysql_8_loads_on_empty_input if {
	m := data.cis.mysql_8 with input as {}
	is_object(m)
}

test_cis_mysql_8_report_wellformed_on_empty_input if {
	report := data.cis.mysql_8.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_mysql_8_fail_closed_on_empty_input if {
	report := data.cis.mysql_8.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_mysql_8_violations_on_empty_input if {
	v := data.cis.mysql_8.violations with input as {}
	count(v) > 0
}
