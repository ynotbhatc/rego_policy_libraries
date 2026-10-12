package cis.apache_2_4_test

import rego.v1

# Generated smoke test for benchmarks/cis/apache/cis_apache_2_4.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_apache_2_4_loads_on_empty_input if {
	m := data.cis.apache_2_4 with input as {}
	is_object(m)
}

test_cis_apache_2_4_report_wellformed_on_empty_input if {
	report := data.cis.apache_2_4.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_apache_2_4_fail_closed_on_empty_input if {
	report := data.cis.apache_2_4.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_apache_2_4_violations_on_empty_input if {
	v := data.cis.apache_2_4.violations with input as {}
	count(v) > 0
}
