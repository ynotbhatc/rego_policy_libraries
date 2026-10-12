package cis_gcp.main_test

import rego.v1

# Generated smoke test for benchmarks/cis/cloud/gcp/cis_gcp_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_gcp_main_loads_on_empty_input if {
	m := data.cis_gcp.main with input as {}
	is_object(m)
}

test_cis_gcp_main_report_wellformed_on_empty_input if {
	report := data.cis_gcp.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_gcp_main_fail_closed_on_empty_input if {
	report := data.cis_gcp.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cis_gcp_main_violations_on_empty_input if {
	v := data.cis_gcp.main.violations with input as {}
	count(v) > 0
}
