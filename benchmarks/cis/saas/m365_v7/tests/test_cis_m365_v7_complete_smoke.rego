package cis_m365_v7.main_test

import rego.v1

# Generated smoke test for benchmarks/cis/saas/m365_v7/cis_m365_v7_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_m365_v7_complete_loads_on_empty_input if {
	m := data.cis_m365_v7.main with input as {}
	is_object(m)
}

test_cis_m365_v7_complete_report_wellformed_on_empty_input if {
	report := data.cis_m365_v7.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cis_m365_v7_complete_fail_closed_on_empty_input if {
	report := data.cis_m365_v7.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
