package cis_m365_v7.purview_test

import rego.v1

# Generated smoke test for benchmarks/cis/saas/m365_v7/purview_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_purview_validation_loads_on_empty_input if {
	m := data.cis_m365_v7.purview with input as {}
	is_object(m)
}

test_purview_validation_report_wellformed_on_empty_input if {
	report := data.cis_m365_v7.purview.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_purview_validation_fail_closed_on_empty_input if {
	report := data.cis_m365_v7.purview.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
