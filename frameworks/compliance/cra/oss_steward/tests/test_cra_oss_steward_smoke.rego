package cra.oss_steward_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/oss_steward/cra_oss_steward.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_oss_steward_loads_on_empty_input if {
	m := data.cra.oss_steward with input as {}
	is_object(m)
}

test_cra_oss_steward_report_wellformed_on_empty_input if {
	report := data.cra.oss_steward.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

