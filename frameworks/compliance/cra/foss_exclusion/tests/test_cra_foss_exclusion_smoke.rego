package cra.foss_exclusion_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/foss_exclusion/cra_foss_exclusion.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_foss_exclusion_loads_on_empty_input if {
	m := data.cra.foss_exclusion with input as {}
	is_object(m)
}

test_cra_foss_exclusion_report_wellformed_on_empty_input if {
	report := data.cra.foss_exclusion.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

