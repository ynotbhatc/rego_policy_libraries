package finops.tagging_test

import rego.v1

# Generated smoke test for governance/finops/finops_tagging.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_finops_tagging_loads_on_empty_input if {
	m := data.finops.tagging with input as {}
	is_object(m)
}

test_finops_tagging_report_wellformed_on_empty_input if {
	report := data.finops.tagging.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

