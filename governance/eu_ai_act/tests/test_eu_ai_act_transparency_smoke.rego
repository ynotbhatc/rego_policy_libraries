package eu_ai_act.transparency_test

import rego.v1

# Generated smoke test for governance/eu_ai_act/eu_ai_act_transparency.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_eu_ai_act_transparency_loads_on_empty_input if {
	m := data.eu_ai_act.transparency with input as {}
	is_object(m)
}

test_eu_ai_act_transparency_report_wellformed_on_empty_input if {
	report := data.eu_ai_act.transparency.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

