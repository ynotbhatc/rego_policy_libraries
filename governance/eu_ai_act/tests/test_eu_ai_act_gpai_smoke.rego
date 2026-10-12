package eu_ai_act.gpai_test

import rego.v1

# Generated smoke test for governance/eu_ai_act/eu_ai_act_gpai.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_eu_ai_act_gpai_loads_on_empty_input if {
	m := data.eu_ai_act.gpai with input as {}
	is_object(m)
}

test_eu_ai_act_gpai_report_wellformed_on_empty_input if {
	report := data.eu_ai_act.gpai.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_eu_ai_act_gpai_fail_closed_on_empty_input if {
	report := data.eu_ai_act.gpai.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_eu_ai_act_gpai_violations_on_empty_input if {
	v := data.eu_ai_act.gpai.violations with input as {}
	count(v) > 0
}
