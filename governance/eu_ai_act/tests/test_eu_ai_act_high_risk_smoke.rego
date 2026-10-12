package eu_ai_act.high_risk_test

import rego.v1

# Generated smoke test for governance/eu_ai_act/eu_ai_act_high_risk.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_eu_ai_act_high_risk_loads_on_empty_input if {
	m := data.eu_ai_act.high_risk with input as {}
	is_object(m)
}

test_eu_ai_act_high_risk_report_wellformed_on_empty_input if {
	report := data.eu_ai_act.high_risk.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_eu_ai_act_high_risk_fail_closed_on_empty_input if {
	report := data.eu_ai_act.high_risk.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_eu_ai_act_high_risk_violations_on_empty_input if {
	v := data.eu_ai_act.high_risk.violations with input as {}
	count(v) > 0
}
