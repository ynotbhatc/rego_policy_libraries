package hipaa.privacy_rule_test

import rego.v1

# Generated smoke test for frameworks/privacy/hipaa/hipaa_privacy_rule.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_hipaa_privacy_rule_loads_on_empty_input if {
	m := data.hipaa.privacy_rule with input as {}
	is_object(m)
}

test_hipaa_privacy_rule_report_wellformed_on_empty_input if {
	report := data.hipaa.privacy_rule.report with input as {}
	is_object(report)
	count(report) > 0
}

test_hipaa_privacy_rule_fail_closed_on_empty_input if {
	report := data.hipaa.privacy_rule.report with input as {}
	not object.get(report, "compliant", false) == true
}
