package ccpa.sensitive_data_test

import rego.v1

# Generated smoke test for frameworks/privacy/ccpa/ccpa_sensitive_data.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ccpa_sensitive_data_loads_on_empty_input if {
	m := data.ccpa.sensitive_data with input as {}
	is_object(m)
}

test_ccpa_sensitive_data_report_wellformed_on_empty_input if {
	report := data.ccpa.sensitive_data.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ccpa_sensitive_data_fail_closed_on_empty_input if {
	report := data.ccpa.sensitive_data.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_ccpa_sensitive_data_violations_on_empty_input if {
	v := data.ccpa.sensitive_data.violations with input as {}
	count(v) > 0
}
