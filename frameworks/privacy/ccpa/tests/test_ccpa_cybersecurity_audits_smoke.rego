package ccpa.cybersecurity_audits_test

import rego.v1

# Generated smoke test for frameworks/privacy/ccpa/ccpa_cybersecurity_audits.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ccpa_cybersecurity_audits_loads_on_empty_input if {
	m := data.ccpa.cybersecurity_audits with input as {}
	is_object(m)
}

test_ccpa_cybersecurity_audits_report_wellformed_on_empty_input if {
	report := data.ccpa.cybersecurity_audits.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ccpa_cybersecurity_audits_fail_closed_on_empty_input if {
	report := data.ccpa.cybersecurity_audits.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_ccpa_cybersecurity_audits_violations_on_empty_input if {
	v := data.ccpa.cybersecurity_audits.violations with input as {}
	count(v) > 0
}
