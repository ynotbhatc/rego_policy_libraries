package nist.csf.recover_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/cybersecurity_framework_2.0/recover/recover.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_recover_loads_on_empty_input if {
	m := data.nist.csf.recover with input as {}
	is_object(m)
}

test_recover_report_wellformed_on_empty_input if {
	report := data.nist.csf.recover.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_recover_fail_closed_on_empty_input if {
	report := data.nist.csf.recover.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
