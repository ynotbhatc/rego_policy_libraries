package nist_ssdf.pw_test

import rego.v1

# Generated smoke test for frameworks/federal/nist_ssdf/pw_produce_secured_software.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_pw_produce_secured_software_loads_on_empty_input if {
	m := data.nist_ssdf.pw with input as {}
	is_object(m)
}

test_pw_produce_secured_software_report_wellformed_on_empty_input if {
	report := data.nist_ssdf.pw.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_pw_produce_secured_software_fail_closed_on_empty_input if {
	report := data.nist_ssdf.pw.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_pw_produce_secured_software_violations_on_empty_input if {
	v := data.nist_ssdf.pw.violations with input as {}
	count(v) > 0
}
