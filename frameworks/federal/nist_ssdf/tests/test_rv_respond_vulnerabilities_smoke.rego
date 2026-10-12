package nist_ssdf.rv_test

import rego.v1

# Generated smoke test for frameworks/federal/nist_ssdf/rv_respond_vulnerabilities.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_rv_respond_vulnerabilities_loads_on_empty_input if {
	m := data.nist_ssdf.rv with input as {}
	is_object(m)
}

test_rv_respond_vulnerabilities_report_wellformed_on_empty_input if {
	report := data.nist_ssdf.rv.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_rv_respond_vulnerabilities_fail_closed_on_empty_input if {
	report := data.nist_ssdf.rv.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_rv_respond_vulnerabilities_violations_on_empty_input if {
	v := data.nist_ssdf.rv.violations with input as {}
	count(v) > 0
}
