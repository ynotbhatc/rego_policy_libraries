package ncsc_caf.b4_system_security_test

import rego.v1

# Generated smoke test for frameworks/compliance/ncsc_caf/caf_b4_system_security.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_caf_b4_system_security_loads_on_empty_input if {
	m := data.ncsc_caf.b4_system_security with input as {}
	is_object(m)
}

test_caf_b4_system_security_report_wellformed_on_empty_input if {
	report := data.ncsc_caf.b4_system_security.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_caf_b4_system_security_fail_closed_on_empty_input if {
	report := data.ncsc_caf.b4_system_security.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
