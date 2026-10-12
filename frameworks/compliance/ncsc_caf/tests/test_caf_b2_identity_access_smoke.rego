package ncsc_caf.b2_identity_access_test

import rego.v1

# Generated smoke test for frameworks/compliance/ncsc_caf/caf_b2_identity_access.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_caf_b2_identity_access_loads_on_empty_input if {
	m := data.ncsc_caf.b2_identity_access with input as {}
	is_object(m)
}

test_caf_b2_identity_access_report_wellformed_on_empty_input if {
	report := data.ncsc_caf.b2_identity_access.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_caf_b2_identity_access_fail_closed_on_empty_input if {
	report := data.ncsc_caf.b2_identity_access.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
