package nist.sp800_53.identification_authentication_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_53/identification_authentication/ia_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ia_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.identification_authentication with input as {}
	is_object(m)
}

test_ia_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.identification_authentication.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ia_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.identification_authentication.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
