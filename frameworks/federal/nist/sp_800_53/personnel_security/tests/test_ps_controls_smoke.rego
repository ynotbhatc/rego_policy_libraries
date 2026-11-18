package nist.sp800_53.personnel_security_test

import rego.v1

# Smoke test for frameworks/federal/nist/sp_800_53/personnel_security/ps_controls.rego, written in the shape scripts/gen_tests.py generates: each rule states one thing the
# module does on empty input (loads, returns a well-formed report, fails closed).

test_ps_controls_loads_on_empty_input if {
	m := data.nist.sp800_53.personnel_security with input as {}
	is_object(m)
}

test_ps_controls_report_wellformed_on_empty_input if {
	report := data.nist.sp800_53.personnel_security.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_ps_controls_fail_closed_on_empty_input if {
	report := data.nist.sp800_53.personnel_security.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
