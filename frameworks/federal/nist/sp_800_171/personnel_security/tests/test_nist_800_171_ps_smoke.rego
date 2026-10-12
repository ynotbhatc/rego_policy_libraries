package nist.sp800_171.personnel_security_test

import rego.v1

# Generated smoke test for frameworks/federal/nist/sp_800_171/personnel_security/nist_800_171_ps.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_800_171_ps_loads_on_empty_input if {
	m := data.nist.sp800_171.personnel_security with input as {}
	is_object(m)
}

test_nist_800_171_ps_report_wellformed_on_empty_input if {
	report := data.nist.sp800_171.personnel_security.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_nist_800_171_ps_fail_closed_on_empty_input if {
	report := data.nist.sp800_171.personnel_security.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_nist_800_171_ps_violations_on_empty_input if {
	v := data.nist.sp800_171.personnel_security.violations with input as {}
	count(v) > 0
}
