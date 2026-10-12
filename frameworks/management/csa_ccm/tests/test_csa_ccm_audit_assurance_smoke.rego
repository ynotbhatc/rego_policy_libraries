package csa_ccm.audit_assurance_test

import rego.v1

# Generated smoke test for frameworks/management/csa_ccm/csa_ccm_audit_assurance.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_csa_ccm_audit_assurance_loads_on_empty_input if {
	m := data.csa_ccm.audit_assurance with input as {}
	is_object(m)
}

test_csa_ccm_audit_assurance_report_wellformed_on_empty_input if {
	report := data.csa_ccm.audit_assurance.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_csa_ccm_audit_assurance_fail_closed_on_empty_input if {
	report := data.csa_ccm.audit_assurance.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_csa_ccm_audit_assurance_violations_on_empty_input if {
	v := data.csa_ccm.audit_assurance.violations with input as {}
	count(v) > 0
}
