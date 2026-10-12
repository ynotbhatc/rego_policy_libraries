package csa_ccm.interoperability_test

import rego.v1

# Generated smoke test for frameworks/management/csa_ccm/csa_ccm_interoperability.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_csa_ccm_interoperability_loads_on_empty_input if {
	m := data.csa_ccm.interoperability with input as {}
	is_object(m)
}

test_csa_ccm_interoperability_report_wellformed_on_empty_input if {
	report := data.csa_ccm.interoperability.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_csa_ccm_interoperability_fail_closed_on_empty_input if {
	report := data.csa_ccm.interoperability.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_csa_ccm_interoperability_violations_on_empty_input if {
	v := data.csa_ccm.interoperability.violations with input as {}
	count(v) > 0
}
