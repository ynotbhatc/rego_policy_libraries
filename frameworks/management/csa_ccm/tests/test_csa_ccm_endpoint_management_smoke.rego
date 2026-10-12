package csa_ccm.endpoint_management_test

import rego.v1

# Generated smoke test for frameworks/management/csa_ccm/csa_ccm_endpoint_management.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_csa_ccm_endpoint_management_loads_on_empty_input if {
	m := data.csa_ccm.endpoint_management with input as {}
	is_object(m)
}

test_csa_ccm_endpoint_management_report_wellformed_on_empty_input if {
	report := data.csa_ccm.endpoint_management.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_csa_ccm_endpoint_management_fail_closed_on_empty_input if {
	report := data.csa_ccm.endpoint_management.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_csa_ccm_endpoint_management_violations_on_empty_input if {
	v := data.csa_ccm.endpoint_management.violations with input as {}
	count(v) > 0
}
