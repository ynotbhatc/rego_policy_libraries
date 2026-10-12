package nist_ssdf.po_test

import rego.v1

# Generated smoke test for frameworks/federal/nist_ssdf/po_prepare_organization.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_po_prepare_organization_loads_on_empty_input if {
	m := data.nist_ssdf.po with input as {}
	is_object(m)
}

test_po_prepare_organization_report_wellformed_on_empty_input if {
	report := data.nist_ssdf.po.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_po_prepare_organization_fail_closed_on_empty_input if {
	report := data.nist_ssdf.po.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_po_prepare_organization_violations_on_empty_input if {
	v := data.nist_ssdf.po.violations with input as {}
	count(v) > 0
}
