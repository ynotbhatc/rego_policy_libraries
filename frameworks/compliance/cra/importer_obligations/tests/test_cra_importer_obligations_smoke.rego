package cra.importer_obligations_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/importer_obligations/cra_importer_obligations.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_importer_obligations_loads_on_empty_input if {
	m := data.cra.importer_obligations with input as {}
	is_object(m)
}

test_cra_importer_obligations_report_wellformed_on_empty_input if {
	report := data.cra.importer_obligations.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cra_importer_obligations_fail_closed_on_empty_input if {
	report := data.cra.importer_obligations.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}
