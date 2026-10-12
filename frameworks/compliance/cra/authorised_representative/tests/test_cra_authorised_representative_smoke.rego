package cra.authorised_representative_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/authorised_representative/cra_authorised_representative.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_authorised_representative_loads_on_empty_input if {
	m := data.cra.authorised_representative with input as {}
	is_object(m)
}

test_cra_authorised_representative_report_wellformed_on_empty_input if {
	report := data.cra.authorised_representative.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

