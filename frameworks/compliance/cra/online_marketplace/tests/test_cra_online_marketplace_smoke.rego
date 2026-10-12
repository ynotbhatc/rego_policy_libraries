package cra.online_marketplace_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/online_marketplace/cra_online_marketplace.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_online_marketplace_loads_on_empty_input if {
	m := data.cra.online_marketplace with input as {}
	is_object(m)
}

test_cra_online_marketplace_report_wellformed_on_empty_input if {
	report := data.cra.online_marketplace.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

