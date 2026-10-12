package nerc_cip.cip_013_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nerc_cip/cip_013_supply_chain.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cip_013_supply_chain_loads_on_empty_input if {
	m := data.nerc_cip.cip_013 with input as {}
	is_object(m)
}

test_cip_013_supply_chain_report_wellformed_on_empty_input if {
	report := data.nerc_cip.cip_013.report with input as {}
	is_object(report)
	count(report) > 0
}

test_cip_013_supply_chain_fail_closed_on_empty_input if {
	report := data.nerc_cip.cip_013.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_cip_013_supply_chain_violations_on_empty_input if {
	v := data.nerc_cip.cip_013.violations with input as {}
	count(v) > 0
}
