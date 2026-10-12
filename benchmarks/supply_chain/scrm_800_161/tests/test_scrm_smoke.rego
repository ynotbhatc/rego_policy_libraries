package supply_chain.scrm_800_161_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/scrm_800_161/scrm.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_scrm_loads_on_empty_input if {
	m := data.supply_chain.scrm_800_161 with input as {}
	is_object(m)
}

test_scrm_report_wellformed_on_empty_input if {
	report := data.supply_chain.scrm_800_161.report with input as {}
	is_object(report)
	count(report) > 0
}

test_scrm_fail_closed_on_empty_input if {
	report := data.supply_chain.scrm_800_161.report with input as {}
	not object.get(report, "compliant", false) == true
}
