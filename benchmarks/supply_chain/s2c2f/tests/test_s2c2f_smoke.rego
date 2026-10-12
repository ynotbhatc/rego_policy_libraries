package supply_chain.s2c2f_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/s2c2f/s2c2f.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_s2c2f_loads_on_empty_input if {
	m := data.supply_chain.s2c2f with input as {}
	is_object(m)
}

test_s2c2f_report_wellformed_on_empty_input if {
	report := data.supply_chain.s2c2f.report with input as {}
	is_object(report)
	count(report) > 0
}

test_s2c2f_fail_closed_on_empty_input if {
	report := data.supply_chain.s2c2f.report with input as {}
	not object.get(report, "compliant", false) == true
}
