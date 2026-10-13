package supply_chain.coverage_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/coverage/coverage.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_coverage_loads_on_empty_input if {
	m := data.supply_chain.coverage with input as {}
	is_object(m)
}

test_coverage_report_wellformed_on_empty_input if {
	report := data.supply_chain.coverage.report with input as {}
	is_object(report)
	count(report) > 0
}

test_coverage_fail_closed_on_empty_input if {
	report := data.supply_chain.coverage.report with input as {}
	not object.get(report, "compliant", false) == true
}
