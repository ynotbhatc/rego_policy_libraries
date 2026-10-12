package supply_chain.ssdf_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/ssdf/ssdf.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ssdf_loads_on_empty_input if {
	m := data.supply_chain.ssdf with input as {}
	is_object(m)
}

test_ssdf_report_wellformed_on_empty_input if {
	report := data.supply_chain.ssdf.report with input as {}
	is_object(report)
	count(report) > 0
}

test_ssdf_fail_closed_on_empty_input if {
	report := data.supply_chain.ssdf.report with input as {}
	not object.get(report, "compliant", false) == true
}
