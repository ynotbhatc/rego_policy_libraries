package supply_chain.baseline_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/baseline/baseline.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_baseline_loads_on_empty_input if {
	m := data.supply_chain.baseline with input as {}
	is_object(m)
}

test_baseline_report_wellformed_on_empty_input if {
	report := data.supply_chain.baseline.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_baseline_fail_closed_on_empty_input if {
	report := data.supply_chain.baseline.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_baseline_violations_on_empty_input if {
	v := data.supply_chain.baseline.violations with input as {}
	count(v) > 0
}
