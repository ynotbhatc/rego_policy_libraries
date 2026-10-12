package supply_chain.metrics_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/metrics/collapse.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_collapse_loads_on_empty_input if {
	m := data.supply_chain.metrics with input as {}
	is_object(m)
}
