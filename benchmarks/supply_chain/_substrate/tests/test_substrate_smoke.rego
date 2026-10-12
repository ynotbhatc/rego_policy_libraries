package supply_chain.substrate_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/_substrate/substrate.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_substrate_loads_on_empty_input if {
	m := data.supply_chain.substrate with input as {}
	is_object(m)
}
