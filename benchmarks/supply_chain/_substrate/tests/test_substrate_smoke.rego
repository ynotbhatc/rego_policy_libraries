package supply_chain.substrate_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/_substrate/substrate.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_substrate_loads_on_empty_input if {
	m := data.supply_chain.substrate with input as {}
	is_object(m)
}

# #300 type traps: a non-number must not pass source_control_ok.
test_source_control_ok_number_type_traps if {
	data.supply_chain.substrate.source_control_ok with input as {"source": {"branch_protection": true, "code_owner_review": true, "required_reviews": 1}}
	not data.supply_chain.substrate.source_control_ok with input as {"source": {"branch_protection": true, "code_owner_review": true, "required_reviews": "1"}}
	not data.supply_chain.substrate.source_control_ok with input as {"source": {"branch_protection": true, "code_owner_review": true, "required_reviews": null}}
	not data.supply_chain.substrate.source_control_ok with input as {"source": {"branch_protection": true, "code_owner_review": true, "required_reviews": "not-a-number"}}
}
