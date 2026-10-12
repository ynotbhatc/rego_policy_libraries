package cis_rocky_linux_9.network_test

import rego.v1

# Generated smoke test for benchmarks/cis/rocky_linux_9/network_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_network_validation_loads_on_empty_input if {
	m := data.cis_rocky_linux_9.network with input as {}
	is_object(m)
}

