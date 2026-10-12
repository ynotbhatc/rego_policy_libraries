package cis_rocky_linux_8_test

import rego.v1

# Generated smoke test for benchmarks/cis/rocky_linux_8/cis_rocky_linux_8_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_rocky_linux_8_complete_loads_on_empty_input if {
	m := data.cis_rocky_linux_8 with input as {}
	is_object(m)
}
