package stig.amazon_linux_2023.core_test

import rego.v1

# Generated smoke test for benchmarks/stig/amazon_linux_2023/core.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_core_loads_on_empty_input if {
	m := data.stig.amazon_linux_2023.core with input as {}
	is_object(m)
}
