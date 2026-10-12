package cis_amazon_linux_2023_test

import rego.v1

# Generated smoke test for benchmarks/cis/amazon_linux_2023/cis_al20239_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_al20239_complete_loads_on_empty_input if {
	m := data.cis_amazon_linux_2023 with input as {}
	is_object(m)
}
