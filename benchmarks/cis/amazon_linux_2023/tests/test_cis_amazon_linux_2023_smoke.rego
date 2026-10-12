package cis.amazon_linux_2023_test

import rego.v1

# Generated smoke test for benchmarks/cis/amazon_linux_2023/cis_amazon_linux_2023.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_amazon_linux_2023_loads_on_empty_input if {
	m := data.cis.amazon_linux_2023 with input as {}
	is_object(m)
}

test_cis_amazon_linux_2023_violations_on_empty_input if {
	v := data.cis.amazon_linux_2023.violations with input as {}
	count(v) > 0
}
