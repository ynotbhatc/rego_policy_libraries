package cis_amazon_linux_2023.sudo_test

import rego.v1

# Generated smoke test for benchmarks/cis/amazon_linux_2023/sudo_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_sudo_validation_loads_on_empty_input if {
	m := data.cis_amazon_linux_2023.sudo with input as {}
	is_object(m)
}

test_sudo_validation_violations_on_empty_input if {
	v := data.cis_amazon_linux_2023.sudo.violations with input as {}
	count(v) > 0
}
