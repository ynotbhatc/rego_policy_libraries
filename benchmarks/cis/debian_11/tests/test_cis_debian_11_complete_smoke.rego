package cis_debian_11_test

import rego.v1

# Generated smoke test for benchmarks/cis/debian_11/cis_debian_11_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_debian_11_complete_loads_on_empty_input if {
	m := data.cis_debian_11 with input as {}
	is_object(m)
}

test_cis_debian_11_complete_violations_on_empty_input if {
	v := data.cis_debian_11.violations with input as {}
	count(v) > 0
}
