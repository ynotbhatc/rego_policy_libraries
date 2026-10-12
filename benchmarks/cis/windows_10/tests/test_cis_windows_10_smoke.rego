package cis_windows_10_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_10/cis_windows_10.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_10_loads_on_empty_input if {
	m := data.cis_windows_10 with input as {}
	is_object(m)
}

test_cis_windows_10_violations_on_empty_input if {
	v := data.cis_windows_10.violations with input as {}
	count(v) > 0
}
