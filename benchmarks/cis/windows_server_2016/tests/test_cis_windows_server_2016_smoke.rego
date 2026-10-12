package cis_windows_server_2016_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2016/cis_windows_server_2016.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_server_2016_loads_on_empty_input if {
	m := data.cis_windows_server_2016 with input as {}
	is_object(m)
}

test_cis_windows_server_2016_violations_on_empty_input if {
	v := data.cis_windows_server_2016.violations with input as {}
	count(v) > 0
}
