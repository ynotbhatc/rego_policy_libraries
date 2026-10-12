package cis_windows_server_2022_legacy_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2022/cis_windows_server_2022.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_server_2022_loads_on_empty_input if {
	m := data.cis_windows_server_2022_legacy with input as {}
	is_object(m)
}

test_cis_windows_server_2022_violations_on_empty_input if {
	v := data.cis_windows_server_2022_legacy.violations with input as {}
	count(v) > 0
}
