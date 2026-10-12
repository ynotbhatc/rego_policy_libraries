package cis_windows_server_2019_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/cis_windows_server_2019_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_windows_server_2019_complete_loads_on_empty_input if {
	m := data.cis_windows_server_2019 with input as {}
	is_object(m)
}
