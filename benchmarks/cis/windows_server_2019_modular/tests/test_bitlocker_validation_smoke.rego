package cis_windows_server_2019.bitlocker_test

import rego.v1

# Generated smoke test for benchmarks/cis/windows_server_2019_modular/bitlocker_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_bitlocker_validation_loads_on_empty_input if {
	m := data.cis_windows_server_2019.bitlocker with input as {}
	is_object(m)
}

test_bitlocker_validation_violations_on_empty_input if {
	v := data.cis_windows_server_2019.bitlocker.violations with input as {}
	count(v) > 0
}
