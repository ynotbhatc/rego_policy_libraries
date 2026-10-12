package stig.windows_10_test

import rego.v1

# Generated smoke test for benchmarks/stig/windows_10/stig_windows_10_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_windows_10_complete_loads_on_empty_input if {
	m := data.stig.windows_10 with input as {}
	is_object(m)
}
