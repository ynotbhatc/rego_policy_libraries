package stig.windows_server_2025.registry_cc_test

import rego.v1

# Generated smoke test for benchmarks/stig/windows_server_2025/registry_cc.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_registry_cc_loads_on_empty_input if {
	m := data.stig.windows_server_2025.registry_cc with input as {}
	is_object(m)
}
