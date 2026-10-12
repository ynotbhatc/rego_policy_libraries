package stig.windows_server_2022.registry_other_test

import rego.v1

# Generated smoke test for benchmarks/stig/windows_server_2022/registry_other.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_registry_other_loads_on_empty_input if {
	m := data.stig.windows_server_2022.registry_other with input as {}
	is_object(m)
}
