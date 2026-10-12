package cis.ubuntu.initial_setup_test

import rego.v1

# Generated smoke test for benchmarks/cis/os/linux/ubuntu/01_initial_setup/filesystem.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_filesystem_loads_on_empty_input if {
	m := data.cis.ubuntu.initial_setup with input as {}
	is_object(m)
}
