package cis_rhel9.filesystem_test

import rego.v1

# Generated smoke test for benchmarks/cis/rhel_9/filesystem_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_filesystem_validation_loads_on_empty_input if {
	m := data.cis_rhel9.filesystem with input as {}
	is_object(m)
}

