package cis_rhel8.file_permissions_test

import rego.v1

# Generated smoke test for benchmarks/cis/rhel_8/file_permissions_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_file_permissions_validation_loads_on_empty_input if {
	m := data.cis_rhel8.file_permissions with input as {}
	is_object(m)
}

test_file_permissions_validation_violations_on_empty_input if {
	v := data.cis_rhel8.file_permissions.violations with input as {}
	count(v) > 0
}
