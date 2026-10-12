package cis_oracle.installation_patches_test

import rego.v1

# Generated smoke test for benchmarks/cis/databases/oracle_legacy/modules/installation_patches.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_installation_patches_loads_on_empty_input if {
	m := data.cis_oracle.installation_patches with input as {}
	is_object(m)
}

test_installation_patches_violations_on_empty_input if {
	v := data.cis_oracle.installation_patches.violations with input as {}
	count(v) > 0
}
