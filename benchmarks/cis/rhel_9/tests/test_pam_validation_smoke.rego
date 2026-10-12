package cis_rhel9.pam_test

import rego.v1

# Generated smoke test for benchmarks/cis/rhel_9/pam_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_pam_validation_loads_on_empty_input if {
	m := data.cis_rhel9.pam with input as {}
	is_object(m)
}

