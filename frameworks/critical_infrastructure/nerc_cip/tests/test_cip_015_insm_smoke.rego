package nerc_cip_cip015_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nerc_cip/cip_015_insm.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cip_015_insm_loads_on_empty_input if {
	m := data.nerc_cip_cip015 with input as {}
	is_object(m)
}
