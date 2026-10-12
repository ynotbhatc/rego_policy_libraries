package nerc.cip.simplified_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/nerc_cip/nerc_cip_simplified.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nerc_cip_simplified_loads_on_empty_input if {
	m := data.nerc.cip.simplified with input as {}
	is_object(m)
}
