package sox.itgc_test

import rego.v1

# Generated smoke test for frameworks/financial/sox/itgc/it_general_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_it_general_controls_loads_on_empty_input if {
	m := data.sox.itgc with input as {}
	is_object(m)
}
