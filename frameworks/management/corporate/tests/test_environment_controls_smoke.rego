package corporate.environment.controls_test

import rego.v1

# Generated smoke test for frameworks/management/corporate/environment_controls.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_environment_controls_loads_on_empty_input if {
	m := data.corporate.environment.controls with input as {}
	is_object(m)
}
