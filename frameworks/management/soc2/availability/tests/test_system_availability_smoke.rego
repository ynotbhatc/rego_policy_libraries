package soc2.availability.system_availability_test

import rego.v1

# Generated smoke test for frameworks/management/soc2/availability/system_availability.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_system_availability_loads_on_empty_input if {
	m := data.soc2.availability.system_availability with input as {}
	is_object(m)
}
