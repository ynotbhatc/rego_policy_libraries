package iec_62443_main_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/iec_62443/iec_62443_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_iec_62443_main_loads_on_empty_input if {
	m := data.iec_62443_main with input as {}
	is_object(m)
}
