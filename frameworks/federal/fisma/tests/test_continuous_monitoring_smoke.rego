package fisma.continuous_monitoring_test

import rego.v1

# Generated smoke test for frameworks/federal/fisma/continuous_monitoring.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_continuous_monitoring_loads_on_empty_input if {
	m := data.fisma.continuous_monitoring with input as {}
	is_object(m)
}
