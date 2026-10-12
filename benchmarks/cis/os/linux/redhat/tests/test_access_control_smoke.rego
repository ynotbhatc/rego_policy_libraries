package cis.access_control_test

import rego.v1

# Generated smoke test for benchmarks/cis/os/linux/redhat/access_control.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_access_control_loads_on_empty_input if {
	m := data.cis.access_control with input as {}
	is_object(m)
}
