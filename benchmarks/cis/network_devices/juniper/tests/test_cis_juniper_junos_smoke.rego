package cis_juniper_junos_test

import rego.v1

# Generated smoke test for benchmarks/cis/network_devices/juniper/cis_juniper_junos.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_juniper_junos_loads_on_empty_input if {
	m := data.cis_juniper_junos with input as {}
	is_object(m)
}

test_cis_juniper_junos_violations_on_empty_input if {
	v := data.cis_juniper_junos.violations with input as {}
	count(v) > 0
}
