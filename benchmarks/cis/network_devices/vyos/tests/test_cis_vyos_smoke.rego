package cis_vyos_test

import rego.v1

# Generated smoke test for benchmarks/cis/network_devices/vyos/cis_vyos.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_vyos_loads_on_empty_input if {
	m := data.cis_vyos with input as {}
	is_object(m)
}

test_cis_vyos_violations_on_empty_input if {
	v := data.cis_vyos.violations with input as {}
	count(v) > 0
}
