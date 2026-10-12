package cis_palo_alto_panos_test

import rego.v1

# Generated smoke test for benchmarks/cis/network_devices/palo_alto/cis_palo_alto_panos.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_palo_alto_panos_loads_on_empty_input if {
	m := data.cis_palo_alto_panos with input as {}
	is_object(m)
}

test_cis_palo_alto_panos_violations_on_empty_input if {
	v := data.cis_palo_alto_panos.violations with input as {}
	count(v) > 0
}
