package cis_cisco_ios_test

import rego.v1

# Generated smoke test for benchmarks/cis/network_devices/cisco/cis_cisco_ios.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_cisco_ios_loads_on_empty_input if {
	m := data.cis_cisco_ios with input as {}
	is_object(m)
}

test_cis_cisco_ios_violations_on_empty_input if {
	v := data.cis_cisco_ios.violations with input as {}
	count(v) > 0
}
