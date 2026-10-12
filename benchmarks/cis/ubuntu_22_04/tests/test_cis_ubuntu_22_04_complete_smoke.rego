package cis_ubuntu_22_04_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/cis_ubuntu_22_04_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_ubuntu_22_04_complete_loads_on_empty_input if {
	m := data.cis_ubuntu_22_04 with input as {}
	is_object(m)
}

test_cis_ubuntu_22_04_complete_violations_on_empty_input if {
	v := data.cis_ubuntu_22_04.violations with input as {}
	count(v) > 0
}
