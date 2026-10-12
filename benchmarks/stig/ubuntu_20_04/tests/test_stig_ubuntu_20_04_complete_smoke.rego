package stig.ubuntu_20_04_test

import rego.v1

# Generated smoke test for benchmarks/stig/ubuntu_20_04/stig_ubuntu_20_04_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_ubuntu_20_04_complete_loads_on_empty_input if {
	m := data.stig.ubuntu_20_04 with input as {}
	is_object(m)
}
