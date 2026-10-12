package cis_esxi_8_test

import rego.v1

# Generated smoke test for benchmarks/cis/vmware/esxi/cis_esxi_8.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_esxi_8_loads_on_empty_input if {
	m := data.cis_esxi_8 with input as {}
	is_object(m)
}

