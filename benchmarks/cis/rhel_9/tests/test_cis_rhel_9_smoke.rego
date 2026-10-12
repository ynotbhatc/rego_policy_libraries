package cis.rhel_9_test

import rego.v1

# Generated smoke test for benchmarks/cis/rhel_9/cis_rhel_9.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_rhel_9_loads_on_empty_input if {
	m := data.cis.rhel_9 with input as {}
	is_object(m)
}

test_cis_rhel_9_violations_on_empty_input if {
	v := data.cis.rhel_9.violations with input as {}
	count(v) > 0
}
