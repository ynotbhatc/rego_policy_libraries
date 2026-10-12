package cis_debian_11.apparmor_test

import rego.v1

# Generated smoke test for benchmarks/cis/debian_11/apparmor_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_apparmor_validation_loads_on_empty_input if {
	m := data.cis_debian_11.apparmor with input as {}
	is_object(m)
}

test_apparmor_validation_violations_on_empty_input if {
	v := data.cis_debian_11.apparmor.violations with input as {}
	count(v) > 0
}
