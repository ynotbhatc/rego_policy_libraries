package cis_ubuntu_22_04.logging_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/logging_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_logging_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_22_04.logging with input as {}
	is_object(m)
}

test_logging_validation_violations_on_empty_input if {
	v := data.cis_ubuntu_22_04.logging.violations with input as {}
	count(v) > 0
}
