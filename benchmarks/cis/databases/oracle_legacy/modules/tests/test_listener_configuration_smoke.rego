package cis_oracle.listener_configuration_test

import rego.v1

# Generated smoke test for benchmarks/cis/databases/oracle_legacy/modules/listener_configuration.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_listener_configuration_loads_on_empty_input if {
	m := data.cis_oracle.listener_configuration with input as {}
	is_object(m)
}

test_listener_configuration_violations_on_empty_input if {
	v := data.cis_oracle.listener_configuration.violations with input as {}
	count(v) > 0
}
