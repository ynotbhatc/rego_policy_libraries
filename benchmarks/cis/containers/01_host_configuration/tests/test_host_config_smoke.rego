package cis.docker.host_test

import rego.v1

# Generated smoke test for benchmarks/cis/containers/01_host_configuration/host_config.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_host_config_loads_on_empty_input if {
	m := data.cis.docker.host with input as {}
	is_object(m)
}
