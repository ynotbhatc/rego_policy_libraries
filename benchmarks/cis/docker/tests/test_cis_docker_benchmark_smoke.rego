package cis_docker_test

import rego.v1

# Generated smoke test for benchmarks/cis/docker/cis_docker_benchmark.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_docker_benchmark_loads_on_empty_input if {
	m := data.cis_docker with input as {}
	is_object(m)
}

test_cis_docker_benchmark_violations_on_empty_input if {
	v := data.cis_docker.violations with input as {}
	count(v) > 0
}
