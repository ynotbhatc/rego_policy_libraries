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

# Semantic review 2026-11-13 regressions.
test_docker_service_wrong_owner_only_violates if {
	v := data.cis_docker.daemon_config_violations with input as {"host": {"file_permissions": {"docker.service": {"owner": "alice", "group": "root"}}}}
	count(v) == 1
}

test_docker_service_wrong_group_only_violates if {
	v := data.cis_docker.daemon_config_violations with input as {"host": {"file_permissions": {"docker.service": {"owner": "root", "group": "docker"}}}}
	count(v) == 1
}

test_docker_service_missing_entry_violates if {
	v := data.cis_docker.daemon_config_violations with input as {"host": {"file_permissions": {}}}
	count(v) == 1
}

test_docker_service_root_root_passes if {
	v := data.cis_docker.daemon_config_violations with input as {"host": {"file_permissions": {"docker.service": {"owner": "root", "group": "root"}}}}
	count(v) == 0
}
