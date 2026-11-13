package cis_kubernetes_test

import rego.v1

# Generated smoke test for benchmarks/cis/kubernetes/cis_kubernetes_benchmark.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_kubernetes_benchmark_loads_on_empty_input if {
	m := data.cis_kubernetes with input as {}
	is_object(m)
}

test_cis_kubernetes_benchmark_violations_on_empty_input if {
	v := data.cis_kubernetes.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13 regressions.
test_etcd_cert_without_key_violates if {
	v := data.cis_kubernetes.etcd_violations with input as {"etcd": {"cert_file": "/x"}}
	count(v) == 1
}

test_etcd_both_files_set_passes if {
	v := data.cis_kubernetes.etcd_violations with input as {"etcd": {"cert_file": "/x", "key_file": "/y"}}
	count(v) == 0
}

test_api_server_mode_622_violates if {
	v := data.cis_kubernetes.control_plane_violations with input as {"control_plane": {"api_server_pod_spec_permissions": 622}}
	count(v) == 1
}

test_api_server_mode_606_violates if {
	v := data.cis_kubernetes.control_plane_violations with input as {"control_plane": {"api_server_pod_spec_permissions": 606}}
	count(v) == 1
}

test_api_server_mode_600_and_644_pass if {
	a := data.cis_kubernetes.control_plane_violations with input as {"control_plane": {"api_server_pod_spec_permissions": 600}}
	b := data.cis_kubernetes.control_plane_violations with input as {"control_plane": {"api_server_pod_spec_permissions": 644}}
	c := data.cis_kubernetes.control_plane_violations with input as {"control_plane": {"api_server_pod_spec_permissions": "0644"}}
	(count(a) + count(b)) + count(c) == 0
}

test_kubelet_service_mode_622_violates if {
	v := data.cis_kubernetes.worker_nodes_violations with input as {"worker_nodes": [{"kubelet_service_permissions": 622}]}
	count(v) == 1
}
