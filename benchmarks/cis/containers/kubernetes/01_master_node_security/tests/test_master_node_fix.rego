package cis.kubernetes.master_test

import rego.v1

# Validation fix pass 2026-10-17.

test_restrictive_manifest_mode_600_passes if {
	data.cis.kubernetes.master.api_server_pod_file_permissions with input as {"file_permissions": {"/etc/kubernetes/manifests/kube-apiserver.yaml": {"mode": "600"}}}
}

test_manifest_mode_0644_passes if {
	data.cis.kubernetes.master.etcd_pod_file_permissions with input as {"file_permissions": {"/etc/kubernetes/manifests/etcd.yaml": {"mode": "0644"}}}
}

test_manifest_mode_664_fails if {
	not data.cis.kubernetes.master.scheduler_pod_file_permissions with input as {"file_permissions": {"/etc/kubernetes/manifests/kube-scheduler.yaml": {"mode": "664"}}}
}

test_missing_apiserver_args_do_not_pass_negative_checks if {
	not data.cis.kubernetes.master.basic_auth_file_not_set with input as {}
	not data.cis.kubernetes.master.token_auth_file_not_set with input as {}
	not data.cis.kubernetes.master.kubelet_https_enabled with input as {}
	not data.cis.kubernetes.master.authorization_mode_not_always_allow with input as {}
	not data.cis.kubernetes.master.admission_control_service_account with input as {}
}

test_negative_check_passes_with_args_present if {
	data.cis.kubernetes.master.basic_auth_file_not_set with input as {"kube_apiserver_args": "--anonymous-auth=false"}
}

test_report_fully_populated_on_empty_input if {
	r := data.cis.kubernetes.master.kubernetes_master_compliance with input as {}
	r.overall_compliant == false
	count(r) == 24
}
