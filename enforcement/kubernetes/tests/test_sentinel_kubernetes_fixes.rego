package sentinel.kubernetes_test

import rego.v1

# Regression tests for the 2026-10-17 validation pass.

has(prefix, v) if {
	some m in v
	startswith(m, prefix)
}

bad_container := {
	"name": "c", "image": "quay.io/x/y:1",
	"securityContext": {"privileged": true, "runAsUser": 0},
}

test_k8s_cronjob_containers_checked if {
	i := {"kind": "CronJob", "manifest": {
		"metadata": {"name": "j", "namespace": "n"},
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [bad_container]}}}}},
	}}
	v1 := data.sentinel.kubernetes.violation_k8s_001 with input as i
	v2 := data.sentinel.kubernetes.violation_k8s_002 with input as i
	has("SENTINEL-K8S-001", v1)
	has("SENTINEL-K8S-002", v2)
}

test_k8s_pod_host_namespaces_checked if {
	i := {"kind": "Pod", "manifest": {
		"metadata": {"name": "p", "namespace": "n"},
		"spec": {"hostNetwork": true, "hostPID": true, "hostIPC": true, "containers": [], "volumes": [{"name": "v", "hostPath": {"path": "/"}}]},
	}}
	v5 := data.sentinel.kubernetes.violation_k8s_005 with input as i
	count(v5) == 3
	v6 := data.sentinel.kubernetes.violation_k8s_006 with input as i
	count(v6) == 1
}

test_k8s_deployment_host_namespaces_still_checked if {
	i := {"kind": "Deployment", "manifest": {
		"metadata": {"name": "d", "namespace": "n"},
		"spec": {"template": {"spec": {"hostNetwork": true, "containers": []}}},
	}}
	v := data.sentinel.kubernetes.violation_k8s_005 with input as i
	count(v) == 1
}

test_k8s_absent_readonly_rootfs_flagged if {
	i := {"kind": "Pod", "manifest": {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "a:1", "securityContext": {}}]}}}
	v := data.sentinel.kubernetes.violation_k8s_003 with input as i
	count(v) == 1
}

test_k8s_readonly_rootfs_true_ok if {
	i := {"kind": "Pod", "manifest": {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "a:1", "securityContext": {"readOnlyRootFilesystem": true}}]}}}
	v := data.sentinel.kubernetes.violation_k8s_003 with input as i
	count(v) == 0
}

test_k8s_absent_allow_priv_esc_flagged if {
	i := {"kind": "Pod", "manifest": {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "a:1"}]}}}
	v := data.sentinel.kubernetes.violation_k8s_009 with input as i
	count(v) == 1
}

test_k8s_allow_priv_esc_false_ok if {
	i := {"kind": "Pod", "manifest": {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "image": "a:1", "securityContext": {"allowPrivilegeEscalation": false}}]}}}
	v := data.sentinel.kubernetes.violation_k8s_009 with input as i
	count(v) == 0
}

test_k8s_absent_automount_flagged if {
	i := {"kind": "Deployment", "manifest": {"metadata": {"name": "d", "namespace": "n"}, "spec": {"template": {"spec": {"containers": []}}}}}
	v := data.sentinel.kubernetes.violation_k8s_014 with input as i
	count(v) == 1
}

test_k8s_automount_false_ok if {
	i := {"kind": "Deployment", "manifest": {"metadata": {"name": "d", "namespace": "n"}, "spec": {"template": {"spec": {"automountServiceAccountToken": false, "containers": []}}}}}
	v := data.sentinel.kubernetes.violation_k8s_014 with input as i
	count(v) == 0
}

test_k8s_result_defined_for_noncompliant_resource if {
	i := {"kind": "Pod", "manifest": {"metadata": {"name": "p", "namespace": "n"}, "spec": {"containers": [bad_container]}}}
	r := data.sentinel.kubernetes.result with input as i
	r.compliant == false
	r.violation_count > 0
	r.resource == "p"
}
