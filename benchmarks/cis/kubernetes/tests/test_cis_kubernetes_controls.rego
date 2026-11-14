package cis_kubernetes_test

import rego.v1

import data.cis_kubernetes as b
import data.cis_kubernetes.main as bridge

# Generated per-recommendation tests for CIS Kubernetes Benchmark v2.1.0: every recommendation has a pass test (green input) and a
# fail test; fact-based checks also have an evidence-missing test; attestations fail when false or absent.
# Profile, report-contract and helper tests come first.

green := {
	"api_server": {
		"flags": {
			"anonymous-auth": "false",
			"kubelet-client-certificate": "/etc/kubernetes/pki/apiserver-kubelet-client.crt",
			"kubelet-client-key": "/etc/kubernetes/pki/apiserver-kubelet-client.key",
			"kubelet-certificate-authority": "/etc/kubernetes/pki/ca.crt",
			"authorization-mode": "Node,RBAC",
			"enable-admission-plugins": "NodeRestriction,EventRateLimit,AlwaysPullImages,DenyServiceExternalIPs",
			"profiling": "false",
			"audit-log-path": "/var/log/kubernetes/audit.log",
			"audit-log-maxage": "30",
			"audit-log-maxbackup": "10",
			"audit-log-maxsize": "100",
			"audit-policy-file": "/etc/kubernetes/audit-policy.yaml",
			"service-account-lookup": "true",
			"service-account-key-file": "/etc/kubernetes/pki/sa.pub",
			"etcd-certfile": "/etc/kubernetes/pki/apiserver-etcd-client.crt",
			"etcd-keyfile": "/etc/kubernetes/pki/apiserver-etcd-client.key",
			"etcd-cafile": "/etc/kubernetes/pki/etcd/ca.crt",
			"tls-cert-file": "/etc/kubernetes/pki/apiserver.crt",
			"tls-private-key-file": "/etc/kubernetes/pki/apiserver.key",
			"client-ca-file": "/etc/kubernetes/pki/ca.crt",
			"encryption-provider-config": "/etc/kubernetes/enc/config.yaml",
			"tls-cipher-suites": "TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"service-account-extend-token-expiration": "false",
		},
		"audit_policy": {
			"apiVersion": "audit.k8s.io/v1",
			"kind": "Policy",
			"rules": [{"level": "Metadata"}],
		},
		"encryption_config": {"resources": [{
			"resources": ["secrets"],
			"providers": [
				"aescbc",
				"identity",
			],
		}]},
	},
	"controller_manager": {"flags": {
		"terminated-pod-gc-threshold": "1000",
		"profiling": "false",
		"use-service-account-credentials": "true",
		"service-account-private-key-file": "/etc/kubernetes/pki/sa.key",
		"root-ca-file": "/etc/kubernetes/pki/ca.crt",
		"bind-address": "127.0.0.1",
	}},
	"scheduler": {"flags": {
		"profiling": "false",
		"bind-address": "127.0.0.1",
	}},
	"etcd": {"flags": {
		"cert-file": "/etc/kubernetes/pki/etcd/server.crt",
		"key-file": "/etc/kubernetes/pki/etcd/server.key",
		"client-cert-auth": "true",
		"peer-cert-file": "/etc/kubernetes/pki/etcd/peer.crt",
		"peer-key-file": "/etc/kubernetes/pki/etcd/peer.key",
		"peer-client-cert-auth": "true",
		"trusted-ca-file": "/etc/kubernetes/pki/etcd/ca.crt",
		"data-dir": "/var/lib/etcd",
	}},
	"kubelet": {
		"flags": {
			"config": "/var/lib/kubelet/config.yaml",
			"kubeconfig": "/etc/kubernetes/kubelet.conf",
			"config-dir": "/etc/kubernetes/kubelet.conf.d",
		},
		"config": {
			"authentication": {
				"anonymous": {"enabled": false},
				"x509": {"clientCAFile": "/etc/kubernetes/pki/ca.crt"},
			},
			"authorization": {"mode": "Webhook"},
			"readOnlyPort": 0,
			"streamingConnectionIdleTimeout": "4h0m0s",
			"makeIPTablesUtilChains": true,
			"tlsCertFile": "/var/lib/kubelet/pki/kubelet.crt",
			"tlsPrivateKeyFile": "/var/lib/kubelet/pki/kubelet.key",
			"rotateCertificates": true,
			"serverTLSBootstrap": true,
			"tlsCipherSuites": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
			"podPidsLimit": 4096,
			"seccompDefault": true,
		},
	},
	"kube_proxy": {
		"running": true,
		"flags": {"config": "/var/lib/kube-proxy/config.conf"},
		"config": {"metricsBindAddress": "127.0.0.1:10249"},
	},
	"files": {
		"manifests": [
			{
				"path": "/etc/kubernetes/manifests/kube-apiserver.yaml",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/manifests/kube-controller-manager.yaml",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/manifests/kube-scheduler.yaml",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/manifests/etcd.yaml",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
		],
		"cni": [{
			"path": "/etc/cni/net.d/10-calico.conflist",
			"mode": "0600",
			"owner": "root",
			"group": "root",
		}],
		"etcd_data": [
			{
				"path": "/var/lib/etcd",
				"mode": "0700",
				"owner": "etcd",
				"group": "etcd",
			},
			{
				"path": "/var/lib/etcd/member",
				"mode": "0700",
				"owner": "etcd",
				"group": "etcd",
			},
		],
		"control_plane_confs": [
			{
				"path": "/etc/kubernetes/admin.conf",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/scheduler.conf",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/controller-manager.conf",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/super-admin.conf",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
		],
		"pki": [
			{
				"path": "/etc/kubernetes/pki/ca.crt",
				"mode": "0644",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/pki/ca.key",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/pki",
				"mode": "0755",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/pki/apiserver.crt",
				"mode": "0644",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/pki/apiserver.key",
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
		],
		"kubelet_service": [{
			"path": "/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf",
			"mode": "0600",
			"owner": "root",
			"group": "root",
		}],
		"kube_proxy_kubeconfig": [{
			"path": "/var/lib/kube-proxy/kubeconfig.conf",
			"mode": "0600",
			"owner": "root",
			"group": "root",
		}],
		"kubelet_kubeconfig": [{
			"path": "/etc/kubernetes/kubelet.conf",
			"mode": "0600",
			"owner": "root",
			"group": "root",
		}],
		"kubelet_client_ca": [{
			"path": "/etc/kubernetes/pki/ca.crt",
			"mode": "0644",
			"owner": "root",
			"group": "root",
		}],
		"kubelet_config_yaml": [{
			"path": "/var/lib/kubelet/config.yaml",
			"mode": "0600",
			"owner": "root",
			"group": "root",
		}],
		"kubelet_config_dir": [
			{
				"path": "/etc/kubernetes/kubelet.conf.d",
				"mode": "0755",
				"owner": "root",
				"group": "root",
			},
			{
				"path": "/etc/kubernetes/kubelet.conf.d/10-limits.conf",
				"mode": "0644",
				"owner": "root",
				"group": "root",
			},
		],
	},
	"service_accounts": {"default": [
		{
			"namespace": "default",
			"automount_token": false,
			"role_bindings": [],
		},
		{
			"namespace": "kube-system",
			"automount_token": false,
			"role_bindings": [],
		},
	]},
	"network_policies": {"namespaces_without_policy": []},
	"secrets": {"env_var_usage_count": 0},
	"cluster": {"namespace_resources": {"default": ["service/kubernetes"]}},
	"collection_status": {
		"default_service_accounts": "ok",
		"network_policies": "ok",
		"secret_env_scan": "ok",
		"namespace_resources": "ok",
	},
	"attest": {
		"users_no_client_certificate_auth": true,
		"users_no_service_account_token_auth": true,
		"users_no_bootstrap_token_auth": true,
		"audit_policy_coverage_reviewed": true,
		"kubelet_event_record_qps_reviewed": true,
		"cluster_admin_bindings_reviewed": true,
		"secret_access_reviewed": true,
		"rbac_wildcards_reviewed": true,
		"pod_create_access_reviewed": true,
		"service_account_token_mounts_reviewed": true,
		"system_masters_not_used": true,
		"bind_impersonate_escalate_reviewed": true,
		"persistent_volume_create_access_reviewed": true,
		"node_proxy_access_reviewed": true,
		"csr_approval_access_reviewed": true,
		"webhook_config_access_reviewed": true,
		"service_account_token_create_access_reviewed": true,
		"kubelet_fine_grained_access_reviewed": true,
		"policy_control_mechanism_active": true,
		"admission_privileged_restricted": true,
		"admission_host_pid_restricted": true,
		"admission_host_ipc_restricted": true,
		"admission_host_network_restricted": true,
		"admission_privilege_escalation_restricted": true,
		"admission_root_containers_restricted": true,
		"admission_net_raw_restricted": true,
		"admission_capabilities_restricted": true,
		"admission_windows_host_process_restricted": true,
		"admission_host_path_restricted": true,
		"admission_host_ports_restricted": true,
		"admission_proc_mount_restricted": true,
		"cni_enforces_network_policies": true,
		"external_secret_storage_reviewed": true,
		"image_provenance_configured": true,
		"namespace_boundaries_reviewed": true,
		"pod_seccomp_profiles_reviewed": true,
		"pod_security_contexts_reviewed": true,
	},
}

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

_patched(ops) := json.patch(green, ops)

test_green_input_is_compliant if {
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	r := bridge.compliance_report with input as green
	r.compliant == true
	r.failed_controls == 0
	r.passed_controls == 134
	r.compliance_percentage == 100
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == 134
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == 65
	count([id | some id, r in b.recommendations; r.assessment == "Manual"]) == 69
	count([id | some id, r in b.recommendations; r.profiles == ["Level 1 - Master Node"]]) == 93
	count([id | some id, r in b.recommendations; r.profiles == ["Level 2 - Master Node"]]) == 15
	count([id | some id, r in b.recommendations; r.profiles == ["Level 1 - Worker Node"]]) == 25
	count([id | some id, r in b.recommendations; r.profiles == ["Level 2 - Worker Node"]]) == 1
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == 37
}

test_report_contract_on_empty_input if {
	r := bridge.compliance_report with input as {}
	r.compliant == false
	r.total_controls == 134
	r.failed_controls == 134
	r.passed_controls == 0
	r.compliance_percentage == 0
	r.facts_supplied == false
	is_array(r.violations)
	r.violation_count == count(r.violations)
	r.level_1.total == 118
	r.level_2.total == 16
	r.version == "v2.1.0"
}

_profile_total(p) := r.total_controls if r := bridge.compliance_report with input as {"cis_profile": p}

_profile_failed(p) := r.failed_controls if r := bridge.compliance_report with input as {"cis_profile": p}

test_profile_totals if {
	_profile_total({"level": 1}) == 118
	_profile_total({"level": 2}) == 134
	_profile_total({"level": 1, "role": "master"}) == 93
	_profile_total({"level": 2, "role": "master"}) == 108
	_profile_total({"role": "control_plane"}) == 108
	_profile_total({"level": 1, "role": "worker"}) == 25
	_profile_total({"level": 2, "role": "Worker"}) == 26
	_profile_total({"level": 3, "role": "edge"}) == 134
}

test_profile_fails_only_what_is_in_scope if {
	_profile_failed({"level": 1, "role": "master"}) == 93
	_profile_failed({"level": 2, "role": "master"}) == 108
	_profile_failed({"level": 1, "role": "worker"}) == 25
	_profile_failed({"level": 2, "role": "worker"}) == 26
}

test_worker_role_does_not_count_master_recommendations if {
	inp := {"cis_profile": {"role": "worker", "level": 1}}
	vs := b.violations with input as inp
	not _has_id(vs, "1.1.1")
	not _has_id(vs, "4.1.1")
	not _has_id(vs, "4.2.8")
	_has_id(vs, "4.1.2")
	_has_id(vs, "5.1.3")
}

test_master_role_does_not_count_worker_recommendations if {
	inp := {"cis_profile": {"role": "master", "level": 1}}
	vs := b.violations with input as inp
	_has_id(vs, "1.1.1")
	_has_id(vs, "4.1.1")
	not _has_id(vs, "4.1.2")
	not _has_id(vs, "1.2.12")
	not _has_id(vs, "5.1.3")
}

test_worker_only_facts_are_compliant_for_the_worker_profile if {
	inp := object.union(object.remove(green, ["api_server", "controller_manager", "scheduler", "etcd"]), {"cis_profile": {"role": "worker"}})
	b.compliant with input as inp
	not b.compliant with input as object.remove(inp, ["cis_profile"])
}

test_section_results_partition_the_scope if {
	r := b.compliance_report with input as {}
	sum([s.total | some _, s in r.section_results]) == r.total_controls
	sum([s.failed | some _, s in r.section_results]) == r.failed_controls
}

# file modes are octal bit masks: 0460 is numerically below 0600 but grants group access
test_mode_is_a_bit_mask if {
	b.mode_within("0600", "600")
	b.mode_within("400", "600")
	b.mode_within("0o640", "644")
	not b.mode_within("0460", "600")
	not b.mode_within("0601", "600")
	not b.mode_within("4600", "600")
	not b.mode_within("1755", "755")
	not b.mode_within(600, "600")
	not b.mode_within("rw-------", "600")
	not b.mode_within("", "600")
}

test_1_1_1_group_readable_manifest_fails if {
	_has_id(b.violations, "1.1.1") with input as _patched([{"op": "add", "path": "/files/manifests/0/mode", "value": "0460"}])
	_has_id(b.violations, "1.1.1") with input as _patched([{"op": "add", "path": "/files/manifests/0/mode", "value": 600}])
	not _has_id(b.violations, "1.1.1") with input as _patched([{"op": "add", "path": "/files/manifests/0/mode", "value": "400"}])
}

test_1_1_11_follows_the_etcd_data_dir_flag if {
	ops := [{"op": "add", "path": "/etcd/flags/data-dir", "value": "/data/etcd/"}]
	vs := b.violations with input as _patched(ops)
	"1.1.11: evidence missing — files.etcd_data entry for the etcd --data-dir directory not collected" in vs
	ok := array.concat(ops, [{"op": "add", "path": "/files/etcd_data/-", "value": {"path": "/data/etcd", "mode": "700", "owner": "etcd", "group": "etcd"}}])
	not _has_id(b.violations, "1.1.11") with input as _patched(ok)
}

test_flag_spellings_and_ambiguity if {
	ops := [{"op": "remove", "path": "/api_server/flags/profiling"}, {"op": "add", "path": "/api_server/flags/--profiling", "value": "False"}]
	not _has_id(b.violations, "1.2.15") with input as _patched(ops)
	both := [{"op": "add", "path": "/api_server/flags/--profiling", "value": "false"}]
	_has_id(b.violations, "1.2.15") with input as _patched(both)
	listed := [{"op": "add", "path": "/api_server/flags/token_auth_file", "value": ["/a", "/b"]}]
	_has_id(b.violations, "1.2.2") with input as _patched(listed)
}

test_1_2_1_structured_authentication if {
	base := [{"op": "remove", "path": "/api_server/flags/anonymous-auth"}, {"op": "add", "path": "/api_server/flags/authentication-config", "value": "/etc/kubernetes/authn.yaml"}]
	"1.2.1: evidence missing — api_server.flags (and api_server.authentication_config when --authentication-config is set) not collected" in b.violations with input as _patched(base)
	off := array.concat(base, [{"op": "add", "path": "/api_server/authentication_config", "value": {"anonymous": {"enabled": false}}}])
	not _has_id(b.violations, "1.2.1") with input as _patched(off)
	health := array.concat(base, [{"op": "add", "path": "/api_server/authentication_config", "value": {"anonymous": {"enabled": true, "conditions": [{"path": "/healthz"}, {"path": "/livez"}]}}}])
	not _has_id(b.violations, "1.2.1") with input as _patched(health)
	open := array.concat(base, [{"op": "add", "path": "/api_server/authentication_config", "value": {"anonymous": {"enabled": true}}}])
	_has_id(b.violations, "1.2.1") with input as _patched(open)
	none := array.concat(base, [{"op": "add", "path": "/api_server/authentication_config", "value": {"jwt": []}}])
	_has_id(b.violations, "1.2.1") with input as _patched(none)
	other := array.concat(base, [{"op": "add", "path": "/api_server/authentication_config", "value": {"anonymous": {"enabled": true, "conditions": [{"path": "/metrics"}]}}}])
	_has_id(b.violations, "1.2.1") with input as _patched(other)
	attested := array.concat(other, [{"op": "add", "path": "/attest/api_anonymous_paths_required", "value": true}])
	not _has_id(b.violations, "1.2.1") with input as _patched(attested)
	unset := [{"op": "remove", "path": "/api_server/flags/anonymous-auth"}]
	_has_id(b.violations, "1.2.1") with input as _patched(unset)
}

test_1_2_20_request_timeout if {
	set := [{"op": "add", "path": "/api_server/flags/request-timeout", "value": "5m"}]
	_has_id(b.violations, "1.2.20") with input as _patched(set)
	ok := array.concat(set, [{"op": "add", "path": "/attest/api_request_timeout_appropriate", "value": true}])
	not _has_id(b.violations, "1.2.20") with input as _patched(ok)
	zero := array.concat(ok, [{"op": "add", "path": "/api_server/flags/request-timeout", "value": "0"}])
	_has_id(b.violations, "1.2.20") with input as _patched(zero)
}

test_unset_defaults if {
	# 1.2.10, 1.2.12, 1.2.13, 1.2.21, 1.3.6, 2.3, 2.6 pass when the flag is absent (green carries none of them)
	vs := b.violations with input as _patched([{"op": "remove", "path": "/api_server/flags/service-account-lookup"}])
	count(vs) == 0

	# 1.3.7 and 1.4.2 do not: the default bind address is the wildcard
	_has_id(b.violations, "1.3.7") with input as _patched([{"op": "remove", "path": "/controller_manager/flags/bind-address"}])
	_has_id(b.violations, "1.4.2") with input as _patched([{"op": "add", "path": "/scheduler/flags/bind-address", "value": "::"}])
	not _has_id(b.violations, "1.4.2") with input as _patched([{"op": "add", "path": "/scheduler/flags/bind-address", "value": "::1"}])
}

test_ambiguous_flags_fail_negative_checks if {
	listed := [{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": ["NodeRestriction", "AlwaysAdmit"]}]
	_has_id(b.violations, "1.2.10") with input as _patched(listed)
	twice := [{"op": "add", "path": "/api_server/flags/disable_admission_plugins", "value": "ServiceAccount"}, {"op": "add", "path": "/api_server/flags/disable-admission-plugins", "value": ""}]
	vs := b.violations with input as _patched(twice)
	_has_id(vs, "1.2.12")
	_has_id(vs, "1.2.13")
	gates := [{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "RotateKubeletServerCertificate=true"}, {"op": "add", "path": "/controller_manager/flags/feature_gates", "value": "RotateKubeletServerCertificate=false"}]
	_has_id(b.violations, "1.3.6") with input as _patched(gates)
	kgates := [{"op": "remove", "path": "/kubelet/config/serverTLSBootstrap"}, {"op": "add", "path": "/kubelet/config/featureGates", "value": {"RotateKubeletServerCertificate": true}}]
	not _has_id(b.violations, "4.2.11") with input as _patched(kgates)
	kamb := array.concat(kgates, [{"op": "add", "path": "/kubelet/flags/feature-gates", "value": ["RotateKubeletServerCertificate=false"]}])
	_has_id(b.violations, "4.2.11") with input as _patched(kamb)
}

test_4_1_9_only_applies_with_a_config_file if {
	noconf := [{"op": "add", "path": "/kubelet", "value": {"flags": {}}}, {"op": "remove", "path": "/files/kubelet_config_yaml"}]
	vs := b.violations with input as _patched(noconf)
	not _has_id(vs, "4.1.9")
	not _has_id(vs, "4.1.10")
}

test_1_3_6_feature_gate if {
	not _has_id(b.violations, "1.3.6") with input as _patched([{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "A=false,RotateKubeletServerCertificate=true"}])
	_has_id(b.violations, "1.3.6") with input as _patched([{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "RotateKubeletServerCertificate=maybe"}])
}

test_single_member_etcd_is_exempt_from_peer_tls if {
	ops := [{"op": "remove", "path": "/etcd/flags/peer-cert-file"}, {"op": "remove", "path": "/etcd/flags/peer-client-cert-auth"}]
	vs := b.violations with input as _patched(ops)
	_has_id(vs, "2.4")
	_has_id(vs, "2.5")
	vs1 := b.violations with input as _patched(array.concat(ops, [{"op": "add", "path": "/etcd/member_count", "value": 1}]))
	not _has_id(vs1, "2.4")
	not _has_id(vs1, "2.5")
}

test_kubelet_flags_override_the_config_file if {
	_has_id(b.violations, "4.2.1") with input as _patched([{"op": "add", "path": "/kubelet/flags/anonymous-auth", "value": "true"}])
	_has_id(b.violations, "4.2.4") with input as _patched([{"op": "add", "path": "/kubelet/flags/read-only-port", "value": "10255"}])
	not _has_id(b.violations, "4.2.4") with input as _patched([{"op": "remove", "path": "/kubelet/config/readOnlyPort"}])
	_has_id(b.violations, "4.2.5") with input as _patched([{"op": "add", "path": "/kubelet/flags/streaming-connection-idle-timeout", "value": "0"}])
	not _has_id(b.violations, "4.2.5") with input as _patched([{"op": "remove", "path": "/kubelet/config/streamingConnectionIdleTimeout"}])
	_has_id(b.violations, "4.2.13") with input as _patched([{"op": "add", "path": "/kubelet/flags/pod-max-pids", "value": "0"}])
}

test_kubelet_without_a_config_file if {
	flags := {"anonymous-auth": "false", "authorization-mode": "Webhook", "client-ca-file": "/etc/kubernetes/pki/ca.crt", "read-only-port": "0", "tls-cert-file": "/k.crt", "tls-private-key-file": "/k.key", "rotate-server-certificates": "true", "tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "pod-max-pids": "1024", "seccomp-default": "true"}
	inp := json.patch(green, [{"op": "add", "path": "/kubelet", "value": {"flags": flags}}])
	vs := b.violations with input as inp
	count(vs) == 0

	# the file's values do not count when --config is not given
	stale := json.patch(green, [{"op": "remove", "path": "/kubelet/flags/config"}])
	vs2 := b.violations with input as stale
	_has_id(vs2, "4.2.1")
	_has_id(vs2, "4.2.4")

	# --config given but the file was not collected
	gone := json.patch(green, [{"op": "remove", "path": "/kubelet/config"}])
	"4.2.1: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in b.violations with input as gone
}

test_4_1_11_only_applies_with_a_drop_in_directory if {
	ops := [{"op": "remove", "path": "/kubelet/flags/config-dir"}, {"op": "remove", "path": "/files/kubelet_config_dir"}]
	not _has_id(b.violations, "4.1.11") with input as _patched(ops)
	_has_id(b.violations, "4.1.11") with input as _patched([{"op": "add", "path": "/files/kubelet_config_dir/0/mode", "value": "0775"}])
	_has_id(b.violations, "4.1.11") with input as _patched([{"op": "add", "path": "/files/kubelet_config_dir/1/owner", "value": "kube"}])
}

test_kube_proxy_not_running_or_bound_elsewhere if {
	off := json.patch(green, [{"op": "add", "path": "/kube_proxy", "value": {"running": false}}, {"op": "remove", "path": "/files/kube_proxy_kubeconfig"}])
	vs := b.violations with input as off
	count(vs) == 0
	_has_id(b.violations, "4.3.1") with input as _patched([{"op": "add", "path": "/kube_proxy/flags/metrics-bind-address", "value": "0.0.0.0:10249"}])
	not _has_id(b.violations, "4.3.1") with input as _patched([{"op": "add", "path": "/kube_proxy/flags/metrics-bind-address", "value": "[::1]:10249"}])
	not _has_id(b.violations, "4.3.1") with input as _patched([{"op": "remove", "path": "/kube_proxy/config/metricsBindAddress"}])
}

test_violation_messages_start_with_an_in_scope_id if {
	vs := b.violations with input as {}
	every v in vs { split(v, ":")[0] in object.keys(b.recommendations) }
}

test_1_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.1")
}

test_1_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/0/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"1.1.1: kube-apiserver static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.1: evidence missing — files.manifests entry for kube-apiserver not collected" in vs
	not "1.1.1: kube-apiserver static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.2")
}

test_1_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/0/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"1.1.2: kube-apiserver static pod manifest must be owned by root:root" in vs
}

test_1_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.2: evidence missing — files.manifests entry for kube-apiserver not collected" in vs
	not "1.1.2: kube-apiserver static pod manifest must be owned by root:root" in vs
}

test_1_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.3")
}

test_1_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/1/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"1.1.3: kube-controller-manager static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.3: evidence missing — files.manifests entry for kube-controller-manager not collected" in vs
	not "1.1.3: kube-controller-manager static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.4")
}

test_1_1_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/1/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"1.1.4: kube-controller-manager static pod manifest must be owned by root:root" in vs
}

test_1_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.4: evidence missing — files.manifests entry for kube-controller-manager not collected" in vs
	not "1.1.4: kube-controller-manager static pod manifest must be owned by root:root" in vs
}

test_1_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.5")
}

test_1_1_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/2/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"1.1.5: kube-scheduler static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.5: evidence missing — files.manifests entry for kube-scheduler not collected" in vs
	not "1.1.5: kube-scheduler static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.6")
}

test_1_1_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/2/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"1.1.6: kube-scheduler static pod manifest must be owned by root:root" in vs
}

test_1_1_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.6: evidence missing — files.manifests entry for kube-scheduler not collected" in vs
	not "1.1.6: kube-scheduler static pod manifest must be owned by root:root" in vs
}

test_1_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.7")
}

test_1_1_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/3/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"1.1.7: etcd static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.7: evidence missing — files.manifests entry for etcd not collected" in vs
	not "1.1.7: etcd static pod manifest mode must be 600 or stricter" in vs
}

test_1_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.8")
}

test_1_1_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/manifests/3/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"1.1.8: etcd static pod manifest must be owned by root:root" in vs
}

test_1_1_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/manifests"}])
	vs := b.violations with input as inp
	"1.1.8: evidence missing — files.manifests entry for etcd not collected" in vs
	not "1.1.8: etcd static pod manifest must be owned by root:root" in vs
}

test_1_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.9")
}

test_1_1_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/cni/0/mode", "value": "0666"}])
	vs := b.violations with input as inp
	"1.1.9: every CNI configuration file mode must be 600 or stricter" in vs
}

test_1_1_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/cni"}])
	vs := b.violations with input as inp
	"1.1.9: evidence missing — files.cni not collected" in vs
	not "1.1.9: every CNI configuration file mode must be 600 or stricter" in vs
}

test_1_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.10")
}

test_1_1_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/cni/0/group", "value": "wheel"}])
	vs := b.violations with input as inp
	"1.1.10: every CNI configuration file must be owned by root:root" in vs
}

test_1_1_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/cni"}])
	vs := b.violations with input as inp
	"1.1.10: evidence missing — files.cni not collected" in vs
	not "1.1.10: every CNI configuration file must be owned by root:root" in vs
}

test_1_1_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.11")
}

test_1_1_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/etcd_data/0/mode", "value": "0755"}])
	vs := b.violations with input as inp
	"1.1.11: etcd data directory mode must be 700 or stricter" in vs
}

test_1_1_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/etcd_data"}])
	vs := b.violations with input as inp
	"1.1.11: evidence missing — files.etcd_data entry for the etcd --data-dir directory not collected" in vs
	not "1.1.11: etcd data directory mode must be 700 or stricter" in vs
}

test_1_1_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.12")
}

test_1_1_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/etcd_data/0/owner", "value": "root"}])
	vs := b.violations with input as inp
	"1.1.12: etcd data directory must be owned by etcd:etcd" in vs
}

test_1_1_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/etcd_data"}])
	vs := b.violations with input as inp
	"1.1.12: evidence missing — files.etcd_data entry for the etcd --data-dir directory not collected" in vs
	not "1.1.12: etcd data directory must be owned by etcd:etcd" in vs
}

test_1_1_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.13")
}

test_1_1_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/control_plane_confs/3/mode", "value": "0640"}])
	vs := b.violations with input as inp
	"1.1.13: admin.conf (and super-admin.conf when present) mode must be 600 or stricter" in vs
}

test_1_1_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/control_plane_confs"}])
	vs := b.violations with input as inp
	"1.1.13: evidence missing — files.control_plane_confs entry for admin.conf not collected" in vs
	not "1.1.13: admin.conf (and super-admin.conf when present) mode must be 600 or stricter" in vs
}

test_1_1_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.14")
}

test_1_1_14_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/control_plane_confs/0/owner", "value": "admin"}])
	vs := b.violations with input as inp
	"1.1.14: admin.conf (and super-admin.conf when present) must be owned by root:root" in vs
}

test_1_1_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/control_plane_confs"}])
	vs := b.violations with input as inp
	"1.1.14: evidence missing — files.control_plane_confs entry for admin.conf not collected" in vs
	not "1.1.14: admin.conf (and super-admin.conf when present) must be owned by root:root" in vs
}

test_1_1_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.15")
}

test_1_1_15_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/control_plane_confs/1/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"1.1.15: scheduler.conf mode must be 600 or stricter" in vs
}

test_1_1_15_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/control_plane_confs"}])
	vs := b.violations with input as inp
	"1.1.15: evidence missing — files.control_plane_confs entry for scheduler.conf not collected" in vs
	not "1.1.15: scheduler.conf mode must be 600 or stricter" in vs
}

test_1_1_16_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.16")
}

test_1_1_16_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/control_plane_confs/1/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"1.1.16: scheduler.conf must be owned by root:root" in vs
}

test_1_1_16_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/control_plane_confs"}])
	vs := b.violations with input as inp
	"1.1.16: evidence missing — files.control_plane_confs entry for scheduler.conf not collected" in vs
	not "1.1.16: scheduler.conf must be owned by root:root" in vs
}

test_1_1_17_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.17")
}

test_1_1_17_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/control_plane_confs/2/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"1.1.17: controller-manager.conf mode must be 600 or stricter" in vs
}

test_1_1_17_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/control_plane_confs"}])
	vs := b.violations with input as inp
	"1.1.17: evidence missing — files.control_plane_confs entry for controller-manager.conf not collected" in vs
	not "1.1.17: controller-manager.conf mode must be 600 or stricter" in vs
}

test_1_1_18_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.18")
}

test_1_1_18_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/control_plane_confs/2/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"1.1.18: controller-manager.conf must be owned by root:root" in vs
}

test_1_1_18_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/control_plane_confs"}])
	vs := b.violations with input as inp
	"1.1.18: evidence missing — files.control_plane_confs entry for controller-manager.conf not collected" in vs
	not "1.1.18: controller-manager.conf must be owned by root:root" in vs
}

test_1_1_19_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.19")
}

test_1_1_19_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/pki/0/group", "value": "wheel"}])
	vs := b.violations with input as inp
	"1.1.19: every file and directory under the Kubernetes PKI directory must be owned by root:root" in vs
}

test_1_1_19_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/pki"}])
	vs := b.violations with input as inp
	"1.1.19: evidence missing — files.pki not collected" in vs
	not "1.1.19: every file and directory under the Kubernetes PKI directory must be owned by root:root" in vs
}

test_1_1_20_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.20")
}

test_1_1_20_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/pki/0/mode", "value": "0666"}])
	vs := b.violations with input as inp
	"1.1.20: every Kubernetes PKI .crt file mode must be 644 or stricter" in vs
}

test_1_1_20_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/pki"}])
	vs := b.violations with input as inp
	"1.1.20: evidence missing — files.pki entries ending in .crt not collected" in vs
	not "1.1.20: every Kubernetes PKI .crt file mode must be 644 or stricter" in vs
}

test_1_1_21_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.1.21")
}

test_1_1_21_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/pki/1/mode", "value": "0640"}])
	vs := b.violations with input as inp
	"1.1.21: every Kubernetes PKI .key file mode must be 600 or stricter" in vs
}

test_1_1_21_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/pki"}])
	vs := b.violations with input as inp
	"1.1.21: evidence missing — files.pki entries ending in .key not collected" in vs
	not "1.1.21: every Kubernetes PKI .key file mode must be 600 or stricter" in vs
}

test_1_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.1")
}

test_1_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/anonymous-auth", "value": "true"}])
	vs := b.violations with input as inp
	"1.2.1: anonymous requests to kube-apiserver must be disabled or limited to health endpoints" in vs
}

test_1_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.1: evidence missing — api_server.flags (and api_server.authentication_config when --authentication-config is set) not collected" in vs
	not "1.2.1: anonymous requests to kube-apiserver must be disabled or limited to health endpoints" in vs
}

test_1_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.2")
}

test_1_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/token-auth-file", "value": "/etc/kubernetes/tokens.csv"}])
	vs := b.violations with input as inp
	"1.2.2: kube-apiserver --token-auth-file must be absent" in vs
}

test_1_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.2: evidence missing — api_server.flags not collected" in vs
	not "1.2.2: kube-apiserver --token-auth-file must be absent" in vs
}

test_1_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.3")
}

test_1_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": "NodeRestriction"}])
	vs := b.violations with input as inp
	"1.2.3: kube-apiserver --enable-admission-plugins must list DenyServiceExternalIPs" in vs
}

test_1_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.3: evidence missing — api_server.flags not collected" in vs
	not "1.2.3: kube-apiserver --enable-admission-plugins must list DenyServiceExternalIPs" in vs
}

test_1_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.4")
}

test_1_2_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/kubelet-client-certificate"}])
	vs := b.violations with input as inp
	"1.2.4: kube-apiserver --kubelet-client-certificate and --kubelet-client-key must both be given" in vs
}

test_1_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.4: evidence missing — api_server.flags not collected" in vs
	not "1.2.4: kube-apiserver --kubelet-client-certificate and --kubelet-client-key must both be given" in vs
}

test_1_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.5")
}

test_1_2_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/kubelet-certificate-authority"}])
	vs := b.violations with input as inp
	"1.2.5: kube-apiserver --kubelet-certificate-authority must be given" in vs
}

test_1_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.5: evidence missing — api_server.flags not collected" in vs
	not "1.2.5: kube-apiserver --kubelet-certificate-authority must be given" in vs
}

test_1_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.6")
}

test_1_2_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/authorization-mode", "value": "Node,RBAC,AlwaysAllow"}])
	vs := b.violations with input as inp
	"1.2.6: kube-apiserver --authorization-mode must be given and must exclude AlwaysAllow" in vs
}

test_1_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.6: evidence missing — api_server.flags not collected" in vs
	not "1.2.6: kube-apiserver --authorization-mode must be given and must exclude AlwaysAllow" in vs
}

test_1_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.7")
}

test_1_2_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/authorization-mode", "value": "RBAC"}])
	vs := b.violations with input as inp
	"1.2.7: kube-apiserver --authorization-mode must list Node" in vs
}

test_1_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.7: evidence missing — api_server.flags not collected" in vs
	not "1.2.7: kube-apiserver --authorization-mode must list Node" in vs
}

test_1_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.8")
}

test_1_2_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/authorization-mode", "value": "Node,Webhook"}])
	vs := b.violations with input as inp
	"1.2.8: kube-apiserver --authorization-mode must list RBAC" in vs
}

test_1_2_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.8: evidence missing — api_server.flags not collected" in vs
	not "1.2.8: kube-apiserver --authorization-mode must list RBAC" in vs
}

test_1_2_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.9")
}

test_1_2_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": "NodeRestriction"}])
	vs := b.violations with input as inp
	"1.2.9: kube-apiserver --enable-admission-plugins must list EventRateLimit" in vs
}

test_1_2_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.9: evidence missing — api_server.flags not collected" in vs
	not "1.2.9: kube-apiserver --enable-admission-plugins must list EventRateLimit" in vs
}

test_1_2_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.10")
}

test_1_2_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": "NodeRestriction,AlwaysAdmit"}])
	vs := b.violations with input as inp
	"1.2.10: kube-apiserver --enable-admission-plugins must exclude AlwaysAdmit" in vs
}

test_1_2_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.10: evidence missing — api_server.flags not collected" in vs
	not "1.2.10: kube-apiserver --enable-admission-plugins must exclude AlwaysAdmit" in vs
}

test_1_2_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.11")
}

test_1_2_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": "NodeRestriction"}])
	vs := b.violations with input as inp
	"1.2.11: kube-apiserver --enable-admission-plugins must list AlwaysPullImages" in vs
}

test_1_2_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.11: evidence missing — api_server.flags not collected" in vs
	not "1.2.11: kube-apiserver --enable-admission-plugins must list AlwaysPullImages" in vs
}

test_1_2_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.12")
}

test_1_2_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/disable-admission-plugins", "value": "ServiceAccount"}])
	vs := b.violations with input as inp
	"1.2.12: kube-apiserver --disable-admission-plugins must exclude ServiceAccount" in vs
}

test_1_2_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.12: evidence missing — api_server.flags not collected" in vs
	not "1.2.12: kube-apiserver --disable-admission-plugins must exclude ServiceAccount" in vs
}

test_1_2_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.13")
}

test_1_2_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/disable-admission-plugins", "value": "PodSecurity,NamespaceLifecycle"}])
	vs := b.violations with input as inp
	"1.2.13: kube-apiserver --disable-admission-plugins must exclude NamespaceLifecycle" in vs
}

test_1_2_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.13: evidence missing — api_server.flags not collected" in vs
	not "1.2.13: kube-apiserver --disable-admission-plugins must exclude NamespaceLifecycle" in vs
}

test_1_2_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.14")
}

test_1_2_14_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": "EventRateLimit"}])
	vs := b.violations with input as inp
	"1.2.14: kube-apiserver --enable-admission-plugins must list NodeRestriction" in vs
}

test_1_2_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.14: evidence missing — api_server.flags not collected" in vs
	not "1.2.14: kube-apiserver --enable-admission-plugins must list NodeRestriction" in vs
}

test_1_2_15_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.15")
}

test_1_2_15_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/profiling"}])
	vs := b.violations with input as inp
	"1.2.15: kube-apiserver --profiling must be false" in vs
}

test_1_2_15_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.15: evidence missing — api_server.flags not collected" in vs
	not "1.2.15: kube-apiserver --profiling must be false" in vs
}

test_1_2_16_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.16")
}

test_1_2_16_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/audit-log-path"}])
	vs := b.violations with input as inp
	"1.2.16: kube-apiserver --audit-log-path must be given" in vs
}

test_1_2_16_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.16: evidence missing — api_server.flags not collected" in vs
	not "1.2.16: kube-apiserver --audit-log-path must be given" in vs
}

test_1_2_17_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.17")
}

test_1_2_17_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/audit-log-maxage", "value": "7"}])
	vs := b.violations with input as inp
	"1.2.17: kube-apiserver --audit-log-maxage must be 30 or more" in vs
}

test_1_2_17_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.17: evidence missing — api_server.flags not collected" in vs
	not "1.2.17: kube-apiserver --audit-log-maxage must be 30 or more" in vs
}

test_1_2_18_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.18")
}

test_1_2_18_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/audit-log-maxbackup", "value": "0"}])
	vs := b.violations with input as inp
	"1.2.18: kube-apiserver --audit-log-maxbackup must be 10 or more" in vs
}

test_1_2_18_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.18: evidence missing — api_server.flags not collected" in vs
	not "1.2.18: kube-apiserver --audit-log-maxbackup must be 10 or more" in vs
}

test_1_2_19_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.19")
}

test_1_2_19_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/audit-log-maxsize", "value": "10"}])
	vs := b.violations with input as inp
	"1.2.19: kube-apiserver --audit-log-maxsize must be 100 or more" in vs
}

test_1_2_19_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.19: evidence missing — api_server.flags not collected" in vs
	not "1.2.19: kube-apiserver --audit-log-maxsize must be 100 or more" in vs
}

test_1_2_20_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.20")
}

test_1_2_20_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/request-timeout", "value": "0s"}])
	vs := b.violations with input as inp
	"1.2.20: kube-apiserver --request-timeout must be absent, or a positive duration attested as suitable (attest.api_request_timeout_appropriate)" in vs
}

test_1_2_20_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.20: evidence missing — api_server.flags not collected" in vs
	not "1.2.20: kube-apiserver --request-timeout must be absent, or a positive duration attested as suitable (attest.api_request_timeout_appropriate)" in vs
}

test_1_2_21_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.21")
}

test_1_2_21_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/service-account-lookup", "value": "false"}])
	vs := b.violations with input as inp
	"1.2.21: kube-apiserver --service-account-lookup must be true when given" in vs
}

test_1_2_21_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.21: evidence missing — api_server.flags not collected" in vs
	not "1.2.21: kube-apiserver --service-account-lookup must be true when given" in vs
}

test_1_2_22_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.22")
}

test_1_2_22_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/service-account-key-file"}])
	vs := b.violations with input as inp
	"1.2.22: kube-apiserver --service-account-key-file must be given" in vs
}

test_1_2_22_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.22: evidence missing — api_server.flags not collected" in vs
	not "1.2.22: kube-apiserver --service-account-key-file must be given" in vs
}

test_1_2_23_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.23")
}

test_1_2_23_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/etcd-certfile"}])
	vs := b.violations with input as inp
	"1.2.23: kube-apiserver --etcd-certfile and --etcd-keyfile must both be given" in vs
}

test_1_2_23_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.23: evidence missing — api_server.flags not collected" in vs
	not "1.2.23: kube-apiserver --etcd-certfile and --etcd-keyfile must both be given" in vs
}

test_1_2_24_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.24")
}

test_1_2_24_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/tls-cert-file"}])
	vs := b.violations with input as inp
	"1.2.24: kube-apiserver --tls-cert-file and --tls-private-key-file must both be given" in vs
}

test_1_2_24_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.24: evidence missing — api_server.flags not collected" in vs
	not "1.2.24: kube-apiserver --tls-cert-file and --tls-private-key-file must both be given" in vs
}

test_1_2_25_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.25")
}

test_1_2_25_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/client-ca-file"}])
	vs := b.violations with input as inp
	"1.2.25: kube-apiserver --client-ca-file must be given" in vs
}

test_1_2_25_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.25: evidence missing — api_server.flags not collected" in vs
	not "1.2.25: kube-apiserver --client-ca-file must be given" in vs
}

test_1_2_26_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.26")
}

test_1_2_26_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/etcd-cafile"}])
	vs := b.violations with input as inp
	"1.2.26: kube-apiserver --etcd-cafile must be given" in vs
}

test_1_2_26_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.26: evidence missing — api_server.flags not collected" in vs
	not "1.2.26: kube-apiserver --etcd-cafile must be given" in vs
}

test_1_2_27_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.27")
}

test_1_2_27_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/encryption_config/resources/0/resources", "value": ["configmaps"]}])
	vs := b.violations with input as inp
	"1.2.27: kube-apiserver --encryption-provider-config must be given and the file must cover secrets" in vs
}

test_1_2_27_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.27: evidence missing — api_server.flags (and api_server.encryption_config when --encryption-provider-config is set) not collected" in vs
	not "1.2.27: kube-apiserver --encryption-provider-config must be given and the file must cover secrets" in vs
}

test_1_2_28_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.28")
}

test_1_2_28_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/encryption_config/resources/0/providers", "value": ["identity", "aescbc"]}])
	vs := b.violations with input as inp
	"1.2.28: every EncryptionConfiguration resource entry must write with aescbc, kms or secretbox" in vs
}

test_1_2_28_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.28: evidence missing — api_server.flags (and api_server.encryption_config when --encryption-provider-config is set) not collected" in vs
	not "1.2.28: every EncryptionConfiguration resource entry must write with aescbc, kms or secretbox" in vs
}

test_1_2_29_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.29")
}

test_1_2_29_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/flags/tls-cipher-suites", "value": "TLS_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA"}])
	vs := b.violations with input as inp
	"1.2.29: kube-apiserver --tls-cipher-suites must be given and hold only the strong suites" in vs
}

test_1_2_29_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.29: evidence missing — api_server.flags not collected" in vs
	not "1.2.29: kube-apiserver --tls-cipher-suites must be given and hold only the strong suites" in vs
}

test_1_2_30_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.2.30")
}

test_1_2_30_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags/service-account-extend-token-expiration"}])
	vs := b.violations with input as inp
	"1.2.30: kube-apiserver --service-account-extend-token-expiration must be false" in vs
}

test_1_2_30_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"1.2.30: evidence missing — api_server.flags not collected" in vs
	not "1.2.30: kube-apiserver --service-account-extend-token-expiration must be false" in vs
}

test_1_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.1")
}

test_1_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/controller_manager/flags/terminated-pod-gc-threshold", "value": "0"}])
	vs := b.violations with input as inp
	"1.3.1: kube-controller-manager --terminated-pod-gc-threshold must be given as a positive number" in vs
}

test_1_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.1: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.1: kube-controller-manager --terminated-pod-gc-threshold must be given as a positive number" in vs
}

test_1_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.2")
}

test_1_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/controller_manager/flags/profiling", "value": "true"}])
	vs := b.violations with input as inp
	"1.3.2: kube-controller-manager --profiling must be false" in vs
}

test_1_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.2: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.2: kube-controller-manager --profiling must be false" in vs
}

test_1_3_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.3")
}

test_1_3_3_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags/use-service-account-credentials"}])
	vs := b.violations with input as inp
	"1.3.3: kube-controller-manager --use-service-account-credentials must be true" in vs
}

test_1_3_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.3: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.3: kube-controller-manager --use-service-account-credentials must be true" in vs
}

test_1_3_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.4")
}

test_1_3_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags/service-account-private-key-file"}])
	vs := b.violations with input as inp
	"1.3.4: kube-controller-manager --service-account-private-key-file must be given" in vs
}

test_1_3_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.4: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.4: kube-controller-manager --service-account-private-key-file must be given" in vs
}

test_1_3_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.5")
}

test_1_3_5_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags/root-ca-file"}])
	vs := b.violations with input as inp
	"1.3.5: kube-controller-manager --root-ca-file must be given" in vs
}

test_1_3_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.5: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.5: kube-controller-manager --root-ca-file must be given" in vs
}

test_1_3_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.6")
}

test_1_3_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "RotateKubeletServerCertificate=false"}])
	vs := b.violations with input as inp
	"1.3.6: kube-controller-manager feature gate RotateKubeletServerCertificate must not be switched off" in vs
}

test_1_3_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.6: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.6: kube-controller-manager feature gate RotateKubeletServerCertificate must not be switched off" in vs
}

test_1_3_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.3.7")
}

test_1_3_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/controller_manager/flags/bind-address", "value": "0.0.0.0"}])
	vs := b.violations with input as inp
	"1.3.7: kube-controller-manager --bind-address must be a loopback address" in vs
}

test_1_3_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/controller_manager/flags"}])
	vs := b.violations with input as inp
	"1.3.7: evidence missing — controller_manager.flags not collected" in vs
	not "1.3.7: kube-controller-manager --bind-address must be a loopback address" in vs
}

test_1_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.1")
}

test_1_4_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/scheduler/flags/profiling"}])
	vs := b.violations with input as inp
	"1.4.1: kube-scheduler --profiling must be false" in vs
}

test_1_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/scheduler/flags"}])
	vs := b.violations with input as inp
	"1.4.1: evidence missing — scheduler.flags not collected" in vs
	not "1.4.1: kube-scheduler --profiling must be false" in vs
}

test_1_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "1.4.2")
}

test_1_4_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/scheduler/flags/bind-address"}])
	vs := b.violations with input as inp
	"1.4.2: kube-scheduler --bind-address must be a loopback address" in vs
}

test_1_4_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/scheduler/flags"}])
	vs := b.violations with input as inp
	"1.4.2: evidence missing — scheduler.flags not collected" in vs
	not "1.4.2: kube-scheduler --bind-address must be a loopback address" in vs
}

test_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.1")
}

test_2_1_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags/cert-file"}])
	vs := b.violations with input as inp
	"2.1: etcd --cert-file and --key-file must both be given" in vs
}

test_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.1: evidence missing — etcd.flags not collected" in vs
	not "2.1: etcd --cert-file and --key-file must both be given" in vs
}

test_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.2")
}

test_2_2_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags/client-cert-auth"}])
	vs := b.violations with input as inp
	"2.2: etcd --client-cert-auth must be true" in vs
}

test_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.2: evidence missing — etcd.flags not collected" in vs
	not "2.2: etcd --client-cert-auth must be true" in vs
}

test_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.3")
}

test_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/etcd/flags/auto-tls", "value": "true"}])
	vs := b.violations with input as inp
	"2.3: etcd --auto-tls must not be true" in vs
}

test_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.3: evidence missing — etcd.flags not collected" in vs
	not "2.3: etcd --auto-tls must not be true" in vs
}

test_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.4")
}

test_2_4_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags/peer-key-file"}])
	vs := b.violations with input as inp
	"2.4: etcd --peer-cert-file and --peer-key-file must both be given (single-member etcd excepted)" in vs
}

test_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.4: evidence missing — etcd.flags not collected" in vs
	not "2.4: etcd --peer-cert-file and --peer-key-file must both be given (single-member etcd excepted)" in vs
}

test_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.5")
}

test_2_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/etcd/flags/peer-client-cert-auth", "value": "false"}])
	vs := b.violations with input as inp
	"2.5: etcd --peer-client-cert-auth must be true (single-member etcd excepted)" in vs
}

test_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.5: evidence missing — etcd.flags not collected" in vs
	not "2.5: etcd --peer-client-cert-auth must be true (single-member etcd excepted)" in vs
}

test_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.6")
}

test_2_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/etcd/flags/peer-auto-tls", "value": "true"}])
	vs := b.violations with input as inp
	"2.6: etcd --peer-auto-tls must not be true" in vs
}

test_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.6: evidence missing — etcd.flags not collected" in vs
	not "2.6: etcd --peer-auto-tls must not be true" in vs
}

test_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "2.7")
}

test_2_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/etcd/flags/trusted-ca-file", "value": "/etc/kubernetes/pki/ca.crt"}])
	vs := b.violations with input as inp
	"2.7: etcd --trusted-ca-file must be given and must differ from kube-apiserver --client-ca-file" in vs
}

test_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/etcd/flags"}])
	vs := b.violations with input as inp
	"2.7: evidence missing — etcd.flags / api_server.flags not collected" in vs
	not "2.7: etcd --trusted-ca-file must be given and must differ from kube-apiserver --client-ca-file" in vs
}

test_3_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.1")
}

test_3_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/users_no_client_certificate_auth", "value": false}])
	vs := b.violations with input as inp
	"3.1.1: users must not sign in with client certificates (manual review not attested)" in vs
}

test_3_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/users_no_client_certificate_auth"}])
	vs := b.violations with input as inp
	"3.1.1: users must not sign in with client certificates (manual review not attested)" in vs
}

test_3_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.2")
}

test_3_1_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/users_no_service_account_token_auth", "value": false}])
	vs := b.violations with input as inp
	"3.1.2: users must not sign in with service account tokens (manual review not attested)" in vs
}

test_3_1_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/users_no_service_account_token_auth"}])
	vs := b.violations with input as inp
	"3.1.2: users must not sign in with service account tokens (manual review not attested)" in vs
}

test_3_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.1.3")
}

test_3_1_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/users_no_bootstrap_token_auth", "value": false}])
	vs := b.violations with input as inp
	"3.1.3: users must not sign in with bootstrap tokens (manual review not attested)" in vs
}

test_3_1_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/users_no_bootstrap_token_auth"}])
	vs := b.violations with input as inp
	"3.1.3: users must not sign in with bootstrap tokens (manual review not attested)" in vs
}

test_3_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2.1")
}

test_3_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/api_server/audit_policy/rules", "value": []}])
	vs := b.violations with input as inp
	"3.2.1: kube-apiserver --audit-policy-file must be given and the file must hold a Policy with rules" in vs
}

test_3_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/api_server/flags"}])
	vs := b.violations with input as inp
	"3.2.1: evidence missing — api_server.flags (and api_server.audit_policy when --audit-policy-file is set) not collected" in vs
	not "3.2.1: kube-apiserver --audit-policy-file must be given and the file must hold a Policy with rules" in vs
}

test_3_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "3.2.2")
}

test_3_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/audit_policy_coverage_reviewed", "value": false}])
	vs := b.violations with input as inp
	"3.2.2: the audit policy must be reviewed against the security events it has to record (manual review not attested)" in vs
}

test_3_2_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/audit_policy_coverage_reviewed"}])
	vs := b.violations with input as inp
	"3.2.2: the audit policy must be reviewed against the security events it has to record (manual review not attested)" in vs
}

test_4_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.1")
}

test_4_1_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_service/0/mode", "value": "0666"}])
	vs := b.violations with input as inp
	"4.1.1: every kubelet service unit and drop-in file mode must be 600 or stricter" in vs
}

test_4_1_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_service"}])
	vs := b.violations with input as inp
	"4.1.1: evidence missing — files.kubelet_service not collected" in vs
	not "4.1.1: every kubelet service unit and drop-in file mode must be 600 or stricter" in vs
}

test_4_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.2")
}

test_4_1_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_service/0/group", "value": "wheel"}])
	vs := b.violations with input as inp
	"4.1.2: every kubelet service unit and drop-in file must be owned by root:root" in vs
}

test_4_1_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_service"}])
	vs := b.violations with input as inp
	"4.1.2: evidence missing — files.kubelet_service not collected" in vs
	not "4.1.2: every kubelet service unit and drop-in file must be owned by root:root" in vs
}

test_4_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.3")
}

test_4_1_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kube_proxy_kubeconfig/0/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"4.1.3: kube-proxy kubeconfig mode must be 600 or stricter while kube-proxy runs" in vs
}

test_4_1_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kube_proxy/running"}])
	vs := b.violations with input as inp
	"4.1.3: evidence missing — kube_proxy.running (and files.kube_proxy_kubeconfig when it runs) not collected" in vs
	not "4.1.3: kube-proxy kubeconfig mode must be 600 or stricter while kube-proxy runs" in vs
}

test_4_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.4")
}

test_4_1_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kube_proxy_kubeconfig/0/owner", "value": "kube-proxy"}])
	vs := b.violations with input as inp
	"4.1.4: kube-proxy kubeconfig must be owned by root:root while kube-proxy runs" in vs
}

test_4_1_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kube_proxy_kubeconfig"}])
	vs := b.violations with input as inp
	"4.1.4: evidence missing — kube_proxy.running (and files.kube_proxy_kubeconfig when it runs) not collected" in vs
	not "4.1.4: kube-proxy kubeconfig must be owned by root:root while kube-proxy runs" in vs
}

test_4_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.5")
}

test_4_1_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_kubeconfig/0/mode", "value": "0666"}])
	vs := b.violations with input as inp
	"4.1.5: kubelet kubeconfig mode must be 600 or stricter" in vs
}

test_4_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_kubeconfig"}])
	vs := b.violations with input as inp
	"4.1.5: evidence missing — files.kubelet_kubeconfig not collected" in vs
	not "4.1.5: kubelet kubeconfig mode must be 600 or stricter" in vs
}

test_4_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.6")
}

test_4_1_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_kubeconfig/0/group", "value": "wheel"}])
	vs := b.violations with input as inp
	"4.1.6: kubelet kubeconfig must be owned by root:root" in vs
}

test_4_1_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_kubeconfig"}])
	vs := b.violations with input as inp
	"4.1.6: evidence missing — files.kubelet_kubeconfig not collected" in vs
	not "4.1.6: kubelet kubeconfig must be owned by root:root" in vs
}

test_4_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.7")
}

test_4_1_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_client_ca/0/mode", "value": "0666"}])
	vs := b.violations with input as inp
	"4.1.7: kubelet client CA file mode must be 644 or stricter" in vs
}

test_4_1_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_client_ca"}])
	vs := b.violations with input as inp
	"4.1.7: evidence missing — files.kubelet_client_ca not collected" in vs
	not "4.1.7: kubelet client CA file mode must be 644 or stricter" in vs
}

test_4_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.8")
}

test_4_1_8_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_client_ca/0/group", "value": "wheel"}])
	vs := b.violations with input as inp
	"4.1.8: kubelet client CA file must be owned by root:root" in vs
}

test_4_1_8_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_client_ca"}])
	vs := b.violations with input as inp
	"4.1.8: evidence missing — files.kubelet_client_ca not collected" in vs
	not "4.1.8: kubelet client CA file must be owned by root:root" in vs
}

test_4_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.9")
}

test_4_1_9_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_config_yaml/0/mode", "value": "0644"}])
	vs := b.violations with input as inp
	"4.1.9: kubelet configuration file mode must be 600 or stricter when --config is used" in vs
}

test_4_1_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_config_yaml"}])
	vs := b.violations with input as inp
	"4.1.9: evidence missing — kubelet.flags (and files.kubelet_config_yaml when --config is set) not collected" in vs
	not "4.1.9: kubelet configuration file mode must be 600 or stricter when --config is used" in vs
}

test_4_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.10")
}

test_4_1_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_config_yaml/0/owner", "value": "kube"}])
	vs := b.violations with input as inp
	"4.1.10: kubelet configuration file must be owned by root:root when --config is used" in vs
}

test_4_1_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_config_yaml"}])
	vs := b.violations with input as inp
	"4.1.10: evidence missing — kubelet.flags (and files.kubelet_config_yaml when --config is set) not collected" in vs
	not "4.1.10: kubelet configuration file must be owned by root:root when --config is used" in vs
}

test_4_1_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.1.11")
}

test_4_1_11_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/files/kubelet_config_dir/1/mode", "value": "0664"}])
	vs := b.violations with input as inp
	"4.1.11: kubelet --config-dir directory must be root:root 755 or stricter and its .conf files root:root 644 or stricter" in vs
}

test_4_1_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/files/kubelet_config_dir"}])
	vs := b.violations with input as inp
	"4.1.11: evidence missing — kubelet.flags (and files.kubelet_config_dir with the --config-dir directory when it is set) not collected" in vs
	not "4.1.11: kubelet --config-dir directory must be root:root 755 or stricter and its .conf files root:root 644 or stricter" in vs
}

test_4_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.1")
}

test_4_2_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/authentication/anonymous/enabled", "value": true}])
	vs := b.violations with input as inp
	"4.2.1: kubelet anonymous authentication must be off (--anonymous-auth or authentication.anonymous.enabled)" in vs
}

test_4_2_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.1: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.1: kubelet anonymous authentication must be off (--anonymous-auth or authentication.anonymous.enabled)" in vs
}

test_4_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.2")
}

test_4_2_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/flags/authorization-mode", "value": "AlwaysAllow"}])
	vs := b.violations with input as inp
	"4.2.2: kubelet authorization mode must be given and must not be AlwaysAllow (--authorization-mode or authorization.mode)" in vs
}

test_4_2_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.2: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.2: kubelet authorization mode must be given and must not be AlwaysAllow (--authorization-mode or authorization.mode)" in vs
}

test_4_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.3")
}

test_4_2_3_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/authentication/x509/clientCAFile", "value": ""}])
	vs := b.violations with input as inp
	"4.2.3: kubelet client CA file must be given (--client-ca-file or authentication.x509.clientCAFile)" in vs
}

test_4_2_3_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.3: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.3: kubelet client CA file must be given (--client-ca-file or authentication.x509.clientCAFile)" in vs
}

test_4_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.4")
}

test_4_2_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/readOnlyPort", "value": 10255}])
	vs := b.violations with input as inp
	"4.2.4: kubelet read-only port must be 0 (--read-only-port, or readOnlyPort in the configuration file)" in vs
}

test_4_2_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.4: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.4: kubelet read-only port must be 0 (--read-only-port, or readOnlyPort in the configuration file)" in vs
}

test_4_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.5")
}

test_4_2_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/streamingConnectionIdleTimeout", "value": "0s"}])
	vs := b.violations with input as inp
	"4.2.5: kubelet streaming connection idle timeout must not be 0" in vs
}

test_4_2_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.5: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.5: kubelet streaming connection idle timeout must not be 0" in vs
}

test_4_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.6")
}

test_4_2_6_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/makeIPTablesUtilChains", "value": false}])
	vs := b.violations with input as inp
	"4.2.6: kubelet iptables utility chains must stay on (--make-iptables-util-chains, makeIPTablesUtilChains)" in vs
}

test_4_2_6_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.6: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.6: kubelet iptables utility chains must stay on (--make-iptables-util-chains, makeIPTablesUtilChains)" in vs
}

test_4_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.7")
}

test_4_2_7_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/flags/hostname-override", "value": "node-a"}])
	vs := b.violations with input as inp
	"4.2.7: kubelet --hostname-override must be absent" in vs
}

test_4_2_7_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.7: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.7: kubelet --hostname-override must be absent" in vs
}

test_4_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.8")
}

test_4_2_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/kubelet_event_record_qps_reviewed", "value": false}])
	vs := b.violations with input as inp
	"4.2.8: kubelet eventRecordQPS must be reviewed as suited to the cluster's event volume (manual review not attested)" in vs
}

test_4_2_8_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/kubelet_event_record_qps_reviewed"}])
	vs := b.violations with input as inp
	"4.2.8: kubelet eventRecordQPS must be reviewed as suited to the cluster's event volume (manual review not attested)" in vs
}

test_4_2_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.9")
}

test_4_2_9_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/config/tlsPrivateKeyFile"}])
	vs := b.violations with input as inp
	"4.2.9: kubelet serving certificate and key must be given (--tls-cert-file/--tls-private-key-file or tlsCertFile/tlsPrivateKeyFile)" in vs
}

test_4_2_9_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.9: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.9: kubelet serving certificate and key must be given (--tls-cert-file/--tls-private-key-file or tlsCertFile/tlsPrivateKeyFile)" in vs
}

test_4_2_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.10")
}

test_4_2_10_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/flags/rotate-certificates", "value": "false"}])
	vs := b.violations with input as inp
	"4.2.10: kubelet client certificate rotation must not be switched off (--rotate-certificates, rotateCertificates)" in vs
}

test_4_2_10_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.10: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.10: kubelet client certificate rotation must not be switched off (--rotate-certificates, rotateCertificates)" in vs
}

test_4_2_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.11")
}

test_4_2_11_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/config/serverTLSBootstrap"}])
	vs := b.violations with input as inp
	"4.2.11: kubelet serving certificate rotation must be on (serverTLSBootstrap, --rotate-server-certificates or the RotateKubeletServerCertificate gate)" in vs
}

test_4_2_11_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.11: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.11: kubelet serving certificate rotation must be on (serverTLSBootstrap, --rotate-server-certificates or the RotateKubeletServerCertificate gate)" in vs
}

test_4_2_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.12")
}

test_4_2_12_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/tlsCipherSuites/-", "value": "TLS_RSA_WITH_AES_256_GCM_SHA384"}])
	vs := b.violations with input as inp
	"4.2.12: kubelet TLS cipher suites must be given and hold only the strong suites (--tls-cipher-suites or tlsCipherSuites)" in vs
}

test_4_2_12_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.12: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.12: kubelet TLS cipher suites must be given and hold only the strong suites (--tls-cipher-suites or tlsCipherSuites)" in vs
}

test_4_2_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.13")
}

test_4_2_13_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kubelet/config/podPidsLimit", "value": -1}])
	vs := b.violations with input as inp
	"4.2.13: kubelet pod PID limit must be a positive number (--pod-max-pids or podPidsLimit)" in vs
}

test_4_2_13_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.13: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.13: kubelet pod PID limit must be a positive number (--pod-max-pids or podPidsLimit)" in vs
}

test_4_2_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.2.14")
}

test_4_2_14_fail if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/config/seccompDefault"}])
	vs := b.violations with input as inp
	"4.2.14: kubelet default seccomp profile must be on (--seccomp-default or seccompDefault)" in vs
}

test_4_2_14_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kubelet/flags"}])
	vs := b.violations with input as inp
	"4.2.14: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in vs
	not "4.2.14: kubelet default seccomp profile must be on (--seccomp-default or seccompDefault)" in vs
}

test_4_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "4.3.1")
}

test_4_3_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/kube_proxy/config/metricsBindAddress", "value": "0.0.0.0:10249"}])
	vs := b.violations with input as inp
	"4.3.1: kube-proxy metrics endpoint must bind to loopback only (--metrics-bind-address, metricsBindAddress)" in vs
}

test_4_3_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/kube_proxy/flags"}])
	vs := b.violations with input as inp
	"4.3.1: evidence missing — kube_proxy.running (and kube_proxy.flags, plus kube_proxy.config when --config is set, when it runs) not collected" in vs
	not "4.3.1: kube-proxy metrics endpoint must bind to loopback only (--metrics-bind-address, metricsBindAddress)" in vs
}

test_5_1_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.1")
}

test_5_1_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/cluster_admin_bindings_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.1: every cluster-admin binding must be reviewed as needed (manual review not attested)" in vs
}

test_5_1_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/cluster_admin_bindings_reviewed"}])
	vs := b.violations with input as inp
	"5.1.1: every cluster-admin binding must be reviewed as needed (manual review not attested)" in vs
}

test_5_1_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.2")
}

test_5_1_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/secret_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.2: get, list and watch rights on Secrets must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/secret_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.2: get, list and watch rights on Secrets must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.3")
}

test_5_1_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/rbac_wildcards_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.3: wildcards in Role and ClusterRole rules must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/rbac_wildcards_reviewed"}])
	vs := b.violations with input as inp
	"5.1.3: wildcards in Role and ClusterRole rules must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.4")
}

test_5_1_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/pod_create_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.4: the right to create Pods must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/pod_create_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.4: the right to create Pods must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.5")
}

test_5_1_5_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/service_accounts/default/0/automount_token", "value": true}])
	vs := b.violations with input as inp
	"5.1.5: every namespace's default ServiceAccount must have token automount off and no added role bindings" in vs
}

test_5_1_5_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/service_accounts"}])
	vs := b.violations with input as inp
	"5.1.5: evidence missing — service_accounts.default / collection_status.default_service_accounts not collected" in vs
	not "5.1.5: every namespace's default ServiceAccount must have token automount off and no added role bindings" in vs
}

test_5_1_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.6")
}

test_5_1_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/service_account_token_mounts_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.6: Pods and ServiceAccounts that mount an API token must be reviewed as needing it (manual review not attested)" in vs
}

test_5_1_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/service_account_token_mounts_reviewed"}])
	vs := b.violations with input as inp
	"5.1.6: Pods and ServiceAccounts that mount an API token must be reviewed as needing it (manual review not attested)" in vs
}

test_5_1_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.7")
}

test_5_1_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/system_masters_not_used", "value": false}])
	vs := b.violations with input as inp
	"5.1.7: credentials in the system:masters group must not be in use (manual review not attested)" in vs
}

test_5_1_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/system_masters_not_used"}])
	vs := b.violations with input as inp
	"5.1.7: credentials in the system:masters group must not be in use (manual review not attested)" in vs
}

test_5_1_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.8")
}

test_5_1_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/bind_impersonate_escalate_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.8: bind, impersonate and escalate rights must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_8_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/bind_impersonate_escalate_reviewed"}])
	vs := b.violations with input as inp
	"5.1.8: bind, impersonate and escalate rights must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.9")
}

test_5_1_9_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/persistent_volume_create_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.9: the right to create PersistentVolumes must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_9_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/persistent_volume_create_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.9: the right to create PersistentVolumes must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.10")
}

test_5_1_10_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/node_proxy_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.10: rights on nodes/proxy must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_10_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/node_proxy_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.10: rights on nodes/proxy must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.11")
}

test_5_1_11_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/csr_approval_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.11: rights on certificatesigningrequests/approval must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_11_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/csr_approval_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.11: rights on certificatesigningrequests/approval must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.12")
}

test_5_1_12_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/webhook_config_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.12: rights on validating and mutating webhook configurations must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_12_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/webhook_config_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.12: rights on validating and mutating webhook configurations must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.13")
}

test_5_1_13_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/service_account_token_create_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.13: the right to create serviceaccounts/token must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_13_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/service_account_token_create_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.13: the right to create serviceaccounts/token must be reviewed and kept small (manual review not attested)" in vs
}

test_5_1_14_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.1.14")
}

test_5_1_14_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/kubelet_fine_grained_access_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.1.14: principals bound to nodes/proxy must be reviewed for a move to the fine-grained kubelet subresources (manual review not attested)" in vs
}

test_5_1_14_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/kubelet_fine_grained_access_reviewed"}])
	vs := b.violations with input as inp
	"5.1.14: principals bound to nodes/proxy must be reviewed for a move to the fine-grained kubelet subresources (manual review not attested)" in vs
}

test_5_2_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.1")
}

test_5_2_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/policy_control_mechanism_active", "value": false}])
	vs := b.violations with input as inp
	"5.2.1: a pod admission policy mechanism must be active in the cluster (manual review not attested)" in vs
}

test_5_2_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/policy_control_mechanism_active"}])
	vs := b.violations with input as inp
	"5.2.1: a pod admission policy mechanism must be active in the cluster (manual review not attested)" in vs
}

test_5_2_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.2")
}

test_5_2_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_privileged_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.2: admission policy must keep privileged containers out except where approved (manual review not attested)" in vs
}

test_5_2_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_privileged_restricted"}])
	vs := b.violations with input as inp
	"5.2.2: admission policy must keep privileged containers out except where approved (manual review not attested)" in vs
}

test_5_2_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.3")
}

test_5_2_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_host_pid_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.3: admission policy must keep hostPID pods out except where approved (manual review not attested)" in vs
}

test_5_2_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_host_pid_restricted"}])
	vs := b.violations with input as inp
	"5.2.3: admission policy must keep hostPID pods out except where approved (manual review not attested)" in vs
}

test_5_2_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.4")
}

test_5_2_4_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_host_ipc_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.4: admission policy must keep hostIPC pods out except where approved (manual review not attested)" in vs
}

test_5_2_4_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_host_ipc_restricted"}])
	vs := b.violations with input as inp
	"5.2.4: admission policy must keep hostIPC pods out except where approved (manual review not attested)" in vs
}

test_5_2_5_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.5")
}

test_5_2_5_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_host_network_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.5: admission policy must keep hostNetwork pods out except where approved (manual review not attested)" in vs
}

test_5_2_5_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_host_network_restricted"}])
	vs := b.violations with input as inp
	"5.2.5: admission policy must keep hostNetwork pods out except where approved (manual review not attested)" in vs
}

test_5_2_6_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.6")
}

test_5_2_6_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_privilege_escalation_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.6: admission policy must keep allowPrivilegeEscalation containers out except where approved (manual review not attested)" in vs
}

test_5_2_6_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_privilege_escalation_restricted"}])
	vs := b.violations with input as inp
	"5.2.6: admission policy must keep allowPrivilegeEscalation containers out except where approved (manual review not attested)" in vs
}

test_5_2_7_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.7")
}

test_5_2_7_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_root_containers_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.7: admission policy must keep containers running as UID 0 out except where approved (manual review not attested)" in vs
}

test_5_2_7_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_root_containers_restricted"}])
	vs := b.violations with input as inp
	"5.2.7: admission policy must keep containers running as UID 0 out except where approved (manual review not attested)" in vs
}

test_5_2_8_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.8")
}

test_5_2_8_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_net_raw_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.8: admission policy must keep the NET_RAW capability out except where approved (manual review not attested)" in vs
}

test_5_2_8_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_net_raw_restricted"}])
	vs := b.violations with input as inp
	"5.2.8: admission policy must keep the NET_RAW capability out except where approved (manual review not attested)" in vs
}

test_5_2_9_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.9")
}

test_5_2_9_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_capabilities_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.9: admission policy must require containers to drop capabilities except where approved (manual review not attested)" in vs
}

test_5_2_9_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_capabilities_restricted"}])
	vs := b.violations with input as inp
	"5.2.9: admission policy must require containers to drop capabilities except where approved (manual review not attested)" in vs
}

test_5_2_10_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.10")
}

test_5_2_10_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_windows_host_process_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.10: admission policy must keep Windows hostProcess containers out except where approved (manual review not attested)" in vs
}

test_5_2_10_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_windows_host_process_restricted"}])
	vs := b.violations with input as inp
	"5.2.10: admission policy must keep Windows hostProcess containers out except where approved (manual review not attested)" in vs
}

test_5_2_11_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.11")
}

test_5_2_11_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_host_path_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.11: admission policy must keep hostPath volumes out except where approved (manual review not attested)" in vs
}

test_5_2_11_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_host_path_restricted"}])
	vs := b.violations with input as inp
	"5.2.11: admission policy must keep hostPath volumes out except where approved (manual review not attested)" in vs
}

test_5_2_12_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.12")
}

test_5_2_12_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_host_ports_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.12: admission policy must keep hostPort use out except where approved (manual review not attested)" in vs
}

test_5_2_12_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_host_ports_restricted"}])
	vs := b.violations with input as inp
	"5.2.12: admission policy must keep hostPort use out except where approved (manual review not attested)" in vs
}

test_5_2_13_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.2.13")
}

test_5_2_13_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/admission_proc_mount_restricted", "value": false}])
	vs := b.violations with input as inp
	"5.2.13: admission policy must keep unmasked procMount containers out except where approved (manual review not attested)" in vs
}

test_5_2_13_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/admission_proc_mount_restricted"}])
	vs := b.violations with input as inp
	"5.2.13: admission policy must keep unmasked procMount containers out except where approved (manual review not attested)" in vs
}

test_5_3_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3.1")
}

test_5_3_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/cni_enforces_network_policies", "value": false}])
	vs := b.violations with input as inp
	"5.3.1: the CNI plugin in use must enforce ingress and egress NetworkPolicy (manual review not attested)" in vs
}

test_5_3_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/cni_enforces_network_policies"}])
	vs := b.violations with input as inp
	"5.3.1: the CNI plugin in use must enforce ingress and egress NetworkPolicy (manual review not attested)" in vs
}

test_5_3_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.3.2")
}

test_5_3_2_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/network_policies/namespaces_without_policy/-", "value": "payments"}])
	vs := b.violations with input as inp
	"5.3.2: every namespace must have at least one NetworkPolicy" in vs
}

test_5_3_2_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/collection_status/network_policies"}])
	vs := b.violations with input as inp
	"5.3.2: evidence missing — network_policies.namespaces_without_policy / collection_status.network_policies not collected" in vs
	not "5.3.2: every namespace must have at least one NetworkPolicy" in vs
}

test_5_4_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.4.1")
}

test_5_4_1_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/secrets/env_var_usage_count", "value": 3}])
	vs := b.violations with input as inp
	"5.4.1: workloads must not read Secrets through environment variables" in vs
}

test_5_4_1_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/secrets"}])
	vs := b.violations with input as inp
	"5.4.1: evidence missing — secrets.env_var_usage_count / collection_status.secret_env_scan not collected" in vs
	not "5.4.1: workloads must not read Secrets through environment variables" in vs
}

test_5_4_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.4.2")
}

test_5_4_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/external_secret_storage_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.4.2: an external secret store must be evaluated and the decision recorded (manual review not attested)" in vs
}

test_5_4_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/external_secret_storage_reviewed"}])
	vs := b.violations with input as inp
	"5.4.2: an external secret store must be evaluated and the decision recorded (manual review not attested)" in vs
}

test_5_5_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.5.1")
}

test_5_5_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/image_provenance_configured", "value": false}])
	vs := b.violations with input as inp
	"5.5.1: image provenance admission control must be in place and reviewed (manual review not attested)" in vs
}

test_5_5_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/image_provenance_configured"}])
	vs := b.violations with input as inp
	"5.5.1: image provenance admission control must be in place and reviewed (manual review not attested)" in vs
}

test_5_6_1_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6.1")
}

test_5_6_1_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/namespace_boundaries_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.6.1: namespaces must be reviewed as the administrative boundaries in use (manual review not attested)" in vs
}

test_5_6_1_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/namespace_boundaries_reviewed"}])
	vs := b.violations with input as inp
	"5.6.1: namespaces must be reviewed as the administrative boundaries in use (manual review not attested)" in vs
}

test_5_6_2_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6.2")
}

test_5_6_2_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/pod_seccomp_profiles_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.6.2: pod definitions must be reviewed for the RuntimeDefault seccomp profile (manual review not attested)" in vs
}

test_5_6_2_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/pod_seccomp_profiles_reviewed"}])
	vs := b.violations with input as inp
	"5.6.2: pod definitions must be reviewed for the RuntimeDefault seccomp profile (manual review not attested)" in vs
}

test_5_6_3_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6.3")
}

test_5_6_3_fail if {
	inp := json.patch(green, [{"op": "replace", "path": "/attest/pod_security_contexts_reviewed", "value": false}])
	vs := b.violations with input as inp
	"5.6.3: pod and container security contexts must be reviewed (manual review not attested)" in vs
}

test_5_6_3_not_attested_when_absent if {
	inp := json.patch(green, [{"op": "remove", "path": "/attest/pod_security_contexts_reviewed"}])
	vs := b.violations with input as inp
	"5.6.3: pod and container security contexts must be reviewed (manual review not attested)" in vs
}

test_5_6_4_pass if {
	vs := b.violations with input as green
	not _has_id(vs, "5.6.4")
}

test_5_6_4_fail if {
	inp := json.patch(green, [{"op": "add", "path": "/cluster/namespace_resources/default/-", "value": "pod/debug"}])
	vs := b.violations with input as inp
	"5.6.4: the default namespace must hold nothing but the kubernetes Service" in vs
}

test_5_6_4_evidence_missing if {
	inp := json.patch(green, [{"op": "remove", "path": "/collection_status"}])
	vs := b.violations with input as inp
	"5.6.4: evidence missing — cluster.namespace_resources.default / collection_status.namespace_resources not collected" in vs
	not "5.6.4: the default namespace must hold nothing but the kubernetes Service" in vs
}
