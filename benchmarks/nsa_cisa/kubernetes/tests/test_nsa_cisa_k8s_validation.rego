# Per-rule unit tests for nsa_cisa_k8s_validation.rego (NSA/CISA Kubernetes
# Hardening Guidance v1.2, 43 controls). One test per violation rule, one
# fully-compliant test, and one report-shape test on empty input.
#
# Strategy: base_input has every fact set to true (fully compliant). Each test
# json.patches exactly one fact to false and asserts (a) exactly one violation
# fires and (b) that rule's exact message is present. Exactly-one-violation is
# the strong assertion that isolates the rule under test.
#
# Shares package nsa_cisa_k8s.main_test with test_nsa_cisa_k8s.rego; all rule
# names here are distinct from that file's to avoid collisions.

package nsa_cisa_k8s.main_test

import data.nsa_cisa_k8s.main
import rego.v1

base_input := {
	"cluster_name": "prod-cluster",
	"assessment_date": "2026-09-17",
	"nsa_cisa": {
		"pod_security": {
			"nonroot_containers": true,
			"readonly_root_filesystems": true,
			"image_scanning_in_pipeline": true,
			"privileged_containers_prevented": true,
			"host_namespaces_denied": true,
			"hostpath_denied": true,
			"root_execution_rejected": true,
			"kernel_hardening_applied": true,
			"pod_security_admission_enforced": true,
			"trusted_registries_enforced": true,
			"image_signature_verification": true,
			"sa_token_automount_disabled_where_unneeded": true,
		},
		"network": {
			"control_plane_firewalled": true,
			"control_plane_separate_network": true,
			"etcd_access_limited": true,
			"control_plane_tls": true,
			"etcd_encrypted_at_rest": true,
			"etcd_dedicated_tls": true,
			"namespaces_partition_resources": true,
			"network_policies_defined": true,
			"default_deny_policy": true,
			"resource_limits_enforced": true,
			"secrets_encrypted_not_in_config": true,
			"api_server_not_internet_exposed": true,
			"traffic_tls12_plus": true,
			"cloud_metadata_access_blocked": true,
		},
		"authn_authz": {
			"anonymous_auth_disabled": true,
			"strong_user_authentication": true,
			"rbac_enabled": true,
			"least_privilege_roles": true,
			"kubelet_anonymous_disabled": true,
			"kubelet_client_tls_auth": true,
		},
		"logging": {
			"audit_logging_enabled": true,
			"audit_policy_configured": true,
			"logs_survive_node_failure": true,
			"logs_aggregated_externally": true,
			"monitoring_alerting_configured": true,
			"pod_baselines_established": true,
			"rbac_periodically_audited": true,
		},
		"updates": {
			"patches_promptly_applied": true,
			"periodic_scans_and_pentests": true,
			"unused_components_removed": true,
			"cis_benchmark_adherence": true,
		},
	},
}

# violations_when_false flips a single fact to false and returns the violation set.
violations_when_false(path) := v if {
	bad := json.patch(base_input, [{"op": "replace", "path": path, "value": false}])
	v := main.violations with input as bad
}

# ── Section 1 — Kubernetes Pod security (12) ─────────────────────────────────

test_ps_nonroot_containers if {
	v := violations_when_false("/nsa_cisa/pod_security/nonroot_containers")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Containers are not built/forced to run as non-root users" in v
}

test_ps_readonly_root_filesystems if {
	v := violations_when_false("/nsa_cisa/pod_security/readonly_root_filesystems")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Containers do not run with immutable (read-only) root filesystems where possible" in v
}

test_ps_image_scanning_in_pipeline if {
	v := violations_when_false("/nsa_cisa/pod_security/image_scanning_in_pipeline")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Container images are not scanned for vulnerabilities or misconfigurations throughout the build workflow" in v
}

test_ps_privileged_containers_prevented if {
	v := violations_when_false("/nsa_cisa/pod_security/privileged_containers_prevented")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Privileged containers are not prevented by a technical control" in v
}

test_ps_host_namespaces_denied if {
	v := violations_when_false("/nsa_cisa/pod_security/host_namespaces_denied")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Breakout-prone features (hostPID, hostIPC, hostNetwork) are not denied" in v
}

test_ps_hostpath_denied if {
	v := violations_when_false("/nsa_cisa/pod_security/hostpath_denied")
	count(v) == 1
	"NSA-K8S 1 (Pod security): hostPath volume mounts are not denied" in v
}

test_ps_root_execution_rejected if {
	v := violations_when_false("/nsa_cisa/pod_security/root_execution_rejected")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Containers executing as root or allowing elevation to root are not rejected" in v
}

test_ps_kernel_hardening_applied if {
	v := violations_when_false("/nsa_cisa/pod_security/kernel_hardening_applied")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Kernel-level hardening (SELinux, AppArmor, seccomp) is not applied to workloads" in v
}

test_ps_pod_security_admission_enforced if {
	v := violations_when_false("/nsa_cisa/pod_security/pod_security_admission_enforced")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Pod Security Admission (baseline or stricter) is not enforced cluster-wide" in v
}

test_ps_trusted_registries_enforced if {
	v := violations_when_false("/nsa_cisa/pod_security/trusted_registries_enforced")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Deployments are not restricted to trusted image registries" in v
}

test_ps_image_signature_verification if {
	v := violations_when_false("/nsa_cisa/pod_security/image_signature_verification")
	count(v) == 1
	"NSA-K8S 1 (Pod security): Only digitally signed images are not enforced via admission control" in v
}

test_ps_sa_token_automount_disabled_where_unneeded if {
	v := violations_when_false("/nsa_cisa/pod_security/sa_token_automount_disabled_where_unneeded")
	count(v) == 1
	"NSA-K8S 1 (Pod security): automountServiceAccountToken is not set to false for Pods that do not need API access" in v
}

# ── Section 2 — Network separation and hardening (14) ────────────────────────

test_net_control_plane_firewalled if {
	v := violations_when_false("/nsa_cisa/network/control_plane_firewalled")
	count(v) == 1
	"NSA-K8S 2 (Network): Access to control plane nodes is not locked down with a firewall and RBAC" in v
}

test_net_control_plane_separate_network if {
	v := violations_when_false("/nsa_cisa/network/control_plane_separate_network")
	count(v) == 1
	"NSA-K8S 2 (Network): Control plane components and worker nodes do not use separate networks" in v
}

test_net_etcd_access_limited if {
	v := violations_when_false("/nsa_cisa/network/etcd_access_limited")
	count(v) == 1
	"NSA-K8S 2 (Network): Access to the etcd server is not further limited (dedicated node, firewall restricted to API servers)" in v
}

test_net_control_plane_tls if {
	v := violations_when_false("/nsa_cisa/network/control_plane_tls")
	count(v) == 1
	"NSA-K8S 2 (Network): Control plane components do not use authenticated, TLS-encrypted communications" in v
}

test_net_etcd_encrypted_at_rest if {
	v := violations_when_false("/nsa_cisa/network/etcd_encrypted_at_rest")
	count(v) == 1
	"NSA-K8S 2 (Network): etcd is not encrypted at rest" in v
}

test_net_etcd_dedicated_tls if {
	v := violations_when_false("/nsa_cisa/network/etcd_dedicated_tls")
	count(v) == 1
	"NSA-K8S 2 (Network): etcd does not use a separate TLS certificate (and trusts more than the API server certificates)" in v
}

test_net_namespaces_partition_resources if {
	v := violations_when_false("/nsa_cisa/network/namespaces_partition_resources")
	count(v) == 1
	"NSA-K8S 2 (Network): Namespaces are not used to partition resources (or user Pods run in kube-system/kube-public)" in v
}

test_net_network_policies_defined if {
	v := violations_when_false("/nsa_cisa/network/network_policies_defined")
	count(v) == 1
	"NSA-K8S 2 (Network): Network policies isolating resources are not defined (CNI must support the NetworkPolicy API)" in v
}

test_net_default_deny_policy if {
	v := violations_when_false("/nsa_cisa/network/default_deny_policy")
	count(v) == 1
	"NSA-K8S 2 (Network): No explicit default-deny (ingress and egress) network policy exists" in v
}

test_net_resource_limits_enforced if {
	v := violations_when_false("/nsa_cisa/network/resource_limits_enforced")
	count(v) == 1
	"NSA-K8S 2 (Network): LimitRange / ResourceQuota / PID limits are not enforced to prevent resource exhaustion" in v
}

test_net_secrets_encrypted_not_in_config if {
	v := violations_when_false("/nsa_cisa/network/secrets_encrypted_not_in_config")
	count(v) == 1
	"NSA-K8S 2 (Network): Credentials are kept in configuration files, or Kubernetes Secrets are not encrypted with a strong method (they are not encrypted by default)" in v
}

test_net_api_server_not_internet_exposed if {
	v := violations_when_false("/nsa_cisa/network/api_server_not_internet_exposed")
	count(v) == 1
	"NSA-K8S 2 (Network): The API server (port 6443) is exposed to the internet or untrusted networks" in v
}

test_net_traffic_tls12_plus if {
	v := violations_when_false("/nsa_cisa/network/traffic_tls12_plus")
	count(v) == 1
	"NSA-K8S 2 (Network): Cluster traffic is not encrypted with TLS 1.2 or 1.3 throughout" in v
}

test_net_cloud_metadata_access_blocked if {
	v := violations_when_false("/nsa_cisa/network/cloud_metadata_access_blocked")
	count(v) == 1
	"NSA-K8S 2 (Network): Pods can reach the cloud instance metadata service (privilege-escalation vector)" in v
}

# ── Section 3 — Authentication and authorization (6) ─────────────────────────

test_authz_anonymous_auth_disabled if {
	v := violations_when_false("/nsa_cisa/authn_authz/anonymous_auth_disabled")
	count(v) == 1
	"NSA-K8S 3 (AuthN/AuthZ): API server anonymous authentication is not disabled (--anonymous-auth=false)" in v
}

test_authz_strong_user_authentication if {
	v := violations_when_false("/nsa_cisa/authn_authz/strong_user_authentication")
	count(v) == 1
	"NSA-K8S 3 (AuthN/AuthZ): Strong user authentication is not implemented (or weak methods like static password files are in use)" in v
}

test_authz_rbac_enabled if {
	v := violations_when_false("/nsa_cisa/authn_authz/rbac_enabled")
	count(v) == 1
	"NSA-K8S 3 (AuthN/AuthZ): RBAC is not enabled (--authorization-mode=RBAC), or AlwaysAllow is in effect" in v
}

test_authz_least_privilege_roles if {
	v := violations_when_false("/nsa_cisa/authn_authz/least_privilege_roles")
	count(v) == 1
	"NSA-K8S 3 (AuthN/AuthZ): RBAC policies with unique least-privilege roles per users, administrators, developers, service accounts, and infrastructure team are not in place" in v
}

test_authz_kubelet_anonymous_disabled if {
	v := violations_when_false("/nsa_cisa/authn_authz/kubelet_anonymous_disabled")
	count(v) == 1
	"NSA-K8S 3 (AuthN/AuthZ): Anonymous access to the kubelet service is not disabled" in v
}

test_authz_kubelet_client_tls_auth if {
	v := violations_when_false("/nsa_cisa/authn_authz/kubelet_client_tls_auth")
	count(v) == 1
	"NSA-K8S 3 (AuthN/AuthZ): Kubelet client TLS authentication is not enforced" in v
}

# ── Section 4 — Audit logging and threat detection (7) ───────────────────────

test_log_audit_logging_enabled if {
	v := violations_when_false("/nsa_cisa/logging/audit_logging_enabled")
	count(v) == 1
	"NSA-K8S 4 (Logging): Kubernetes audit logging is not enabled (it is disabled by default)" in v
}

test_log_audit_policy_configured if {
	v := violations_when_false("/nsa_cisa/logging/audit_policy_configured")
	count(v) == 1
	"NSA-K8S 4 (Logging): No audit policy is configured (security-critical events at RequestResponse; requests involving Secrets reduced to Metadata level)" in v
}

test_log_logs_survive_node_failure if {
	v := violations_when_false("/nsa_cisa/logging/logs_survive_node_failure")
	count(v) == 1
	"NSA-K8S 4 (Logging): Logs are not persisted to survive node, Pod, or container failure" in v
}

test_log_logs_aggregated_externally if {
	v := violations_when_false("/nsa_cisa/logging/logs_aggregated_externally")
	count(v) == 1
	"NSA-K8S 4 (Logging): Logs are not aggregated external to the cluster (TLS 1.2/1.3 in transit, append-only forwarder access)" in v
}

test_log_monitoring_alerting_configured if {
	v := violations_when_false("/nsa_cisa/logging/monitoring_alerting_configured")
	count(v) == 1
	"NSA-K8S 4 (Logging): No log monitoring and alerting system (SIEM or equivalent) is tailored to the cluster" in v
}

test_log_pod_baselines_established if {
	v := violations_when_false("/nsa_cisa/logging/pod_baselines_established")
	count(v) == 1
	"NSA-K8S 4 (Logging): Pod behavioral baselines (network, requests, resource consumption) are not established at creation for anomaly detection" in v
}

test_log_rbac_periodically_audited if {
	v := violations_when_false("/nsa_cisa/logging/rbac_periodically_audited")
	count(v) == 1
	"NSA-K8S 4 (Logging): RBAC policy configuration is not periodically reviewed (and on personnel changes)" in v
}

# ── Section 5 — Upgrading and application security practices (4) ──────────────

test_upd_patches_promptly_applied if {
	v := violations_when_false("/nsa_cisa/updates/patches_promptly_applied")
	count(v) == 1
	"NSA-K8S 5 (Upgrading): Security patches and updates are not promptly applied (Kubernetes, hosts, hypervisors, plugins, CI/CD elements)" in v
}

test_upd_periodic_scans_and_pentests if {
	v := violations_when_false("/nsa_cisa/updates/periodic_scans_and_pentests")
	count(v) == 1
	"NSA-K8S 5 (Upgrading): Periodic vulnerability scans and penetration tests are not performed" in v
}

test_upd_unused_components_removed if {
	v := violations_when_false("/nsa_cisa/updates/unused_components_removed")
	count(v) == 1
	"NSA-K8S 5 (Upgrading): Unused components are not uninstalled and deleted from the environment" in v
}

test_upd_cis_benchmark_adherence if {
	v := violations_when_false("/nsa_cisa/updates/cis_benchmark_adherence")
	count(v) == 1
	"NSA-K8S 5 (Upgrading): CIS benchmarks for Kubernetes and system components are not adhered to / periodically verified" in v
}

# ── Compliant input — empty violation set ────────────────────────────────────

test_all_facts_true_no_violations if {
	v := main.violations with input as base_input
	count(v) == 0
}

# ── Report shape on empty input ──────────────────────────────────────────────

test_report_populated_object_on_empty_input if {
	result := main.compliance_report with input as {}
	is_object(result)
	count(result) > 0
}
