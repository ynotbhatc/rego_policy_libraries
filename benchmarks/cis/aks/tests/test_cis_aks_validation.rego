# Unit tests for benchmarks/cis/aks/cis_aks_validation.rego
# CIS Azure AKS Benchmark v1.8.0 — 56 controls.
#
# Strategy: build one fully-compliant input (every fact true), then for each
# violation rule flip exactly one field to false via a deep merge and assert
# that precisely that one control's message fires. Plus a compliant-input test
# (empty violation set) and an empty-input test (populated report, 56 violations).

package cis_aks.main_test

import rego.v1

import data.cis_aks.main

# ── Fully-compliant fixture: every fact affirmatively true ────────────────────

compliant_input := {"cis_aks": {
	"control_plane": {"audit_logging_enabled": true},
	"node_files": {
		"kubeconfig_perms_restricted": true,
		"kubeconfig_owner_root": true,
		"kubelet_config_perms_restricted": true,
		"kubelet_config_owner_root": true,
	},
	"kubelet": {
		"anonymous_auth_disabled": true,
		"authorization_mode_not_always_allow": true,
		"client_ca_file_configured": true,
		"read_only_port_secured": true,
		"streaming_idle_timeout_nonzero": true,
		"protect_kernel_defaults_enabled": true,
		"make_iptables_util_chains_enabled": true,
		"hostname_override_not_set": true,
		"event_record_qps_appropriate": true,
		"rotate_certificates_enabled": true,
		"rotate_server_certificates_enabled": true,
	},
	"rbac": {
		"cluster_admin_usage_minimized": true,
		"secrets_access_minimized": true,
		"wildcard_use_minimized": true,
		"pod_create_access_minimized": true,
		"default_service_accounts_inactive": true,
		"sa_token_mounts_minimized": true,
		"node_proxy_access_minimized": true,
		"csr_approval_access_minimized": true,
		"webhook_config_access_minimized": true,
		"sa_token_creation_minimized": true,
	},
	"pod_security": {
		"privileged_containers_minimized": true,
		"host_pid_sharing_minimized": true,
		"host_ipc_sharing_minimized": true,
		"host_network_sharing_minimized": true,
		"privilege_escalation_minimized": true,
		"root_containers_minimized": true,
		"added_capabilities_minimized": true,
		"assigned_capabilities_minimized": true,
	},
	"network": {
		"latest_cni_version_used": true,
		"all_namespaces_have_network_policies": true,
	},
	"secrets": {
		"secrets_as_files_preferred": true,
		"external_secret_storage_considered": true,
	},
	"general": {
		"namespace_boundaries_used": true,
		"security_context_applied": true,
		"default_namespace_not_used": true,
	},
	"images": {
		"vulnerability_scanning_enabled": true,
		"acr_cluster_access_readonly": true,
		"acr_user_access_minimized": true,
		"registries_limited_to_approved": true,
	},
	"managed": {
		"dedicated_service_accounts_preferred": true,
		"azure_rbac_for_kubernetes_authz": true,
		"secrets_encrypted": true,
		"control_plane_endpoint_restricted": true,
		"private_endpoint_only": true,
		"private_nodes": true,
		"network_policy_enabled": true,
		"https_lb_tls_encrypted": true,
		"azure_ad_rbac_managed": true,
		"untrusted_workloads_restricted": true,
		"hostile_multitenant_isolated": true,
	},
}}

# Deep-merge helper: compliant input with exactly one field flipped to false.
override(group, field) := object.union(compliant_input, {"cis_aks": {group: {field: false}}})

# ── 2 Control Plane ───────────────────────────────────────────────────────────

test_2_1_1_audit_logging if {
	v := main.violations with input as override("control_plane", "audit_logging_enabled")
	count(v) == 1
	"CIS AKS 2.1.1: Control plane audit logging is not enabled" in v
}

# ── 3.1 Worker node configuration files ───────────────────────────────────────

test_3_1_1_kubeconfig_perms if {
	v := main.violations with input as override("node_files", "kubeconfig_perms_restricted")
	count(v) == 1
	"CIS AKS 3.1.1: kubeconfig file permissions are more permissive than 644" in v
}

test_3_1_2_kubeconfig_owner if {
	v := main.violations with input as override("node_files", "kubeconfig_owner_root")
	count(v) == 1
	"CIS AKS 3.1.2: kubelet kubeconfig file is not owned by root:root" in v
}

test_3_1_3_kubelet_config_perms if {
	v := main.violations with input as override("node_files", "kubelet_config_perms_restricted")
	count(v) == 1
	"CIS AKS 3.1.3: kubelet configuration file permissions are more permissive than 644" in v
}

test_3_1_4_kubelet_config_owner if {
	v := main.violations with input as override("node_files", "kubelet_config_owner_root")
	count(v) == 1
	"CIS AKS 3.1.4: kubelet configuration file is not owned by root:root" in v
}

# ── 3.2 Kubelet ───────────────────────────────────────────────────────────────

test_3_2_1_anonymous_auth if {
	v := main.violations with input as override("kubelet", "anonymous_auth_disabled")
	count(v) == 1
	"CIS AKS 3.2.1: Kubelet --anonymous-auth is not set to false" in v
}

test_3_2_2_authorization_mode if {
	v := main.violations with input as override("kubelet", "authorization_mode_not_always_allow")
	count(v) == 1
	"CIS AKS 3.2.2: Kubelet --authorization-mode allows all requests (AlwaysAllow)" in v
}

test_3_2_3_client_ca_file if {
	v := main.violations with input as override("kubelet", "client_ca_file_configured")
	count(v) == 1
	"CIS AKS 3.2.3: Kubelet --client-ca-file is not set" in v
}

test_3_2_4_read_only_port if {
	v := main.violations with input as override("kubelet", "read_only_port_secured")
	count(v) == 1
	"CIS AKS 3.2.4: Kubelet read-only port is not secured (disabled)" in v
}

test_3_2_5_streaming_idle_timeout if {
	v := main.violations with input as override("kubelet", "streaming_idle_timeout_nonzero")
	count(v) == 1
	"CIS AKS 3.2.5: Kubelet --streaming-connection-idle-timeout is set to 0 (disabled)" in v
}

test_3_2_6_protect_kernel_defaults if {
	v := main.violations with input as override("kubelet", "protect_kernel_defaults_enabled")
	count(v) == 1
	"CIS AKS 3.2.6: Kubelet --protect-kernel-defaults is not set to true" in v
}

test_3_2_7_make_iptables_util_chains if {
	v := main.violations with input as override("kubelet", "make_iptables_util_chains_enabled")
	count(v) == 1
	"CIS AKS 3.2.7: Kubelet --make-iptables-util-chains is not set to true" in v
}

test_3_2_8_hostname_override if {
	v := main.violations with input as override("kubelet", "hostname_override_not_set")
	count(v) == 1
	"CIS AKS 3.2.8: Kubelet --hostname-override is set, breaking node identity verification" in v
}

test_3_2_9_event_record_qps if {
	v := main.violations with input as override("kubelet", "event_record_qps_appropriate")
	count(v) == 1
	"CIS AKS 3.2.9: Kubelet --eventRecordQPS is not set to an appropriate event capture level" in v
}

test_3_2_10_rotate_certificates if {
	v := main.violations with input as override("kubelet", "rotate_certificates_enabled")
	count(v) == 1
	"CIS AKS 3.2.10: Kubelet client certificate rotation is disabled (--rotate-certificates false)" in v
}

test_3_2_11_rotate_server_certificates if {
	v := main.violations with input as override("kubelet", "rotate_server_certificates_enabled")
	count(v) == 1
	"CIS AKS 3.2.11: Kubelet RotateKubeletServerCertificate is not set to true" in v
}

# ── 4.1 RBAC and service accounts ─────────────────────────────────────────────

test_4_1_1_cluster_admin if {
	v := main.violations with input as override("rbac", "cluster_admin_usage_minimized")
	count(v) == 1
	"CIS AKS 4.1.1: cluster-admin role is bound beyond where it is required" in v
}

test_4_1_2_secrets_access if {
	v := main.violations with input as override("rbac", "secrets_access_minimized")
	count(v) == 1
	"CIS AKS 4.1.2: Access to secrets is not minimized" in v
}

test_4_1_3_wildcard_use if {
	v := main.violations with input as override("rbac", "wildcard_use_minimized")
	count(v) == 1
	"CIS AKS 4.1.3: Wildcards are used in Roles or ClusterRoles" in v
}

test_4_1_4_pod_create_access if {
	v := main.violations with input as override("rbac", "pod_create_access_minimized")
	count(v) == 1
	"CIS AKS 4.1.4: Access to create pods is not minimized" in v
}

test_4_1_5_default_service_accounts if {
	v := main.violations with input as override("rbac", "default_service_accounts_inactive")
	count(v) == 1
	"CIS AKS 4.1.5: Default service accounts are actively used" in v
}

test_4_1_6_sa_token_mounts if {
	v := main.violations with input as override("rbac", "sa_token_mounts_minimized")
	count(v) == 1
	"CIS AKS 4.1.6: Service account tokens are mounted in pods that do not need them" in v
}

test_4_1_9_node_proxy_access if {
	v := main.violations with input as override("rbac", "node_proxy_access_minimized")
	count(v) == 1
	"CIS AKS 4.1.9: Access to the proxy sub-resource of nodes is not minimized" in v
}

test_4_1_10_csr_approval_access if {
	v := main.violations with input as override("rbac", "csr_approval_access_minimized")
	count(v) == 1
	"CIS AKS 4.1.10: Access to the approval sub-resource of certificatesigningrequests is not minimized" in v
}

test_4_1_11_webhook_config_access if {
	v := main.violations with input as override("rbac", "webhook_config_access_minimized")
	count(v) == 1
	"CIS AKS 4.1.11: Access to webhook configuration objects is not minimized" in v
}

test_4_1_12_sa_token_creation if {
	v := main.violations with input as override("rbac", "sa_token_creation_minimized")
	count(v) == 1
	"CIS AKS 4.1.12: Access to service account token creation is not minimized" in v
}

# ── 4.2 Pod security ──────────────────────────────────────────────────────────

test_4_2_1_privileged_containers if {
	v := main.violations with input as override("pod_security", "privileged_containers_minimized")
	count(v) == 1
	"CIS AKS 4.2.1: Admission of privileged containers is not minimized" in v
}

test_4_2_2_host_pid if {
	v := main.violations with input as override("pod_security", "host_pid_sharing_minimized")
	count(v) == 1
	"CIS AKS 4.2.2: Admission of containers sharing the host PID namespace is not minimized" in v
}

test_4_2_3_host_ipc if {
	v := main.violations with input as override("pod_security", "host_ipc_sharing_minimized")
	count(v) == 1
	"CIS AKS 4.2.3: Admission of containers sharing the host IPC namespace is not minimized" in v
}

test_4_2_4_host_network if {
	v := main.violations with input as override("pod_security", "host_network_sharing_minimized")
	count(v) == 1
	"CIS AKS 4.2.4: Admission of containers sharing the host network namespace is not minimized" in v
}

test_4_2_5_privilege_escalation if {
	v := main.violations with input as override("pod_security", "privilege_escalation_minimized")
	count(v) == 1
	"CIS AKS 4.2.5: Admission of containers with allowPrivilegeEscalation is not minimized" in v
}

test_4_2_6_root_containers if {
	v := main.violations with input as override("pod_security", "root_containers_minimized")
	count(v) == 1
	"CIS AKS 4.2.6: Admission of root containers is not minimized" in v
}

test_4_2_7_added_capabilities if {
	v := main.violations with input as override("pod_security", "added_capabilities_minimized")
	count(v) == 1
	"CIS AKS 4.2.7: Admission of containers with added capabilities is not minimized" in v
}

test_4_2_8_assigned_capabilities if {
	v := main.violations with input as override("pod_security", "assigned_capabilities_minimized")
	count(v) == 1
	"CIS AKS 4.2.8: Admission of containers with capabilities assigned is not minimized" in v
}

# ── 4.4 CNI and network policies ──────────────────────────────────────────────

test_4_4_1_latest_cni if {
	v := main.violations with input as override("network", "latest_cni_version_used")
	count(v) == 1
	"CIS AKS 4.4.1: The latest CNI version is not in use" in v
}

test_4_4_2_all_namespaces_netpol if {
	v := main.violations with input as override("network", "all_namespaces_have_network_policies")
	count(v) == 1
	"CIS AKS 4.4.2: One or more namespaces have no NetworkPolicy defined" in v
}

# ── 4.5 Secrets management ────────────────────────────────────────────────────

test_4_5_1_secrets_as_files if {
	v := main.violations with input as override("secrets", "secrets_as_files_preferred")
	count(v) == 1
	"CIS AKS 4.5.1: Secrets are exposed as environment variables rather than mounted as files" in v
}

test_4_5_2_external_secret_storage if {
	v := main.violations with input as override("secrets", "external_secret_storage_considered")
	count(v) == 1
	"CIS AKS 4.5.2: External secret storage has not been evaluated or adopted" in v
}

# ── 4.7 General policies ──────────────────────────────────────────────────────

test_4_7_1_namespace_boundaries if {
	v := main.violations with input as override("general", "namespace_boundaries_used")
	count(v) == 1
	"CIS AKS 4.7.1: Namespaces are not used to create administrative boundaries between resources" in v
}

test_4_7_2_security_context if {
	v := main.violations with input as override("general", "security_context_applied")
	count(v) == 1
	"CIS AKS 4.7.2: Security Context is not applied to pods and containers" in v
}

test_4_7_3_default_namespace if {
	v := main.violations with input as override("general", "default_namespace_not_used")
	count(v) == 1
	"CIS AKS 4.7.3: Workloads are deployed in the default namespace" in v
}

# ── 5.1 Image registry and scanning ───────────────────────────────────────────

test_5_1_1_vuln_scanning if {
	v := main.violations with input as override("images", "vulnerability_scanning_enabled")
	count(v) == 1
	"CIS AKS 5.1.1: Image vulnerability scanning (Microsoft Defender for Cloud or third party) is not enabled" in v
}

test_5_1_2_acr_cluster_readonly if {
	v := main.violations with input as override("images", "acr_cluster_access_readonly")
	count(v) == 1
	"CIS AKS 5.1.2: Cluster access to Azure Container Registry is not limited to read-only" in v
}

test_5_1_3_acr_user_access if {
	v := main.violations with input as override("images", "acr_user_access_minimized")
	count(v) == 1
	"CIS AKS 5.1.3: User access to Azure Container Registry is not minimized" in v
}

test_5_1_4_registries_approved if {
	v := main.violations with input as override("images", "registries_limited_to_approved")
	count(v) == 1
	"CIS AKS 5.1.4: Container image registries are not limited to an approved set" in v
}

# ── 5.2–5.6 Managed service configuration ─────────────────────────────────────

test_5_2_1_dedicated_service_accounts if {
	v := main.violations with input as override("managed", "dedicated_service_accounts_preferred")
	count(v) == 1
	"CIS AKS 5.2.1: Dedicated AKS service accounts (workload identity) are not used for workloads needing Azure access" in v
}

test_5_2_2_azure_rbac if {
	v := main.violations with input as override("managed", "azure_rbac_for_kubernetes_authz")
	count(v) == 1
	"CIS AKS 5.2.2: Azure RBAC for Kubernetes Authorization is not in use" in v
}

test_5_3_1_secrets_encrypted if {
	v := main.violations with input as override("managed", "secrets_encrypted")
	count(v) == 1
	"CIS AKS 5.3.1: Kubernetes secrets are not encrypted with a customer-managed key" in v
}

test_5_4_1_control_plane_endpoint if {
	v := main.violations with input as override("managed", "control_plane_endpoint_restricted")
	count(v) == 1
	"CIS AKS 5.4.1: Access to the control plane endpoint is not restricted" in v
}

test_5_4_2_private_endpoint if {
	v := main.violations with input as override("managed", "private_endpoint_only")
	count(v) == 1
	"CIS AKS 5.4.2: Private endpoint is not enabled with public access disabled" in v
}

test_5_4_3_private_nodes if {
	v := main.violations with input as override("managed", "private_nodes")
	count(v) == 1
	"CIS AKS 5.4.3: Cluster nodes are not private (nodes have public reachability)" in v
}

test_5_4_4_network_policy if {
	v := main.violations with input as override("managed", "network_policy_enabled")
	count(v) == 1
	"CIS AKS 5.4.4: Network Policy is not enabled for the cluster" in v
}

test_5_4_5_https_lb_tls if {
	v := main.violations with input as override("managed", "https_lb_tls_encrypted")
	count(v) == 1
	"CIS AKS 5.4.5: Load balancer traffic is not TLS-encrypted end to end" in v
}

test_5_5_1_azure_ad_rbac if {
	v := main.violations with input as override("managed", "azure_ad_rbac_managed")
	count(v) == 1
	"CIS AKS 5.5.1: Kubernetes RBAC users are not managed with Azure AD (Microsoft Entra ID)" in v
}

test_5_6_1_untrusted_workloads if {
	v := main.violations with input as override("managed", "untrusted_workloads_restricted")
	count(v) == 1
	"CIS AKS 5.6.1: Untrusted workloads are not restricted (no sandboxing/isolation in place)" in v
}

test_5_6_2_hostile_multitenant if {
	v := main.violations with input as override("managed", "hostile_multitenant_isolated")
	count(v) == 1
	"CIS AKS 5.6.2: Hostile multi-tenant workloads are not isolated (no dedicated clusters/hard isolation)" in v
}

# ── Compliant input: empty violation set ──────────────────────────────────────

test_fully_compliant_no_violations if {
	v := main.violations with input as compliant_input
	count(v) == 0
}

test_fully_compliant_flag_true if {
	main.compliant with input as compliant_input
}

# ── Empty input: populated report, all 56 controls violated (fail-closed) ─────

test_report_populated_on_empty_input if {
	report := main.compliance_report with input as {}
	report.framework == "CIS Azure AKS Benchmark"
	report.version == "v1.8.0"
	report.total_controls == 56
	report.compliant == false
	report.violation_count == 56
	count(report.violations) == 56
}

test_section_summary_on_empty_input if {
	report := main.compliance_report with input as {}
	report.section_summary["2"] == 1
	report.section_summary["3"] == 15
	report.section_summary["4"] == 25
	report.section_summary["5"] == 15
}
