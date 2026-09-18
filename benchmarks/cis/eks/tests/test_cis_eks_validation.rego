# Per-rule tests for cis_eks.main — CIS Amazon EKS Benchmark v1.8.0 (49 controls)
#
# One test per violation rule: a fully-compliant base fixture with exactly one
# fact flipped false, asserting that rule's exact message is the sole violation.
# Plus a compliant-input test (empty violation set) and a populated-report test
# on empty input. Shares package cis_eks.main_test with test_cis_eks.rego; uses a
# uniquely named fixture (v_base) and rule names (test_ctl_*) to avoid collisions.

package cis_eks.main_test

import rego.v1

import data.cis_eks.main

# Fully compliant fixture — every documented fact affirmatively true.
v_base := {"cis_eks": {
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
		"read_only_port_disabled": true,
		"streaming_idle_timeout_nonzero": true,
		"make_iptables_util_chains_enabled": true,
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
		"cluster_access_manager_api_used": true,
		"bind_impersonate_escalate_limited": true,
		"pv_create_access_minimized": true,
		"node_proxy_access_minimized": true,
		"webhook_config_access_minimized": true,
		"sa_token_creation_minimized": true,
	},
	"pod_security": {
		"privileged_containers_minimized": true,
		"host_pid_sharing_minimized": true,
		"host_ipc_sharing_minimized": true,
		"host_network_sharing_minimized": true,
		"privilege_escalation_minimized": true,
	},
	"network": {
		"cni_supports_network_policies": true,
		"all_namespaces_have_network_policies": true,
	},
	"secrets": {
		"secrets_as_files_preferred": true,
		"external_secret_storage_considered": true,
	},
	"general": {
		"namespace_boundaries_used": true,
		"default_namespace_not_used": true,
	},
	"images": {
		"vulnerability_scanning_enabled": true,
		"ecr_user_access_minimized": true,
		"ecr_cluster_access_readonly": true,
		"registries_limited_to_approved": true,
	},
	"managed": {
		"dedicated_service_accounts_preferred": true,
		"secrets_kms_encrypted": true,
		"control_plane_endpoint_restricted": true,
		"private_endpoint_only": true,
		"private_nodes": true,
		"network_policy_set_appropriately": true,
		"https_lb_tls_encrypted": true,
		"iam_authenticator_rbac_managed": true,
	},
}}

# Violations for the base fixture with exactly one fact (at `path`) flipped false.
v_one(path) := v if {
	inp := json.patch(v_base, [{"op": "replace", "path": path, "value": false}])
	v := main.violations with input as inp
}

# ── 2 Control Plane ──────────────────────────────────────────────────────────

test_ctl_2_1_1 if {
	v := v_one("/cis_eks/control_plane/audit_logging_enabled")
	count(v) == 1
	"CIS EKS 2.1.1: Control plane audit logging is not enabled for all log types" in v
}

# ── 3.1 Worker node configuration files ──────────────────────────────────────

test_ctl_3_1_1 if {
	v := v_one("/cis_eks/node_files/kubeconfig_perms_restricted")
	count(v) == 1
	"CIS EKS 3.1.1: kubeconfig file permissions are more permissive than 644" in v
}

test_ctl_3_1_2 if {
	v := v_one("/cis_eks/node_files/kubeconfig_owner_root")
	count(v) == 1
	"CIS EKS 3.1.2: kubelet kubeconfig file is not owned by root:root" in v
}

test_ctl_3_1_3 if {
	v := v_one("/cis_eks/node_files/kubelet_config_perms_restricted")
	count(v) == 1
	"CIS EKS 3.1.3: kubelet configuration file permissions are more permissive than 644" in v
}

test_ctl_3_1_4 if {
	v := v_one("/cis_eks/node_files/kubelet_config_owner_root")
	count(v) == 1
	"CIS EKS 3.1.4: kubelet configuration file is not owned by root:root" in v
}

# ── 3.2 Kubelet ──────────────────────────────────────────────────────────────

test_ctl_3_2_1 if {
	v := v_one("/cis_eks/kubelet/anonymous_auth_disabled")
	count(v) == 1
	"CIS EKS 3.2.1: Kubelet anonymous authentication is enabled" in v
}

test_ctl_3_2_2 if {
	v := v_one("/cis_eks/kubelet/authorization_mode_not_always_allow")
	count(v) == 1
	"CIS EKS 3.2.2: Kubelet --authorization-mode allows all requests (AlwaysAllow)" in v
}

test_ctl_3_2_3 if {
	v := v_one("/cis_eks/kubelet/client_ca_file_configured")
	count(v) == 1
	"CIS EKS 3.2.3: Kubelet client CA file is not configured" in v
}

test_ctl_3_2_4 if {
	v := v_one("/cis_eks/kubelet/read_only_port_disabled")
	count(v) == 1
	"CIS EKS 3.2.4: Kubelet read-only port is not disabled" in v
}

test_ctl_3_2_5 if {
	v := v_one("/cis_eks/kubelet/streaming_idle_timeout_nonzero")
	count(v) == 1
	"CIS EKS 3.2.5: Kubelet --streaming-connection-idle-timeout is set to 0 (disabled)" in v
}

test_ctl_3_2_6 if {
	v := v_one("/cis_eks/kubelet/make_iptables_util_chains_enabled")
	count(v) == 1
	"CIS EKS 3.2.6: Kubelet --make-iptables-util-chains is not set to true" in v
}

test_ctl_3_2_7 if {
	v := v_one("/cis_eks/kubelet/event_record_qps_appropriate")
	count(v) == 1
	"CIS EKS 3.2.7: Kubelet --eventRecordQPS is not set to an appropriate event capture level" in v
}

test_ctl_3_2_8 if {
	v := v_one("/cis_eks/kubelet/rotate_certificates_enabled")
	count(v) == 1
	"CIS EKS 3.2.8: Kubelet client certificate rotation is disabled (--rotate-certificates false)" in v
}

test_ctl_3_2_9 if {
	v := v_one("/cis_eks/kubelet/rotate_server_certificates_enabled")
	count(v) == 1
	"CIS EKS 3.2.9: Kubelet RotateKubeletServerCertificate is not set to true" in v
}

# ── 4.1 RBAC and service accounts ────────────────────────────────────────────

test_ctl_4_1_1 if {
	v := v_one("/cis_eks/rbac/cluster_admin_usage_minimized")
	count(v) == 1
	"CIS EKS 4.1.1: cluster-admin role is bound beyond where it is required" in v
}

test_ctl_4_1_2 if {
	v := v_one("/cis_eks/rbac/secrets_access_minimized")
	count(v) == 1
	"CIS EKS 4.1.2: Access to secrets is not minimized" in v
}

test_ctl_4_1_3 if {
	v := v_one("/cis_eks/rbac/wildcard_use_minimized")
	count(v) == 1
	"CIS EKS 4.1.3: Wildcards are used in Roles or ClusterRoles" in v
}

test_ctl_4_1_4 if {
	v := v_one("/cis_eks/rbac/pod_create_access_minimized")
	count(v) == 1
	"CIS EKS 4.1.4: Access to create pods is not minimized" in v
}

test_ctl_4_1_5 if {
	v := v_one("/cis_eks/rbac/default_service_accounts_inactive")
	count(v) == 1
	"CIS EKS 4.1.5: Default service accounts are actively used" in v
}

test_ctl_4_1_6 if {
	v := v_one("/cis_eks/rbac/sa_token_mounts_minimized")
	count(v) == 1
	"CIS EKS 4.1.6: Service account tokens are mounted in pods that do not need them" in v
}

test_ctl_4_1_7 if {
	v := v_one("/cis_eks/rbac/cluster_access_manager_api_used")
	count(v) == 1
	"CIS EKS 4.1.7: Cluster Access Manager API is not used to streamline cluster access control" in v
}

test_ctl_4_1_8 if {
	v := v_one("/cis_eks/rbac/bind_impersonate_escalate_limited")
	count(v) == 1
	"CIS EKS 4.1.8: bind, impersonate, or escalate permissions are granted beyond what is required" in v
}

test_ctl_4_1_9 if {
	v := v_one("/cis_eks/rbac/pv_create_access_minimized")
	count(v) == 1
	"CIS EKS 4.1.9: Access to create persistent volumes is not minimized" in v
}

test_ctl_4_1_10 if {
	v := v_one("/cis_eks/rbac/node_proxy_access_minimized")
	count(v) == 1
	"CIS EKS 4.1.10: Access to the proxy sub-resource of nodes is not minimized" in v
}

test_ctl_4_1_11 if {
	v := v_one("/cis_eks/rbac/webhook_config_access_minimized")
	count(v) == 1
	"CIS EKS 4.1.11: Access to webhook configuration objects is not minimized" in v
}

test_ctl_4_1_12 if {
	v := v_one("/cis_eks/rbac/sa_token_creation_minimized")
	count(v) == 1
	"CIS EKS 4.1.12: Access to service account token creation is not minimized" in v
}

# ── 4.2 Pod security ─────────────────────────────────────────────────────────

test_ctl_4_2_1 if {
	v := v_one("/cis_eks/pod_security/privileged_containers_minimized")
	count(v) == 1
	"CIS EKS 4.2.1: Admission of privileged containers is not minimized" in v
}

test_ctl_4_2_2 if {
	v := v_one("/cis_eks/pod_security/host_pid_sharing_minimized")
	count(v) == 1
	"CIS EKS 4.2.2: Admission of containers sharing the host PID namespace is not minimized" in v
}

test_ctl_4_2_3 if {
	v := v_one("/cis_eks/pod_security/host_ipc_sharing_minimized")
	count(v) == 1
	"CIS EKS 4.2.3: Admission of containers sharing the host IPC namespace is not minimized" in v
}

test_ctl_4_2_4 if {
	v := v_one("/cis_eks/pod_security/host_network_sharing_minimized")
	count(v) == 1
	"CIS EKS 4.2.4: Admission of containers sharing the host network namespace is not minimized" in v
}

test_ctl_4_2_5 if {
	v := v_one("/cis_eks/pod_security/privilege_escalation_minimized")
	count(v) == 1
	"CIS EKS 4.2.5: Admission of containers with allowPrivilegeEscalation is not minimized" in v
}

# ── 4.3 Network policies and CNI ─────────────────────────────────────────────

test_ctl_4_3_1 if {
	v := v_one("/cis_eks/network/cni_supports_network_policies")
	count(v) == 1
	"CIS EKS 4.3.1: The CNI plugin in use does not support network policies" in v
}

test_ctl_4_3_2 if {
	v := v_one("/cis_eks/network/all_namespaces_have_network_policies")
	count(v) == 1
	"CIS EKS 4.3.2: One or more namespaces have no NetworkPolicy defined" in v
}

# ── 4.4 Secrets management ───────────────────────────────────────────────────

test_ctl_4_4_1 if {
	v := v_one("/cis_eks/secrets/secrets_as_files_preferred")
	count(v) == 1
	"CIS EKS 4.4.1: Secrets are exposed as environment variables rather than mounted as files" in v
}

test_ctl_4_4_2 if {
	v := v_one("/cis_eks/secrets/external_secret_storage_considered")
	count(v) == 1
	"CIS EKS 4.4.2: External secret storage has not been evaluated or adopted" in v
}

# ── 4.5 General policies ─────────────────────────────────────────────────────

test_ctl_4_5_1 if {
	v := v_one("/cis_eks/general/namespace_boundaries_used")
	count(v) == 1
	"CIS EKS 4.5.1: Namespaces are not used to create administrative boundaries between resources" in v
}

test_ctl_4_5_2 if {
	v := v_one("/cis_eks/general/default_namespace_not_used")
	count(v) == 1
	"CIS EKS 4.5.2: Workloads are deployed in the default namespace" in v
}

# ── 5.1 Image registry and scanning ──────────────────────────────────────────

test_ctl_5_1_1 if {
	v := v_one("/cis_eks/images/vulnerability_scanning_enabled")
	count(v) == 1
	"CIS EKS 5.1.1: Image vulnerability scanning (ECR or third party) is not enabled" in v
}

test_ctl_5_1_2 if {
	v := v_one("/cis_eks/images/ecr_user_access_minimized")
	count(v) == 1
	"CIS EKS 5.1.2: User access to Amazon ECR is not minimized" in v
}

test_ctl_5_1_3 if {
	v := v_one("/cis_eks/images/ecr_cluster_access_readonly")
	count(v) == 1
	"CIS EKS 5.1.3: Cluster access to ECR is not limited to read-only" in v
}

test_ctl_5_1_4 if {
	v := v_one("/cis_eks/images/registries_limited_to_approved")
	count(v) == 1
	"CIS EKS 5.1.4: Container image registries are not limited to an approved set" in v
}

# ── 5.2–5.5 Managed service configuration ────────────────────────────────────

test_ctl_5_2_1 if {
	v := v_one("/cis_eks/managed/dedicated_service_accounts_preferred")
	count(v) == 1
	"CIS EKS 5.2.1: Dedicated EKS service accounts (IRSA/Pod Identity) are not used for workloads needing AWS access" in v
}

test_ctl_5_3_1 if {
	v := v_one("/cis_eks/managed/secrets_kms_encrypted")
	count(v) == 1
	"CIS EKS 5.3.1: Kubernetes secrets are not encrypted with AWS KMS customer-managed keys" in v
}

test_ctl_5_4_1 if {
	v := v_one("/cis_eks/managed/control_plane_endpoint_restricted")
	count(v) == 1
	"CIS EKS 5.4.1: Access to the control plane endpoint is not restricted" in v
}

test_ctl_5_4_2 if {
	v := v_one("/cis_eks/managed/private_endpoint_only")
	count(v) == 1
	"CIS EKS 5.4.2: Private endpoint is not enabled with public access disabled" in v
}

test_ctl_5_4_3 if {
	v := v_one("/cis_eks/managed/private_nodes")
	count(v) == 1
	"CIS EKS 5.4.3: Cluster nodes are not private (nodes have public reachability)" in v
}

test_ctl_5_4_4 if {
	v := v_one("/cis_eks/managed/network_policy_set_appropriately")
	count(v) == 1
	"CIS EKS 5.4.4: Network Policy is not enabled or not set appropriately for the cluster" in v
}

test_ctl_5_4_5 if {
	v := v_one("/cis_eks/managed/https_lb_tls_encrypted")
	count(v) == 1
	"CIS EKS 5.4.5: Load balancer traffic is not TLS-encrypted end to end" in v
}

test_ctl_5_5_1 if {
	v := v_one("/cis_eks/managed/iam_authenticator_rbac_managed")
	count(v) == 1
	"CIS EKS 5.5.1: Kubernetes RBAC users are not managed via AWS IAM Authenticator or aws-cli v1.16.156+" in v
}

# ── Compliant input yields an empty violation set ────────────────────────────

test_ctl_compliant_no_violations if {
	v := main.violations with input as v_base
	count(v) == 0
}

# ── Report rule is a populated object on empty input ─────────────────────────

test_ctl_report_populated_on_empty_input if {
	result := main.compliance_report with input as {}
	is_object(result)
	count(result) > 0
}
