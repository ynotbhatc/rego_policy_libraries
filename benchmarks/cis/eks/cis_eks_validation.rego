# CIS Amazon EKS Benchmark v1.8.0
#
# Control set mirrors the kubescape/regolibrary cis-eks-t1.8.0 framework
# mapping (49 controls); the official CIS EKS benchmark defines additional
# controls not implemented here. There are no numbering gaps inside this
# mapping — sections 2.1, 3.1, 3.2, 4.1–4.5, and 5.1–5.5 are covered
# contiguously as listed below.
#
# Query: POST /v1/data/cis_eks/main/compliance_report
#
# Fail-closed: every fact is a boolean that must be affirmatively true.
# Empty input yields all 49 violations.
#
# Input contract — input.cis_eks.*  (all fields bool)
#
#   control_plane.*            — source: AWS API (eks:DescribeCluster, CloudWatch)
#     audit_logging_enabled                 2.1.1
#
#   node_files.*               — source: node access (SSH/SSM onto worker nodes)
#     kubeconfig_perms_restricted           3.1.1
#     kubeconfig_owner_root                 3.1.2
#     kubelet_config_perms_restricted       3.1.3
#     kubelet_config_owner_root             3.1.4
#
#   kubelet.*                  — source: node access (kubelet config/process args)
#     anonymous_auth_disabled               3.2.1
#     authorization_mode_not_always_allow   3.2.2
#     client_ca_file_configured             3.2.3
#     read_only_port_disabled               3.2.4
#     streaming_idle_timeout_nonzero        3.2.5
#     make_iptables_util_chains_enabled     3.2.6
#     event_record_qps_appropriate          3.2.7
#     rotate_certificates_enabled           3.2.8
#     rotate_server_certificates_enabled    3.2.9
#
#   rbac.*                     — source: cluster API (Roles/ClusterRoles/Bindings)
#     cluster_admin_usage_minimized         4.1.1
#     secrets_access_minimized              4.1.2
#     wildcard_use_minimized                4.1.3
#     pod_create_access_minimized           4.1.4
#     default_service_accounts_inactive     4.1.5
#     sa_token_mounts_minimized             4.1.6
#     cluster_access_manager_api_used       4.1.7  (AWS API: access entries)
#     bind_impersonate_escalate_limited     4.1.8
#     pv_create_access_minimized            4.1.9
#     node_proxy_access_minimized           4.1.10
#     webhook_config_access_minimized       4.1.11
#     sa_token_creation_minimized           4.1.12
#
#   pod_security.*             — source: cluster API (admission config / PSS audit)
#     privileged_containers_minimized       4.2.1
#     host_pid_sharing_minimized            4.2.2
#     host_ipc_sharing_minimized            4.2.3
#     host_network_sharing_minimized        4.2.4
#     privilege_escalation_minimized        4.2.5
#
#   network.*                  — source: cluster API (CNI daemonset, NetworkPolicy objects)
#     cni_supports_network_policies         4.3.1
#     all_namespaces_have_network_policies  4.3.2
#
#   secrets.*                  — source: cluster API (pod specs, secret refs)
#     secrets_as_files_preferred            4.4.1
#     external_secret_storage_considered    4.4.2
#
#   general.*                  — source: cluster API (namespaces, workload placement)
#     namespace_boundaries_used             4.5.1
#     default_namespace_not_used            4.5.2
#
#   images.*                   — source: AWS API (ECR) + IAM policy review
#     vulnerability_scanning_enabled        5.1.1
#     ecr_user_access_minimized             5.1.2
#     ecr_cluster_access_readonly           5.1.3
#     registries_limited_to_approved        5.1.4
#
#   managed.*                  — source: AWS API (eks:DescribeCluster, KMS, IAM, ELB)
#     dedicated_service_accounts_preferred  5.2.1  (IRSA / Pod Identity)
#     secrets_kms_encrypted                 5.3.1
#     control_plane_endpoint_restricted     5.4.1
#     private_endpoint_only                 5.4.2
#     private_nodes                         5.4.3
#     network_policy_set_appropriately      5.4.4
#     https_lb_tls_encrypted                5.4.5
#     iam_authenticator_rbac_managed        5.5.1

package cis_eks.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── 2 Control Plane ──────────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.control_plane.audit_logging_enabled
	msg := "CIS EKS 2.1.1: Control plane audit logging is not enabled for all log types"
}

# ── 3.1 Worker node configuration files ──────────────────────────────────────

violations contains msg if {
	not input.cis_eks.node_files.kubeconfig_perms_restricted
	msg := "CIS EKS 3.1.1: kubeconfig file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_eks.node_files.kubeconfig_owner_root
	msg := "CIS EKS 3.1.2: kubelet kubeconfig file is not owned by root:root"
}

violations contains msg if {
	not input.cis_eks.node_files.kubelet_config_perms_restricted
	msg := "CIS EKS 3.1.3: kubelet configuration file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_eks.node_files.kubelet_config_owner_root
	msg := "CIS EKS 3.1.4: kubelet configuration file is not owned by root:root"
}

# ── 3.2 Kubelet ──────────────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.kubelet.anonymous_auth_disabled
	msg := "CIS EKS 3.2.1: Kubelet anonymous authentication is enabled"
}

violations contains msg if {
	not input.cis_eks.kubelet.authorization_mode_not_always_allow
	msg := "CIS EKS 3.2.2: Kubelet --authorization-mode allows all requests (AlwaysAllow)"
}

violations contains msg if {
	not input.cis_eks.kubelet.client_ca_file_configured
	msg := "CIS EKS 3.2.3: Kubelet client CA file is not configured"
}

violations contains msg if {
	not input.cis_eks.kubelet.read_only_port_disabled
	msg := "CIS EKS 3.2.4: Kubelet read-only port is not disabled"
}

violations contains msg if {
	not input.cis_eks.kubelet.streaming_idle_timeout_nonzero
	msg := "CIS EKS 3.2.5: Kubelet --streaming-connection-idle-timeout is set to 0 (disabled)"
}

violations contains msg if {
	not input.cis_eks.kubelet.make_iptables_util_chains_enabled
	msg := "CIS EKS 3.2.6: Kubelet --make-iptables-util-chains is not set to true"
}

violations contains msg if {
	not input.cis_eks.kubelet.event_record_qps_appropriate
	msg := "CIS EKS 3.2.7: Kubelet --eventRecordQPS is not set to an appropriate event capture level"
}

violations contains msg if {
	not input.cis_eks.kubelet.rotate_certificates_enabled
	msg := "CIS EKS 3.2.8: Kubelet client certificate rotation is disabled (--rotate-certificates false)"
}

violations contains msg if {
	not input.cis_eks.kubelet.rotate_server_certificates_enabled
	msg := "CIS EKS 3.2.9: Kubelet RotateKubeletServerCertificate is not set to true"
}

# ── 4.1 RBAC and service accounts ────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.rbac.cluster_admin_usage_minimized
	msg := "CIS EKS 4.1.1: cluster-admin role is bound beyond where it is required"
}

violations contains msg if {
	not input.cis_eks.rbac.secrets_access_minimized
	msg := "CIS EKS 4.1.2: Access to secrets is not minimized"
}

violations contains msg if {
	not input.cis_eks.rbac.wildcard_use_minimized
	msg := "CIS EKS 4.1.3: Wildcards are used in Roles or ClusterRoles"
}

violations contains msg if {
	not input.cis_eks.rbac.pod_create_access_minimized
	msg := "CIS EKS 4.1.4: Access to create pods is not minimized"
}

violations contains msg if {
	not input.cis_eks.rbac.default_service_accounts_inactive
	msg := "CIS EKS 4.1.5: Default service accounts are actively used"
}

violations contains msg if {
	not input.cis_eks.rbac.sa_token_mounts_minimized
	msg := "CIS EKS 4.1.6: Service account tokens are mounted in pods that do not need them"
}

violations contains msg if {
	not input.cis_eks.rbac.cluster_access_manager_api_used
	msg := "CIS EKS 4.1.7: Cluster Access Manager API is not used to streamline cluster access control"
}

violations contains msg if {
	not input.cis_eks.rbac.bind_impersonate_escalate_limited
	msg := "CIS EKS 4.1.8: bind, impersonate, or escalate permissions are granted beyond what is required"
}

violations contains msg if {
	not input.cis_eks.rbac.pv_create_access_minimized
	msg := "CIS EKS 4.1.9: Access to create persistent volumes is not minimized"
}

violations contains msg if {
	not input.cis_eks.rbac.node_proxy_access_minimized
	msg := "CIS EKS 4.1.10: Access to the proxy sub-resource of nodes is not minimized"
}

violations contains msg if {
	not input.cis_eks.rbac.webhook_config_access_minimized
	msg := "CIS EKS 4.1.11: Access to webhook configuration objects is not minimized"
}

violations contains msg if {
	not input.cis_eks.rbac.sa_token_creation_minimized
	msg := "CIS EKS 4.1.12: Access to service account token creation is not minimized"
}

# ── 4.2 Pod security ─────────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.pod_security.privileged_containers_minimized
	msg := "CIS EKS 4.2.1: Admission of privileged containers is not minimized"
}

violations contains msg if {
	not input.cis_eks.pod_security.host_pid_sharing_minimized
	msg := "CIS EKS 4.2.2: Admission of containers sharing the host PID namespace is not minimized"
}

violations contains msg if {
	not input.cis_eks.pod_security.host_ipc_sharing_minimized
	msg := "CIS EKS 4.2.3: Admission of containers sharing the host IPC namespace is not minimized"
}

violations contains msg if {
	not input.cis_eks.pod_security.host_network_sharing_minimized
	msg := "CIS EKS 4.2.4: Admission of containers sharing the host network namespace is not minimized"
}

violations contains msg if {
	not input.cis_eks.pod_security.privilege_escalation_minimized
	msg := "CIS EKS 4.2.5: Admission of containers with allowPrivilegeEscalation is not minimized"
}

# ── 4.3 Network policies and CNI ─────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.network.cni_supports_network_policies
	msg := "CIS EKS 4.3.1: The CNI plugin in use does not support network policies"
}

violations contains msg if {
	not input.cis_eks.network.all_namespaces_have_network_policies
	msg := "CIS EKS 4.3.2: One or more namespaces have no NetworkPolicy defined"
}

# ── 4.4 Secrets management ───────────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.secrets.secrets_as_files_preferred
	msg := "CIS EKS 4.4.1: Secrets are exposed as environment variables rather than mounted as files"
}

violations contains msg if {
	not input.cis_eks.secrets.external_secret_storage_considered
	msg := "CIS EKS 4.4.2: External secret storage has not been evaluated or adopted"
}

# ── 4.5 General policies ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.general.namespace_boundaries_used
	msg := "CIS EKS 4.5.1: Namespaces are not used to create administrative boundaries between resources"
}

violations contains msg if {
	not input.cis_eks.general.default_namespace_not_used
	msg := "CIS EKS 4.5.2: Workloads are deployed in the default namespace"
}

# ── 5.1 Image registry and scanning ──────────────────────────────────────────

violations contains msg if {
	not input.cis_eks.images.vulnerability_scanning_enabled
	msg := "CIS EKS 5.1.1: Image vulnerability scanning (ECR or third party) is not enabled"
}

violations contains msg if {
	not input.cis_eks.images.ecr_user_access_minimized
	msg := "CIS EKS 5.1.2: User access to Amazon ECR is not minimized"
}

violations contains msg if {
	not input.cis_eks.images.ecr_cluster_access_readonly
	msg := "CIS EKS 5.1.3: Cluster access to ECR is not limited to read-only"
}

violations contains msg if {
	not input.cis_eks.images.registries_limited_to_approved
	msg := "CIS EKS 5.1.4: Container image registries are not limited to an approved set"
}

# ── 5.2–5.5 Managed service configuration ────────────────────────────────────

violations contains msg if {
	not input.cis_eks.managed.dedicated_service_accounts_preferred
	msg := "CIS EKS 5.2.1: Dedicated EKS service accounts (IRSA/Pod Identity) are not used for workloads needing AWS access"
}

violations contains msg if {
	not input.cis_eks.managed.secrets_kms_encrypted
	msg := "CIS EKS 5.3.1: Kubernetes secrets are not encrypted with AWS KMS customer-managed keys"
}

violations contains msg if {
	not input.cis_eks.managed.control_plane_endpoint_restricted
	msg := "CIS EKS 5.4.1: Access to the control plane endpoint is not restricted"
}

violations contains msg if {
	not input.cis_eks.managed.private_endpoint_only
	msg := "CIS EKS 5.4.2: Private endpoint is not enabled with public access disabled"
}

violations contains msg if {
	not input.cis_eks.managed.private_nodes
	msg := "CIS EKS 5.4.3: Cluster nodes are not private (nodes have public reachability)"
}

violations contains msg if {
	not input.cis_eks.managed.network_policy_set_appropriately
	msg := "CIS EKS 5.4.4: Network Policy is not enabled or not set appropriately for the cluster"
}

violations contains msg if {
	not input.cis_eks.managed.https_lb_tls_encrypted
	msg := "CIS EKS 5.4.5: Load balancer traffic is not TLS-encrypted end to end"
}

violations contains msg if {
	not input.cis_eks.managed.iam_authenticator_rbac_managed
	msg := "CIS EKS 5.5.1: Kubernetes RBAC users are not managed via AWS IAM Authenticator or aws-cli v1.16.156+"
}

# ── Section rollup ───────────────────────────────────────────────────────────

section_violations(prefix) := [v | some v in violations; startswith(v, prefix)]

section_summary := {
	"2": count(section_violations("CIS EKS 2.")),
	"3": count(section_violations("CIS EKS 3.")),
	"4": count(section_violations("CIS EKS 4.")),
	"5": count(section_violations("CIS EKS 5.")),
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
	"framework": "CIS Amazon EKS Benchmark",
	"version": "v1.8.0",
	"compliant": compliant,
	"total_controls": 49,
	"violations": violations,
	"violation_count": count(violations),
	"section_summary": section_summary,
}
