# CIS Azure AKS (Azure Kubernetes Service) Benchmark v1.8.0
#
# Control set mirrors the kubescape/regolibrary cis-aks-t1.8.0 framework
# mapping (56 controls); the official CIS AKS benchmark defines additional
# controls not implemented here. Known numbering gaps in this mapping:
#   - 4.1.7 and 4.1.8 do not exist in the mapping (4.1 jumps from 4.1.6
#     to 4.1.9) — do not expect them.
#   - Sections 4.3 (Azure Policy / OPA) and 4.6 (Extensible Admission
#     Control) exist in the benchmark but carry no controls in this
#     mapping.
#
# Query: POST /v1/data/cis_aks/main/compliance_report
#
# Fail-closed: every fact is a boolean that must be affirmatively true.
# Empty input yields all 56 violations.
#
# Input contract — input.cis_aks.*  (all fields bool)
#
#   control_plane.*            — source: Azure API (Diagnostic Settings / Monitor)
#     audit_logging_enabled                 2.1.1
#
#   node_files.*               — source: node access (SSH/az vmss run-command)
#     kubeconfig_perms_restricted           3.1.1
#     kubeconfig_owner_root                 3.1.2
#     kubelet_config_perms_restricted       3.1.3
#     kubelet_config_owner_root             3.1.4
#
#   kubelet.*                  — source: node access (kubelet config/process args)
#     anonymous_auth_disabled               3.2.1
#     authorization_mode_not_always_allow   3.2.2
#     client_ca_file_configured             3.2.3
#     read_only_port_secured                3.2.4
#     streaming_idle_timeout_nonzero        3.2.5
#     protect_kernel_defaults_enabled       3.2.6
#     make_iptables_util_chains_enabled     3.2.7
#     hostname_override_not_set             3.2.8
#     event_record_qps_appropriate          3.2.9
#     rotate_certificates_enabled           3.2.10
#     rotate_server_certificates_enabled    3.2.11
#
#   rbac.*                     — source: cluster API (Roles/ClusterRoles/Bindings)
#     cluster_admin_usage_minimized         4.1.1
#     secrets_access_minimized              4.1.2
#     wildcard_use_minimized                4.1.3
#     pod_create_access_minimized           4.1.4
#     default_service_accounts_inactive     4.1.5
#     sa_token_mounts_minimized             4.1.6
#     node_proxy_access_minimized           4.1.9
#     csr_approval_access_minimized         4.1.10
#     webhook_config_access_minimized       4.1.11
#     sa_token_creation_minimized           4.1.12
#
#   pod_security.*             — source: cluster API (admission config / PSS audit)
#     privileged_containers_minimized       4.2.1
#     host_pid_sharing_minimized            4.2.2
#     host_ipc_sharing_minimized            4.2.3
#     host_network_sharing_minimized        4.2.4
#     privilege_escalation_minimized        4.2.5
#     root_containers_minimized             4.2.6
#     added_capabilities_minimized          4.2.7
#     assigned_capabilities_minimized       4.2.8
#
#   network.*                  — source: cluster API + Azure API (CNI config)
#     latest_cni_version_used               4.4.1
#     all_namespaces_have_network_policies  4.4.2
#
#   secrets.*                  — source: cluster API (pod specs, secret refs)
#     secrets_as_files_preferred            4.5.1
#     external_secret_storage_considered    4.5.2
#
#   general.*                  — source: cluster API (namespaces, workloads)
#     namespace_boundaries_used             4.7.1
#     security_context_applied              4.7.2
#     default_namespace_not_used            4.7.3
#
#   images.*                   — source: Azure API (Defender for Cloud, ACR, RBAC)
#     vulnerability_scanning_enabled        5.1.1
#     acr_cluster_access_readonly           5.1.2
#     acr_user_access_minimized             5.1.3
#     registries_limited_to_approved        5.1.4
#
#   managed.*                  — source: Azure API (aks show, Key Vault, Entra ID, LB)
#     dedicated_service_accounts_preferred  5.2.1  (workload identity)
#     azure_rbac_for_kubernetes_authz       5.2.2
#     secrets_encrypted                     5.3.1  (KMS etcd encryption)
#     control_plane_endpoint_restricted     5.4.1
#     private_endpoint_only                 5.4.2
#     private_nodes                         5.4.3
#     network_policy_enabled                5.4.4
#     https_lb_tls_encrypted                5.4.5
#     azure_ad_rbac_managed                 5.5.1
#     untrusted_workloads_restricted        5.6.1
#     hostile_multitenant_isolated          5.6.2

package cis_aks.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── 2 Control Plane ──────────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.control_plane.audit_logging_enabled
	msg := "CIS AKS 2.1.1: Control plane audit logging is not enabled"
}

# ── 3.1 Worker node configuration files ──────────────────────────────────────

violations contains msg if {
	not input.cis_aks.node_files.kubeconfig_perms_restricted
	msg := "CIS AKS 3.1.1: kubeconfig file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_aks.node_files.kubeconfig_owner_root
	msg := "CIS AKS 3.1.2: kubelet kubeconfig file is not owned by root:root"
}

violations contains msg if {
	not input.cis_aks.node_files.kubelet_config_perms_restricted
	msg := "CIS AKS 3.1.3: kubelet configuration file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_aks.node_files.kubelet_config_owner_root
	msg := "CIS AKS 3.1.4: kubelet configuration file is not owned by root:root"
}

# ── 3.2 Kubelet ──────────────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.kubelet.anonymous_auth_disabled
	msg := "CIS AKS 3.2.1: Kubelet --anonymous-auth is not set to false"
}

violations contains msg if {
	not input.cis_aks.kubelet.authorization_mode_not_always_allow
	msg := "CIS AKS 3.2.2: Kubelet --authorization-mode allows all requests (AlwaysAllow)"
}

violations contains msg if {
	not input.cis_aks.kubelet.client_ca_file_configured
	msg := "CIS AKS 3.2.3: Kubelet --client-ca-file is not set"
}

violations contains msg if {
	not input.cis_aks.kubelet.read_only_port_secured
	msg := "CIS AKS 3.2.4: Kubelet read-only port is not secured (disabled)"
}

violations contains msg if {
	not input.cis_aks.kubelet.streaming_idle_timeout_nonzero
	msg := "CIS AKS 3.2.5: Kubelet --streaming-connection-idle-timeout is set to 0 (disabled)"
}

violations contains msg if {
	not input.cis_aks.kubelet.protect_kernel_defaults_enabled
	msg := "CIS AKS 3.2.6: Kubelet --protect-kernel-defaults is not set to true"
}

violations contains msg if {
	not input.cis_aks.kubelet.make_iptables_util_chains_enabled
	msg := "CIS AKS 3.2.7: Kubelet --make-iptables-util-chains is not set to true"
}

violations contains msg if {
	not input.cis_aks.kubelet.hostname_override_not_set
	msg := "CIS AKS 3.2.8: Kubelet --hostname-override is set, breaking node identity verification"
}

violations contains msg if {
	not input.cis_aks.kubelet.event_record_qps_appropriate
	msg := "CIS AKS 3.2.9: Kubelet --eventRecordQPS is not set to an appropriate event capture level"
}

violations contains msg if {
	not input.cis_aks.kubelet.rotate_certificates_enabled
	msg := "CIS AKS 3.2.10: Kubelet client certificate rotation is disabled (--rotate-certificates false)"
}

violations contains msg if {
	not input.cis_aks.kubelet.rotate_server_certificates_enabled
	msg := "CIS AKS 3.2.11: Kubelet RotateKubeletServerCertificate is not set to true"
}

# ── 4.1 RBAC and service accounts ────────────────────────────────────────────
# (4.1.7 and 4.1.8 intentionally absent — numbering gap in the mapping.)

violations contains msg if {
	not input.cis_aks.rbac.cluster_admin_usage_minimized
	msg := "CIS AKS 4.1.1: cluster-admin role is bound beyond where it is required"
}

violations contains msg if {
	not input.cis_aks.rbac.secrets_access_minimized
	msg := "CIS AKS 4.1.2: Access to secrets is not minimized"
}

violations contains msg if {
	not input.cis_aks.rbac.wildcard_use_minimized
	msg := "CIS AKS 4.1.3: Wildcards are used in Roles or ClusterRoles"
}

violations contains msg if {
	not input.cis_aks.rbac.pod_create_access_minimized
	msg := "CIS AKS 4.1.4: Access to create pods is not minimized"
}

violations contains msg if {
	not input.cis_aks.rbac.default_service_accounts_inactive
	msg := "CIS AKS 4.1.5: Default service accounts are actively used"
}

violations contains msg if {
	not input.cis_aks.rbac.sa_token_mounts_minimized
	msg := "CIS AKS 4.1.6: Service account tokens are mounted in pods that do not need them"
}

violations contains msg if {
	not input.cis_aks.rbac.node_proxy_access_minimized
	msg := "CIS AKS 4.1.9: Access to the proxy sub-resource of nodes is not minimized"
}

violations contains msg if {
	not input.cis_aks.rbac.csr_approval_access_minimized
	msg := "CIS AKS 4.1.10: Access to the approval sub-resource of certificatesigningrequests is not minimized"
}

violations contains msg if {
	not input.cis_aks.rbac.webhook_config_access_minimized
	msg := "CIS AKS 4.1.11: Access to webhook configuration objects is not minimized"
}

violations contains msg if {
	not input.cis_aks.rbac.sa_token_creation_minimized
	msg := "CIS AKS 4.1.12: Access to service account token creation is not minimized"
}

# ── 4.2 Pod security ─────────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.pod_security.privileged_containers_minimized
	msg := "CIS AKS 4.2.1: Admission of privileged containers is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.host_pid_sharing_minimized
	msg := "CIS AKS 4.2.2: Admission of containers sharing the host PID namespace is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.host_ipc_sharing_minimized
	msg := "CIS AKS 4.2.3: Admission of containers sharing the host IPC namespace is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.host_network_sharing_minimized
	msg := "CIS AKS 4.2.4: Admission of containers sharing the host network namespace is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.privilege_escalation_minimized
	msg := "CIS AKS 4.2.5: Admission of containers with allowPrivilegeEscalation is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.root_containers_minimized
	msg := "CIS AKS 4.2.6: Admission of root containers is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.added_capabilities_minimized
	msg := "CIS AKS 4.2.7: Admission of containers with added capabilities is not minimized"
}

violations contains msg if {
	not input.cis_aks.pod_security.assigned_capabilities_minimized
	msg := "CIS AKS 4.2.8: Admission of containers with capabilities assigned is not minimized"
}

# ── 4.4 CNI and network policies ─────────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.network.latest_cni_version_used
	msg := "CIS AKS 4.4.1: The latest CNI version is not in use"
}

violations contains msg if {
	not input.cis_aks.network.all_namespaces_have_network_policies
	msg := "CIS AKS 4.4.2: One or more namespaces have no NetworkPolicy defined"
}

# ── 4.5 Secrets management ───────────────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.secrets.secrets_as_files_preferred
	msg := "CIS AKS 4.5.1: Secrets are exposed as environment variables rather than mounted as files"
}

violations contains msg if {
	not input.cis_aks.secrets.external_secret_storage_considered
	msg := "CIS AKS 4.5.2: External secret storage has not been evaluated or adopted"
}

# ── 4.7 General policies ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.general.namespace_boundaries_used
	msg := "CIS AKS 4.7.1: Namespaces are not used to create administrative boundaries between resources"
}

violations contains msg if {
	not input.cis_aks.general.security_context_applied
	msg := "CIS AKS 4.7.2: Security Context is not applied to pods and containers"
}

violations contains msg if {
	not input.cis_aks.general.default_namespace_not_used
	msg := "CIS AKS 4.7.3: Workloads are deployed in the default namespace"
}

# ── 5.1 Image registry and scanning ──────────────────────────────────────────

violations contains msg if {
	not input.cis_aks.images.vulnerability_scanning_enabled
	msg := "CIS AKS 5.1.1: Image vulnerability scanning (Microsoft Defender for Cloud or third party) is not enabled"
}

violations contains msg if {
	not input.cis_aks.images.acr_cluster_access_readonly
	msg := "CIS AKS 5.1.2: Cluster access to Azure Container Registry is not limited to read-only"
}

violations contains msg if {
	not input.cis_aks.images.acr_user_access_minimized
	msg := "CIS AKS 5.1.3: User access to Azure Container Registry is not minimized"
}

violations contains msg if {
	not input.cis_aks.images.registries_limited_to_approved
	msg := "CIS AKS 5.1.4: Container image registries are not limited to an approved set"
}

# ── 5.2–5.6 Managed service configuration ────────────────────────────────────

violations contains msg if {
	not input.cis_aks.managed.dedicated_service_accounts_preferred
	msg := "CIS AKS 5.2.1: Dedicated AKS service accounts (workload identity) are not used for workloads needing Azure access"
}

violations contains msg if {
	not input.cis_aks.managed.azure_rbac_for_kubernetes_authz
	msg := "CIS AKS 5.2.2: Azure RBAC for Kubernetes Authorization is not in use"
}

violations contains msg if {
	not input.cis_aks.managed.secrets_encrypted
	msg := "CIS AKS 5.3.1: Kubernetes secrets are not encrypted with a customer-managed key"
}

violations contains msg if {
	not input.cis_aks.managed.control_plane_endpoint_restricted
	msg := "CIS AKS 5.4.1: Access to the control plane endpoint is not restricted"
}

violations contains msg if {
	not input.cis_aks.managed.private_endpoint_only
	msg := "CIS AKS 5.4.2: Private endpoint is not enabled with public access disabled"
}

violations contains msg if {
	not input.cis_aks.managed.private_nodes
	msg := "CIS AKS 5.4.3: Cluster nodes are not private (nodes have public reachability)"
}

violations contains msg if {
	not input.cis_aks.managed.network_policy_enabled
	msg := "CIS AKS 5.4.4: Network Policy is not enabled for the cluster"
}

violations contains msg if {
	not input.cis_aks.managed.https_lb_tls_encrypted
	msg := "CIS AKS 5.4.5: Load balancer traffic is not TLS-encrypted end to end"
}

violations contains msg if {
	not input.cis_aks.managed.azure_ad_rbac_managed
	msg := "CIS AKS 5.5.1: Kubernetes RBAC users are not managed with Azure AD (Microsoft Entra ID)"
}

violations contains msg if {
	not input.cis_aks.managed.untrusted_workloads_restricted
	msg := "CIS AKS 5.6.1: Untrusted workloads are not restricted (no sandboxing/isolation in place)"
}

violations contains msg if {
	not input.cis_aks.managed.hostile_multitenant_isolated
	msg := "CIS AKS 5.6.2: Hostile multi-tenant workloads are not isolated (no dedicated clusters/hard isolation)"
}

# ── Section rollup ───────────────────────────────────────────────────────────

section_violations(prefix) := [v | some v in violations; startswith(v, prefix)]

section_summary := {
	"2": count(section_violations("CIS AKS 2.")),
	"3": count(section_violations("CIS AKS 3.")),
	"4": count(section_violations("CIS AKS 4.")),
	"5": count(section_violations("CIS AKS 5.")),
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
	"framework": "CIS Azure AKS Benchmark",
	"version": "v1.8.0",
	"compliant": compliant,
	"total_controls": 56,
	"violations": violations,
	"violation_count": count(violations),
	"section_summary": section_summary,
}
