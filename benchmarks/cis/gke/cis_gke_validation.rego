# CIS Google GKE (Google Kubernetes Engine) Benchmark v1.9.0
#
# Control set mirrors the kubescape/regolibrary cis-gke-v1.9.0 framework
# mapping (40 controls). This mapping is a PARTIAL cover of the official
# CIS GKE v1.9.0 benchmark — the official benchmark defines additional
# controls not implemented here. Known numbering gaps in this mapping:
#   - Section 2 (control plane logging) carries no controls here
#     (5.7.1 covers logging/monitoring instead).
#   - 4.1.9 does not exist (4.1 jumps from 4.1.8 to 4.1.10).
#   - 5.2.1 does not exist (section 5.2 starts at 5.2.2).
#   - 5.4 and 5.9 carry no controls in this mapping.
#   - 5.6.1, 5.6.2, and 5.6.6 do not exist (5.6 covers .3/.4/.5/.7).
#   - 5.10.2 does not exist (5.10 covers .1 and .3).
#
# Query: POST /v1/data/cis_gke/main/compliance_report
#
# Fail-closed: every fact is a boolean that must be affirmatively true.
# Empty input yields all 40 violations.
#
# Input contract — input.cis_gke.*  (all fields bool)
#
#   node_files.*               — source: node access (SSH via gcloud compute)
#     kubeconfig_perms_restricted           3.1.1
#     kubeconfig_owner_root                 3.1.2
#     kubelet_config_perms_restricted       3.1.3
#     kubelet_config_owner_root             3.1.4
#
#   rbac.*                     — source: cluster API (Roles/ClusterRoles/Bindings)
#     cluster_admin_usage_minimized         4.1.1
#     secrets_access_minimized              4.1.2
#     wildcard_use_minimized                4.1.3
#     default_service_accounts_inactive     4.1.4
#     sa_token_mounts_minimized             4.1.5
#     system_masters_group_not_used         4.1.6
#     bind_impersonate_escalate_limited     4.1.7
#     no_system_anonymous_bindings          4.1.8
#     no_nondefault_system_authenticated_bindings  4.1.10
#
#   pod_security.*             — source: cluster API (namespace PSS labels)
#     pss_baseline_enforced                 4.2.1
#
#   network.*                  — source: cluster API + GCP API (CNI, NetworkPolicy)
#     cni_supports_network_policies         4.3.1
#     all_namespaces_have_network_policies  4.3.2
#
#   secrets.*                  — source: cluster API (pod specs, secret refs)
#     secrets_as_files_preferred            4.4.1
#     external_secret_storage_considered    4.4.2
#
#   admission.*                — source: cluster API (admission configuration)
#     image_provenance_configured           4.5.1  (ImagePolicyWebhook / Binary Authorization)
#
#   general.*                  — source: cluster API (namespaces, pod specs)
#     namespace_boundaries_used             4.6.1
#     seccomp_runtime_default               4.6.2
#     security_context_applied              4.6.3
#     default_namespace_not_used            4.6.4
#
#   images.*                   — source: GCP API (Artifact Analysis, IAM)
#     vulnerability_scanning_enabled        5.1.1
#     registry_user_access_minimized        5.1.2
#     registry_cluster_access_readonly      5.1.3
#     trusted_images_only                   5.1.4
#
#   managed.*                  — source: GCP API (gcloud container clusters describe,
#                                Cloud KMS, IAM, Cloud Logging/Monitoring)
#     dedicated_gcp_service_accounts        5.2.2  (Workload Identity)
#     secrets_kms_encrypted                 5.3.1  (application-layer secrets encryption)
#     cos_node_images                       5.5.1  (Container-Optimized OS with containerd)
#     authorized_networks_enabled           5.6.3
#     private_endpoint_only                 5.6.4
#     private_nodes                         5.6.5
#     managed_ssl_certificates              5.6.7
#     logging_monitoring_enabled            5.7.1
#     client_cert_auth_disabled             5.8.1
#     google_groups_rbac_managed            5.8.2
#     legacy_abac_disabled                  5.8.3
#     web_ui_disabled                       5.10.1
#     gke_sandbox_considered                5.10.3

package cis_gke.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── 3.1 Worker node configuration files ──────────────────────────────────────

violations contains msg if {
	not input.cis_gke.node_files.kubeconfig_perms_restricted
	msg := "CIS GKE 3.1.1: kubeconfig file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_gke.node_files.kubeconfig_owner_root
	msg := "CIS GKE 3.1.2: kubelet kubeconfig file is not owned by root:root"
}

violations contains msg if {
	not input.cis_gke.node_files.kubelet_config_perms_restricted
	msg := "CIS GKE 3.1.3: kubelet configuration file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_gke.node_files.kubelet_config_owner_root
	msg := "CIS GKE 3.1.4: kubelet configuration file is not owned by root:root"
}

# ── 4.1 RBAC and service accounts ────────────────────────────────────────────
# (4.1.9 intentionally absent — numbering gap in the mapping.)

violations contains msg if {
	not input.cis_gke.rbac.cluster_admin_usage_minimized
	msg := "CIS GKE 4.1.1: cluster-admin role is bound beyond where it is required"
}

violations contains msg if {
	not input.cis_gke.rbac.secrets_access_minimized
	msg := "CIS GKE 4.1.2: Access to secrets is not minimized"
}

violations contains msg if {
	not input.cis_gke.rbac.wildcard_use_minimized
	msg := "CIS GKE 4.1.3: Wildcards are used in Roles or ClusterRoles"
}

violations contains msg if {
	not input.cis_gke.rbac.default_service_accounts_inactive
	msg := "CIS GKE 4.1.4: Default service accounts are actively used"
}

violations contains msg if {
	not input.cis_gke.rbac.sa_token_mounts_minimized
	msg := "CIS GKE 4.1.5: Service account tokens are mounted in pods that do not need them"
}

violations contains msg if {
	not input.cis_gke.rbac.system_masters_group_not_used
	msg := "CIS GKE 4.1.6: The system:masters group is in use"
}

violations contains msg if {
	not input.cis_gke.rbac.bind_impersonate_escalate_limited
	msg := "CIS GKE 4.1.7: bind, impersonate, or escalate permissions are granted beyond what is required"
}

violations contains msg if {
	not input.cis_gke.rbac.no_system_anonymous_bindings
	msg := "CIS GKE 4.1.8: Role or ClusterRole bindings to system:anonymous exist"
}

violations contains msg if {
	not input.cis_gke.rbac.no_nondefault_system_authenticated_bindings
	msg := "CIS GKE 4.1.10: Non-default bindings to system:authenticated exist"
}

# ── 4.2 Pod Security Standards ───────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.pod_security.pss_baseline_enforced
	msg := "CIS GKE 4.2.1: Pod Security Standard Baseline profile (or stricter) is not enforced for all namespaces"
}

# ── 4.3 Network policies and CNI ─────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.network.cni_supports_network_policies
	msg := "CIS GKE 4.3.1: The CNI plugin in use does not support network policies"
}

violations contains msg if {
	not input.cis_gke.network.all_namespaces_have_network_policies
	msg := "CIS GKE 4.3.2: One or more namespaces have no NetworkPolicy defined"
}

# ── 4.4 Secrets management ───────────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.secrets.secrets_as_files_preferred
	msg := "CIS GKE 4.4.1: Secrets are exposed as environment variables rather than mounted as files"
}

violations contains msg if {
	not input.cis_gke.secrets.external_secret_storage_considered
	msg := "CIS GKE 4.4.2: External secret storage has not been evaluated or adopted"
}

# ── 4.5 Extensible admission control ─────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.admission.image_provenance_configured
	msg := "CIS GKE 4.5.1: Image provenance is not configured via ImagePolicyWebhook admission control"
}

# ── 4.6 General policies ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.general.namespace_boundaries_used
	msg := "CIS GKE 4.6.1: Namespaces are not used to create administrative boundaries between resources"
}

violations contains msg if {
	not input.cis_gke.general.seccomp_runtime_default
	msg := "CIS GKE 4.6.2: Seccomp profile RuntimeDefault is not set in pod definitions"
}

violations contains msg if {
	not input.cis_gke.general.security_context_applied
	msg := "CIS GKE 4.6.3: Security Context is not applied to pods and containers"
}

violations contains msg if {
	not input.cis_gke.general.default_namespace_not_used
	msg := "CIS GKE 4.6.4: Workloads are deployed in the default namespace"
}

# ── 5.1 Image registry and scanning ──────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.images.vulnerability_scanning_enabled
	msg := "CIS GKE 5.1.1: Image vulnerability scanning is not enabled"
}

violations contains msg if {
	not input.cis_gke.images.registry_user_access_minimized
	msg := "CIS GKE 5.1.2: User access to container image repositories is not minimized"
}

violations contains msg if {
	not input.cis_gke.images.registry_cluster_access_readonly
	msg := "CIS GKE 5.1.3: Cluster access to container image repositories is not limited to read-only"
}

violations contains msg if {
	not input.cis_gke.images.trusted_images_only
	msg := "CIS GKE 5.1.4: Container images are not limited to trusted/approved sources"
}

# ── 5.2–5.10 Managed service configuration ───────────────────────────────────
# (5.2.1, 5.6.1, 5.6.2, 5.6.6, 5.10.2 intentionally absent — mapping gaps.)

violations contains msg if {
	not input.cis_gke.managed.dedicated_gcp_service_accounts
	msg := "CIS GKE 5.2.2: Dedicated GCP service accounts with Workload Identity are not in use"
}

violations contains msg if {
	not input.cis_gke.managed.secrets_kms_encrypted
	msg := "CIS GKE 5.3.1: Kubernetes secrets are not encrypted with Cloud KMS keys (application-layer encryption)"
}

violations contains msg if {
	not input.cis_gke.managed.cos_node_images
	msg := "CIS GKE 5.5.1: Node images are not Container-Optimized OS (cos_containerd)"
}

violations contains msg if {
	not input.cis_gke.managed.authorized_networks_enabled
	msg := "CIS GKE 5.6.3: Control Plane Authorized Networks is not enabled"
}

violations contains msg if {
	not input.cis_gke.managed.private_endpoint_only
	msg := "CIS GKE 5.6.4: Private endpoint is not enabled with public access disabled"
}

violations contains msg if {
	not input.cis_gke.managed.private_nodes
	msg := "CIS GKE 5.6.5: Cluster nodes are not private (nodes have public reachability)"
}

violations contains msg if {
	not input.cis_gke.managed.managed_ssl_certificates
	msg := "CIS GKE 5.6.7: Google-managed SSL certificates are not in use for HTTPS load balancing"
}

violations contains msg if {
	not input.cis_gke.managed.logging_monitoring_enabled
	msg := "CIS GKE 5.7.1: Cloud Logging and Cloud Monitoring are not enabled for the cluster"
}

violations contains msg if {
	not input.cis_gke.managed.client_cert_auth_disabled
	msg := "CIS GKE 5.8.1: Client-certificate authentication is not disabled"
}

violations contains msg if {
	not input.cis_gke.managed.google_groups_rbac_managed
	msg := "CIS GKE 5.8.2: Kubernetes RBAC users are not managed with Google Groups for Workspace"
}

violations contains msg if {
	not input.cis_gke.managed.legacy_abac_disabled
	msg := "CIS GKE 5.8.3: Legacy Authorization (ABAC) is not disabled"
}

violations contains msg if {
	not input.cis_gke.managed.web_ui_disabled
	msg := "CIS GKE 5.10.1: The Kubernetes Web UI (Dashboard) is not disabled"
}

violations contains msg if {
	not input.cis_gke.managed.gke_sandbox_considered
	msg := "CIS GKE 5.10.3: GKE Sandbox has not been evaluated or adopted for untrusted workloads"
}

# ── Section rollup ───────────────────────────────────────────────────────────

section_violations(prefix) := [v | some v in violations; startswith(v, prefix)]

section_summary := {
	"3": count(section_violations("CIS GKE 3.")),
	"4": count(section_violations("CIS GKE 4.")),
	"5": count(section_violations("CIS GKE 5.")),
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
	"framework": "CIS Google GKE Benchmark",
	"version": "v1.9.0",
	"compliant": compliant,
	"total_controls": 40,
	"violations": violations,
	"violation_count": count(violations),
	"section_summary": section_summary,
}
