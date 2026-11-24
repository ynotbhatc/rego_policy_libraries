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
# Empty input yields all 40 violations. A fact that is absent, null or of another type (the strings
# "true" and "false", 0, 1) fires its control and is listed in evidence_problems.
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

# METADATA
# title: "CIS Google GKE (Google Kubernetes Engine) Benchmark v1.9.0"
# custom:
#   class: security
#   framework: cis_gke
#   source: cis
#   domains: [kubernetes, cloud, gcp]
#   coverage:
#     checks: 40
#     cited: 40
#     expected: 40
#     found: 40
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_gke.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── 3.1 Worker node configuration files ──────────────────────────────────────

violations contains msg if {
	not input.cis_gke.node_files.kubeconfig_perms_restricted == true
	msg := "CIS GKE 3.1.1: kubeconfig file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_gke.node_files.kubeconfig_owner_root == true
	msg := "CIS GKE 3.1.2: kubelet kubeconfig file is not owned by root:root"
}

violations contains msg if {
	not input.cis_gke.node_files.kubelet_config_perms_restricted == true
	msg := "CIS GKE 3.1.3: kubelet configuration file permissions are more permissive than 644"
}

violations contains msg if {
	not input.cis_gke.node_files.kubelet_config_owner_root == true
	msg := "CIS GKE 3.1.4: kubelet configuration file is not owned by root:root"
}

# ── 4.1 RBAC and service accounts ────────────────────────────────────────────
# (4.1.9 intentionally absent — numbering gap in the mapping.)

violations contains msg if {
	not input.cis_gke.rbac.cluster_admin_usage_minimized == true
	msg := "CIS GKE 4.1.1: cluster-admin role is bound beyond where it is required"
}

violations contains msg if {
	not input.cis_gke.rbac.secrets_access_minimized == true
	msg := "CIS GKE 4.1.2: Access to secrets is not minimized"
}

violations contains msg if {
	not input.cis_gke.rbac.wildcard_use_minimized == true
	msg := "CIS GKE 4.1.3: Wildcards are used in Roles or ClusterRoles"
}

violations contains msg if {
	not input.cis_gke.rbac.default_service_accounts_inactive == true
	msg := "CIS GKE 4.1.4: Default service accounts are actively used"
}

violations contains msg if {
	not input.cis_gke.rbac.sa_token_mounts_minimized == true
	msg := "CIS GKE 4.1.5: Service account tokens are mounted in pods that do not need them"
}

violations contains msg if {
	not input.cis_gke.rbac.system_masters_group_not_used == true
	msg := "CIS GKE 4.1.6: The system:masters group is in use"
}

violations contains msg if {
	not input.cis_gke.rbac.bind_impersonate_escalate_limited == true
	msg := "CIS GKE 4.1.7: bind, impersonate, or escalate permissions are granted beyond what is required"
}

violations contains msg if {
	not input.cis_gke.rbac.no_system_anonymous_bindings == true
	msg := "CIS GKE 4.1.8: Role or ClusterRole bindings to system:anonymous exist"
}

violations contains msg if {
	not input.cis_gke.rbac.no_nondefault_system_authenticated_bindings == true
	msg := "CIS GKE 4.1.10: Non-default bindings to system:authenticated exist"
}

# ── 4.2 Pod Security Standards ───────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.pod_security.pss_baseline_enforced == true
	msg := "CIS GKE 4.2.1: Pod Security Standard Baseline profile (or stricter) is not enforced for all namespaces"
}

# ── 4.3 Network policies and CNI ─────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.network.cni_supports_network_policies == true
	msg := "CIS GKE 4.3.1: The CNI plugin in use does not support network policies"
}

violations contains msg if {
	not input.cis_gke.network.all_namespaces_have_network_policies == true
	msg := "CIS GKE 4.3.2: One or more namespaces have no NetworkPolicy defined"
}

# ── 4.4 Secrets management ───────────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.secrets.secrets_as_files_preferred == true
	msg := "CIS GKE 4.4.1: Secrets are exposed as environment variables rather than mounted as files"
}

violations contains msg if {
	not input.cis_gke.secrets.external_secret_storage_considered == true
	msg := "CIS GKE 4.4.2: External secret storage has not been evaluated or adopted"
}

# ── 4.5 Extensible admission control ─────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.admission.image_provenance_configured == true
	msg := "CIS GKE 4.5.1: Image provenance is not configured via ImagePolicyWebhook admission control"
}

# ── 4.6 General policies ─────────────────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.general.namespace_boundaries_used == true
	msg := "CIS GKE 4.6.1: Namespaces are not used to create administrative boundaries between resources"
}

violations contains msg if {
	not input.cis_gke.general.seccomp_runtime_default == true
	msg := "CIS GKE 4.6.2: Seccomp profile RuntimeDefault is not set in pod definitions"
}

violations contains msg if {
	not input.cis_gke.general.security_context_applied == true
	msg := "CIS GKE 4.6.3: Security Context is not applied to pods and containers"
}

violations contains msg if {
	not input.cis_gke.general.default_namespace_not_used == true
	msg := "CIS GKE 4.6.4: Workloads are deployed in the default namespace"
}

# ── 5.1 Image registry and scanning ──────────────────────────────────────────

violations contains msg if {
	not input.cis_gke.images.vulnerability_scanning_enabled == true
	msg := "CIS GKE 5.1.1: Image vulnerability scanning is not enabled"
}

violations contains msg if {
	not input.cis_gke.images.registry_user_access_minimized == true
	msg := "CIS GKE 5.1.2: User access to container image repositories is not minimized"
}

violations contains msg if {
	not input.cis_gke.images.registry_cluster_access_readonly == true
	msg := "CIS GKE 5.1.3: Cluster access to container image repositories is not limited to read-only"
}

violations contains msg if {
	not input.cis_gke.images.trusted_images_only == true
	msg := "CIS GKE 5.1.4: Container images are not limited to trusted/approved sources"
}

# ── 5.2–5.10 Managed service configuration ───────────────────────────────────
# (5.2.1, 5.6.1, 5.6.2, 5.6.6, 5.10.2 intentionally absent — mapping gaps.)

violations contains msg if {
	not input.cis_gke.managed.dedicated_gcp_service_accounts == true
	msg := "CIS GKE 5.2.2: Dedicated GCP service accounts with Workload Identity are not in use"
}

violations contains msg if {
	not input.cis_gke.managed.secrets_kms_encrypted == true
	msg := "CIS GKE 5.3.1: Kubernetes secrets are not encrypted with Cloud KMS keys (application-layer encryption)"
}

violations contains msg if {
	not input.cis_gke.managed.cos_node_images == true
	msg := "CIS GKE 5.5.1: Node images are not Container-Optimized OS (cos_containerd)"
}

violations contains msg if {
	not input.cis_gke.managed.authorized_networks_enabled == true
	msg := "CIS GKE 5.6.3: Control Plane Authorized Networks is not enabled"
}

violations contains msg if {
	not input.cis_gke.managed.private_endpoint_only == true
	msg := "CIS GKE 5.6.4: Private endpoint is not enabled with public access disabled"
}

violations contains msg if {
	not input.cis_gke.managed.private_nodes == true
	msg := "CIS GKE 5.6.5: Cluster nodes are not private (nodes have public reachability)"
}

violations contains msg if {
	not input.cis_gke.managed.managed_ssl_certificates == true
	msg := "CIS GKE 5.6.7: Google-managed SSL certificates are not in use for HTTPS load balancing"
}

violations contains msg if {
	not input.cis_gke.managed.logging_monitoring_enabled == true
	msg := "CIS GKE 5.7.1: Cloud Logging and Cloud Monitoring are not enabled for the cluster"
}

violations contains msg if {
	not input.cis_gke.managed.client_cert_auth_disabled == true
	msg := "CIS GKE 5.8.1: Client-certificate authentication is not disabled"
}

violations contains msg if {
	not input.cis_gke.managed.google_groups_rbac_managed == true
	msg := "CIS GKE 5.8.2: Kubernetes RBAC users are not managed with Google Groups for Workspace"
}

violations contains msg if {
	not input.cis_gke.managed.legacy_abac_disabled == true
	msg := "CIS GKE 5.8.3: Legacy Authorization (ABAC) is not disabled"
}

violations contains msg if {
	not input.cis_gke.managed.web_ui_disabled == true
	msg := "CIS GKE 5.10.1: The Kubernetes Web UI (Dashboard) is not disabled"
}

violations contains msg if {
	not input.cis_gke.managed.gke_sandbox_considered == true
	msg := "CIS GKE 5.10.3: GKE Sandbox has not been evaluated or adopted for untrusted workloads"
}

# ── Evidence ─────────────────────────────────────────────────────────────────
# Only the boolean true meets a control. A fact that is missing, null or of another type (the strings
# "true" and "false", 0, 1) fails its control like the boolean false does, and is named here so the
# report says whether the control failed on the fact or on the evidence for it.

_facts := {
	"node_files": {"kubeconfig_perms_restricted", "kubeconfig_owner_root", "kubelet_config_perms_restricted", "kubelet_config_owner_root"},
	"rbac": {"cluster_admin_usage_minimized", "secrets_access_minimized", "wildcard_use_minimized", "default_service_accounts_inactive", "sa_token_mounts_minimized", "system_masters_group_not_used", "bind_impersonate_escalate_limited", "no_system_anonymous_bindings", "no_nondefault_system_authenticated_bindings"},
	"pod_security": {"pss_baseline_enforced"},
	"network": {"cni_supports_network_policies", "all_namespaces_have_network_policies"},
	"secrets": {"secrets_as_files_preferred", "external_secret_storage_considered"},
	"admission": {"image_provenance_configured"},
	"general": {"namespace_boundaries_used", "seccomp_runtime_default", "security_context_applied", "default_namespace_not_used"},
	"images": {"vulnerability_scanning_enabled", "registry_user_access_minimized", "registry_cluster_access_readonly", "trusted_images_only"},
	"managed": {"dedicated_gcp_service_accounts", "secrets_kms_encrypted", "cos_node_images", "authorized_networks_enabled", "private_endpoint_only", "private_nodes", "managed_ssl_certificates", "logging_monitoring_enabled", "client_cert_auth_disabled", "google_groups_rbac_managed", "legacy_abac_disabled", "web_ui_disabled", "gke_sandbox_considered"},
}

_section(name) := value if {
	value := object.get(object.get(input, "cis_gke", null), name, null)
	is_object(value)
} else := {}

evidence_problems contains msg if {
	some section, fields in _facts
	some field in fields
	object.get(_section(section), field, null) == null
	msg := sprintf("evidence missing: cis_gke.%s.%s not collected", [section, field])
}

evidence_problems contains msg if {
	some section, fields in _facts
	some field in fields
	value := object.get(_section(section), field, null)
	value != null
	not is_boolean(value)
	msg := sprintf("cis_gke.%s.%s is not a boolean (got %s)", [section, field, type_name(value)])
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
	"evidence_problems": evidence_problems,
	"failed_controls": min([40, count(violations)]),
	"section_summary": section_summary,
}
