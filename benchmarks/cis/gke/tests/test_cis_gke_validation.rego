# Unit tests for benchmarks/cis/gke/cis_gke_validation.rego
# CIS Google GKE Benchmark v1.9.0 — 40 controls, fail-closed booleans.
#
# Strategy: _compliant is a fully-true input (all 40 facts satisfied → zero
# violations). _flip(group, field) deep-merges a single false leaf onto it so
# exactly one rule fires. One test per violation rule asserts the exact message
# is present AND that it is the only violation.

package cis_gke.main_test

import rego.v1

import data.cis_gke.main

# ── Fully-compliant fixture — every fact affirmatively true ───────────────────

_compliant := {"cis_gke": {
	"node_files": {
		"kubeconfig_perms_restricted": true,
		"kubeconfig_owner_root": true,
		"kubelet_config_perms_restricted": true,
		"kubelet_config_owner_root": true,
	},
	"rbac": {
		"cluster_admin_usage_minimized": true,
		"secrets_access_minimized": true,
		"wildcard_use_minimized": true,
		"default_service_accounts_inactive": true,
		"sa_token_mounts_minimized": true,
		"system_masters_group_not_used": true,
		"bind_impersonate_escalate_limited": true,
		"no_system_anonymous_bindings": true,
		"no_nondefault_system_authenticated_bindings": true,
	},
	"pod_security": {"pss_baseline_enforced": true},
	"network": {
		"cni_supports_network_policies": true,
		"all_namespaces_have_network_policies": true,
	},
	"secrets": {
		"secrets_as_files_preferred": true,
		"external_secret_storage_considered": true,
	},
	"admission": {"image_provenance_configured": true},
	"general": {
		"namespace_boundaries_used": true,
		"seccomp_runtime_default": true,
		"security_context_applied": true,
		"default_namespace_not_used": true,
	},
	"images": {
		"vulnerability_scanning_enabled": true,
		"registry_user_access_minimized": true,
		"registry_cluster_access_readonly": true,
		"trusted_images_only": true,
	},
	"managed": {
		"dedicated_gcp_service_accounts": true,
		"secrets_kms_encrypted": true,
		"cos_node_images": true,
		"authorized_networks_enabled": true,
		"private_endpoint_only": true,
		"private_nodes": true,
		"managed_ssl_certificates": true,
		"logging_monitoring_enabled": true,
		"client_cert_auth_disabled": true,
		"google_groups_rbac_managed": true,
		"legacy_abac_disabled": true,
		"web_ui_disabled": true,
		"gke_sandbox_considered": true,
	},
}}

# Deep-merge a single false leaf onto the compliant fixture.
_flip(group, field) := object.union(_compliant, {"cis_gke": {group: {field: false}}})

# ── 3.1 Worker node configuration files ───────────────────────────────────────

test_3_1_1_kubeconfig_perms if {
	inp := _flip("node_files", "kubeconfig_perms_restricted")
	main.violations["CIS GKE 3.1.1: kubeconfig file permissions are more permissive than 644"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_3_1_2_kubeconfig_owner if {
	inp := _flip("node_files", "kubeconfig_owner_root")
	main.violations["CIS GKE 3.1.2: kubelet kubeconfig file is not owned by root:root"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_3_1_3_kubelet_config_perms if {
	inp := _flip("node_files", "kubelet_config_perms_restricted")
	main.violations["CIS GKE 3.1.3: kubelet configuration file permissions are more permissive than 644"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_3_1_4_kubelet_config_owner if {
	inp := _flip("node_files", "kubelet_config_owner_root")
	main.violations["CIS GKE 3.1.4: kubelet configuration file is not owned by root:root"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 4.1 RBAC and service accounts ─────────────────────────────────────────────

test_4_1_1_cluster_admin if {
	inp := _flip("rbac", "cluster_admin_usage_minimized")
	main.violations["CIS GKE 4.1.1: cluster-admin role is bound beyond where it is required"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_2_secrets_access if {
	inp := _flip("rbac", "secrets_access_minimized")
	main.violations["CIS GKE 4.1.2: Access to secrets is not minimized"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_3_wildcards if {
	inp := _flip("rbac", "wildcard_use_minimized")
	main.violations["CIS GKE 4.1.3: Wildcards are used in Roles or ClusterRoles"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_4_default_sa if {
	inp := _flip("rbac", "default_service_accounts_inactive")
	main.violations["CIS GKE 4.1.4: Default service accounts are actively used"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_5_sa_token_mounts if {
	inp := _flip("rbac", "sa_token_mounts_minimized")
	main.violations["CIS GKE 4.1.5: Service account tokens are mounted in pods that do not need them"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_6_system_masters if {
	inp := _flip("rbac", "system_masters_group_not_used")
	main.violations["CIS GKE 4.1.6: The system:masters group is in use"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_7_bind_impersonate_escalate if {
	inp := _flip("rbac", "bind_impersonate_escalate_limited")
	main.violations["CIS GKE 4.1.7: bind, impersonate, or escalate permissions are granted beyond what is required"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_8_anonymous_bindings if {
	inp := _flip("rbac", "no_system_anonymous_bindings")
	main.violations["CIS GKE 4.1.8: Role or ClusterRole bindings to system:anonymous exist"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_1_10_authenticated_bindings if {
	inp := _flip("rbac", "no_nondefault_system_authenticated_bindings")
	main.violations["CIS GKE 4.1.10: Non-default bindings to system:authenticated exist"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 4.2 Pod Security Standards ─────────────────────────────────────────────────

test_4_2_1_pss_baseline if {
	inp := _flip("pod_security", "pss_baseline_enforced")
	main.violations["CIS GKE 4.2.1: Pod Security Standard Baseline profile (or stricter) is not enforced for all namespaces"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 4.3 Network policies and CNI ───────────────────────────────────────────────

test_4_3_1_cni_netpol if {
	inp := _flip("network", "cni_supports_network_policies")
	main.violations["CIS GKE 4.3.1: The CNI plugin in use does not support network policies"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_3_2_all_ns_netpol if {
	inp := _flip("network", "all_namespaces_have_network_policies")
	main.violations["CIS GKE 4.3.2: One or more namespaces have no NetworkPolicy defined"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 4.4 Secrets management ─────────────────────────────────────────────────────

test_4_4_1_secrets_as_files if {
	inp := _flip("secrets", "secrets_as_files_preferred")
	main.violations["CIS GKE 4.4.1: Secrets are exposed as environment variables rather than mounted as files"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_4_2_external_secret_storage if {
	inp := _flip("secrets", "external_secret_storage_considered")
	main.violations["CIS GKE 4.4.2: External secret storage has not been evaluated or adopted"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 4.5 Extensible admission control ───────────────────────────────────────────

test_4_5_1_image_provenance if {
	inp := _flip("admission", "image_provenance_configured")
	main.violations["CIS GKE 4.5.1: Image provenance is not configured via ImagePolicyWebhook admission control"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 4.6 General policies ───────────────────────────────────────────────────────

test_4_6_1_namespace_boundaries if {
	inp := _flip("general", "namespace_boundaries_used")
	main.violations["CIS GKE 4.6.1: Namespaces are not used to create administrative boundaries between resources"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_6_2_seccomp if {
	inp := _flip("general", "seccomp_runtime_default")
	main.violations["CIS GKE 4.6.2: Seccomp profile RuntimeDefault is not set in pod definitions"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_6_3_security_context if {
	inp := _flip("general", "security_context_applied")
	main.violations["CIS GKE 4.6.3: Security Context is not applied to pods and containers"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_4_6_4_default_namespace if {
	inp := _flip("general", "default_namespace_not_used")
	main.violations["CIS GKE 4.6.4: Workloads are deployed in the default namespace"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 5.1 Image registry and scanning ────────────────────────────────────────────

test_5_1_1_vuln_scanning if {
	inp := _flip("images", "vulnerability_scanning_enabled")
	main.violations["CIS GKE 5.1.1: Image vulnerability scanning is not enabled"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_1_2_registry_user_access if {
	inp := _flip("images", "registry_user_access_minimized")
	main.violations["CIS GKE 5.1.2: User access to container image repositories is not minimized"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_1_3_registry_readonly if {
	inp := _flip("images", "registry_cluster_access_readonly")
	main.violations["CIS GKE 5.1.3: Cluster access to container image repositories is not limited to read-only"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_1_4_trusted_images if {
	inp := _flip("images", "trusted_images_only")
	main.violations["CIS GKE 5.1.4: Container images are not limited to trusted/approved sources"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── 5.2–5.10 Managed service configuration ─────────────────────────────────────

test_5_2_2_dedicated_gcp_sa if {
	inp := _flip("managed", "dedicated_gcp_service_accounts")
	main.violations["CIS GKE 5.2.2: Dedicated GCP service accounts with Workload Identity are not in use"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_3_1_secrets_kms if {
	inp := _flip("managed", "secrets_kms_encrypted")
	main.violations["CIS GKE 5.3.1: Kubernetes secrets are not encrypted with Cloud KMS keys (application-layer encryption)"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_5_1_cos_node_images if {
	inp := _flip("managed", "cos_node_images")
	main.violations["CIS GKE 5.5.1: Node images are not Container-Optimized OS (cos_containerd)"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_6_3_authorized_networks if {
	inp := _flip("managed", "authorized_networks_enabled")
	main.violations["CIS GKE 5.6.3: Control Plane Authorized Networks is not enabled"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_6_4_private_endpoint if {
	inp := _flip("managed", "private_endpoint_only")
	main.violations["CIS GKE 5.6.4: Private endpoint is not enabled with public access disabled"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_6_5_private_nodes if {
	inp := _flip("managed", "private_nodes")
	main.violations["CIS GKE 5.6.5: Cluster nodes are not private (nodes have public reachability)"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_6_7_managed_ssl if {
	inp := _flip("managed", "managed_ssl_certificates")
	main.violations["CIS GKE 5.6.7: Google-managed SSL certificates are not in use for HTTPS load balancing"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_7_1_logging_monitoring if {
	inp := _flip("managed", "logging_monitoring_enabled")
	main.violations["CIS GKE 5.7.1: Cloud Logging and Cloud Monitoring are not enabled for the cluster"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_8_1_client_cert_auth if {
	inp := _flip("managed", "client_cert_auth_disabled")
	main.violations["CIS GKE 5.8.1: Client-certificate authentication is not disabled"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_8_2_google_groups_rbac if {
	inp := _flip("managed", "google_groups_rbac_managed")
	main.violations["CIS GKE 5.8.2: Kubernetes RBAC users are not managed with Google Groups for Workspace"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_8_3_legacy_abac if {
	inp := _flip("managed", "legacy_abac_disabled")
	main.violations["CIS GKE 5.8.3: Legacy Authorization (ABAC) is not disabled"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_10_1_web_ui if {
	inp := _flip("managed", "web_ui_disabled")
	main.violations["CIS GKE 5.10.1: The Kubernetes Web UI (Dashboard) is not disabled"] with input as inp
	count(main.violations) == 1 with input as inp
}

test_5_10_3_gke_sandbox if {
	inp := _flip("managed", "gke_sandbox_considered")
	main.violations["CIS GKE 5.10.3: GKE Sandbox has not been evaluated or adopted for untrusted workloads"] with input as inp
	count(main.violations) == 1 with input as inp
}

# ── Compliant input: fully-true fixture yields an empty violation set ──────────

test_compliant_input_no_violations if {
	count(main.violations) == 0 with input as _compliant
	main.compliant with input as _compliant
}

# ── Report is a populated object on empty input {} (fail-closed → all 40) ──────

test_report_populated_on_empty_input if {
	report := main.compliance_report with input as {}
	report.framework == "CIS Google GKE Benchmark"
	report.version == "v1.9.0"
	report.total_controls == 40
	report.compliant == false
	report.violation_count == 40
	count(report.violations) == 40
	report.section_summary["3"] == 4
	report.section_summary["4"] == 19
	report.section_summary["5"] == 17
}
