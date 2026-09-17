# Tests for cis_gke.main — CIS Google GKE Benchmark v1.9.0 (40 controls)

package cis_gke.main_test

import rego.v1

import data.cis_gke.main

# Fully compliant fixture — every documented fact affirmatively true.
compliant_input := {"cis_gke": {
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

# ── Fail-closed: empty input fires every control ─────────────────────────────

test_empty_input_report_well_formed if {
	report := main.compliance_report with input as {}
	report.framework == "CIS Google GKE Benchmark"
	report.version == "v1.9.0"
	report.total_controls == 40
	report.compliant == false
	report.violation_count == 40
}

test_empty_input_section_summary_sums_to_violation_count if {
	report := main.compliance_report with input as {}
	sum([c | some _, c in report.section_summary]) == report.violation_count
}

# ── Fully compliant fixture ──────────────────────────────────────────────────

test_fully_compliant_fixture if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
}

# ── Targeted single-control tests ────────────────────────────────────────────

test_rbac_system_masters_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_gke/rbac/system_masters_group_not_used",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS GKE 4.1.6:")
	report.section_summary["4"] == 1
	report.compliant == false
}

test_managed_legacy_abac_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_gke/managed/legacy_abac_disabled",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS GKE 5.8.3:")
	report.section_summary["5"] == 1
	report.compliant == false
}

test_node_files_kubeconfig_perms_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_gke/node_files/kubeconfig_perms_restricted",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS GKE 3.1.1:")
	report.section_summary["3"] == 1
}

# ── Empty-input section distribution ─────────────────────────────────────────
# 3: 4 node_files | 4: 9 rbac + 1 pod_security + 2 network + 2 secrets
# + 1 admission + 4 general = 19 | 5: 4 images + 13 managed = 17

test_empty_input_section_distribution if {
	report := main.compliance_report with input as {}
	report.section_summary["3"] == 4
	report.section_summary["4"] == 19
	report.section_summary["5"] == 17
}
