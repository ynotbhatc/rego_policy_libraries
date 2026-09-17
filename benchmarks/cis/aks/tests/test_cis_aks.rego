# Tests for cis_aks.main — CIS Azure AKS Benchmark v1.8.0 (56 controls)

package cis_aks.main_test

import rego.v1

import data.cis_aks.main

# Fully compliant fixture — every documented fact affirmatively true.
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

# ── Fail-closed: empty input fires every control ─────────────────────────────

test_empty_input_report_well_formed if {
	report := main.compliance_report with input as {}
	report.framework == "CIS Azure AKS Benchmark"
	report.version == "v1.8.0"
	report.total_controls == 56
	report.compliant == false
	report.violation_count == 56
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

test_kubelet_protect_kernel_defaults_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_aks/kubelet/protect_kernel_defaults_enabled",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS AKS 3.2.6:")
	report.section_summary["3"] == 1
	report.compliant == false
}

test_rbac_csr_approval_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_aks/rbac/csr_approval_access_minimized",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS AKS 4.1.10:")
	report.section_summary["4"] == 1
	report.compliant == false
}

test_managed_azure_rbac_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_aks/managed/azure_rbac_for_kubernetes_authz",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS AKS 5.2.2:")
	report.section_summary["5"] == 1
}

# ── Empty-input section distribution ─────────────────────────────────────────
# 2: 1 | 3: 4 node_files + 11 kubelet = 15 | 4: 10 rbac + 8 pod_security
# + 2 network + 2 secrets + 3 general = 25 | 5: 4 images + 11 managed = 15

test_empty_input_section_distribution if {
	report := main.compliance_report with input as {}
	report.section_summary["2"] == 1
	report.section_summary["3"] == 15
	report.section_summary["4"] == 25
	report.section_summary["5"] == 15
}
