# Tests for cis_eks.main — CIS Amazon EKS Benchmark v1.8.0 (49 controls)

package cis_eks.main_test

import rego.v1

import data.cis_eks.main

# Fully compliant fixture — every documented fact affirmatively true.
compliant_input := {"cis_eks": {
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

# ── Fail-closed: empty input fires every control ─────────────────────────────

test_empty_input_report_well_formed if {
	report := main.compliance_report with input as {}
	report.framework == "CIS Amazon EKS Benchmark"
	report.version == "v1.8.0"
	report.total_controls == 49
	report.compliant == false
	report.violation_count == 49
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

test_kubelet_anonymous_auth_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_eks/kubelet/anonymous_auth_disabled",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS EKS 3.2.1:")
	report.section_summary["3"] == 1
	report.compliant == false
}

test_managed_private_endpoint_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_eks/managed/private_endpoint_only",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS EKS 5.4.2:")
	report.section_summary["5"] == 1
	report.compliant == false
}

test_rbac_cluster_access_manager_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_eks/rbac/cluster_access_manager_api_used",
		"value": false,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS EKS 4.1.7:")
	report.section_summary["4"] == 1
}

# ── Empty-input section distribution ─────────────────────────────────────────

test_empty_input_section_distribution if {
	report := main.compliance_report with input as {}
	report.section_summary["2"] == 1
	report.section_summary["3"] == 13
	report.section_summary["4"] == 23
	report.section_summary["5"] == 12
}
