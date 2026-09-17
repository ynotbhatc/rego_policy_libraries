package nsa_cisa_k8s.main_test

import data.nsa_cisa_k8s.main
import rego.v1

test_report_wellformed_on_empty_input if {
	r := main.compliance_report with input as {}
	is_object(r)
	r.compliant == false
	r.violation_count > 0
}

test_empty_input_fails_all_43 if {
	r := main.compliance_report with input as {}
	r.violation_count == r.total_controls
	r.total_controls == 43
}

test_section_summary_sums_to_violation_count if {
	r := main.compliance_report with input as {}
	total := sum([n | some _, n in r.section_summary])
	total == r.violation_count
}

compliant_input := {
	"cluster_name": "prod-east",
	"assessment_date": "2026-09-16",
	"nsa_cisa": {
		"pod_security": {
			"nonroot_containers": true,
			"readonly_root_filesystems": true,
			"image_scanning_in_pipeline": true,
			"privileged_containers_prevented": true,
			"host_namespaces_denied": true,
			"hostpath_denied": true,
			"root_execution_rejected": true,
			"kernel_hardening_applied": true,
			"pod_security_admission_enforced": true,
			"trusted_registries_enforced": true,
			"image_signature_verification": true,
			"sa_token_automount_disabled_where_unneeded": true,
		},
		"network": {
			"control_plane_firewalled": true,
			"control_plane_separate_network": true,
			"etcd_access_limited": true,
			"control_plane_tls": true,
			"etcd_encrypted_at_rest": true,
			"etcd_dedicated_tls": true,
			"namespaces_partition_resources": true,
			"network_policies_defined": true,
			"default_deny_policy": true,
			"resource_limits_enforced": true,
			"secrets_encrypted_not_in_config": true,
			"api_server_not_internet_exposed": true,
			"traffic_tls12_plus": true,
			"cloud_metadata_access_blocked": true,
		},
		"authn_authz": {
			"anonymous_auth_disabled": true,
			"strong_user_authentication": true,
			"rbac_enabled": true,
			"least_privilege_roles": true,
			"kubelet_anonymous_disabled": true,
			"kubelet_client_tls_auth": true,
		},
		"logging": {
			"audit_logging_enabled": true,
			"audit_policy_configured": true,
			"logs_survive_node_failure": true,
			"logs_aggregated_externally": true,
			"monitoring_alerting_configured": true,
			"pod_baselines_established": true,
			"rbac_periodically_audited": true,
		},
		"updates": {
			"patches_promptly_applied": true,
			"periodic_scans_and_pentests": true,
			"unused_components_removed": true,
			"cis_benchmark_adherence": true,
		},
	},
}

test_fully_compliant_cluster if {
	r := main.compliance_report with input as compliant_input
	r.compliant == true
	r.violation_count == 0
}

test_missing_default_deny_flagged if {
	bad := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/nsa_cisa/network/default_deny_policy",
		"value": false,
	}])
	r := main.compliance_report with input as bad
	r.compliant == false
	r.violation_count == 1
	r.section_summary.network_separation == 1
}

test_anonymous_auth_enabled_flagged if {
	bad := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/nsa_cisa/authn_authz/anonymous_auth_disabled",
		"value": false,
	}])
	r := main.compliance_report with input as bad
	some v in r.violations
	contains(v, "--anonymous-auth=false")
}
