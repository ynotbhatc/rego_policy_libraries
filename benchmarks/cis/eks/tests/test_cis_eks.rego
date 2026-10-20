# Tests for cis_eks.main — CIS Amazon EKS Benchmark v2.0.0 (47 controls)

package cis_eks.main_test

import rego.v1

import data.cis_eks.main

# Fully compliant fixture — evidence for every Automated control, attestations for every Manual one.
compliant_input := {"cis_eks": {
	"cluster": {
		"logging": {"clusterLogging": [{
			"types": [
				"api",
				"audit",
				"authenticator",
				"controllerManager",
				"scheduler",
			],
			"enabled": true,
		}]},
		"accessConfig": {"authenticationMode": "API"},
		"resourcesVpcConfig": {
			"endpointPublicAccess": false,
			"endpointPrivateAccess": true,
			"publicAccessCidrs": [],
		},
	},
	"access_entries": [{
		"principalArn": "arn:aws:iam::111122223333:role/eks-admins",
		"accessPolicies": [{
			"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
			"accessScope": {
				"type": "namespace",
				"namespaces": ["apps"],
			},
		}],
		"kubernetesGroups": [],
	}],
	"nodes": [
		{
			"name": "node-a",
			"kubeconfig_file": {
				"exists": true,
				"mode": "600",
				"owner": "root",
				"group": "root",
			},
			"kubelet_config_file": {
				"exists": true,
				"mode": "644",
				"owner": "root",
				"group": "root",
			},
			"configz": {"kubeletconfig": {
				"authentication": {
					"anonymous": {"enabled": false},
					"x509": {"clientCAFile": "/etc/kubernetes/pki/ca.crt"},
				},
				"authorization": {"mode": "Webhook"},
				"makeIPTablesUtilChains": true,
				"eventRecordQPS": 50,
				"rotateCertificates": true,
				"serverTLSBootstrap": true,
				"featureGates": {"RotateKubeletServerCertificate": true},
				"readOnlyPort": 0,
			}},
		},
		{
			"name": "node-b",
			"kubeconfig_file": {"exists": false},
			"kubelet_config_file": {
				"exists": true,
				"mode": "0600",
				"owner": "root",
				"group": "root",
			},
			"configz": {"kubeletconfig": {
				"authentication": {
					"anonymous": {"enabled": false},
					"x509": {"clientCAFile": "/etc/kubernetes/pki/ca.crt"},
				},
				"authorization": {"mode": "Webhook"},
				"makeIPTablesUtilChains": true,
				"eventRecordQPS": 50,
				"rotateCertificates": true,
				"serverTLSBootstrap": true,
				"featureGates": {"RotateKubeletServerCertificate": true},
			}},
		},
	],
	"namespaces": [
		{"metadata": {"name": "kube-system"}},
		{"metadata": {
			"name": "apps",
			"labels": {"pod-security.kubernetes.io/enforce": "restricted"},
		}},
	],
	"workloads": [
		{
			"kind": "Deployment",
			"metadata": {
				"namespace": "apps",
				"name": "web",
			},
			"spec": {"template": {"spec": {
				"serviceAccountName": "web",
				"automountServiceAccountToken": false,
				"containers": [{
					"name": "web",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			}}},
		},
		{
			"kind": "Pod",
			"metadata": {
				"namespace": "apps",
				"name": "web-abc",
			},
			"spec": {
				"serviceAccountName": "web",
				"automountServiceAccountToken": false,
				"containers": [{
					"name": "web",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			},
		},
		{
			"kind": "CronJob",
			"metadata": {
				"namespace": "apps",
				"name": "report",
			},
			"spec": {"jobTemplate": {"spec": {"template": {"spec": {
				"serviceAccountName": "reporter",
				"containers": [{
					"name": "r",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			}}}}},
		},
		{
			"kind": "Pod",
			"metadata": {
				"namespace": "kube-system",
				"name": "aws-node-1",
			},
			"spec": {
				"serviceAccountName": "aws-node",
				"hostNetwork": true,
				"containers": [{
					"name": "aws-node",
					"securityContext": {"privileged": true},
				}],
			},
		},
	],
	"service_accounts": [
		{
			"metadata": {
				"namespace": "apps",
				"name": "default",
			},
			"automountServiceAccountToken": false,
		},
		{
			"metadata": {
				"namespace": "apps",
				"name": "web",
			},
			"automountServiceAccountToken": false,
		},
		{"metadata": {
			"namespace": "apps",
			"name": "reporter",
		}},
		{"metadata": {
			"namespace": "kube-system",
			"name": "default",
		}},
	],
	"role_bindings": [{
		"kind": "RoleBinding",
		"metadata": {
			"namespace": "apps",
			"name": "web-read",
		},
		"subjects": [{
			"kind": "ServiceAccount",
			"name": "web",
			"namespace": "apps",
		}],
	}],
	"vpc_cni": {"addon": {
		"status": "ACTIVE",
		"addonVersion": "v1.18.3-eksbuild.1",
		"configurationValues": "{\"enableNetworkPolicy\":\"true\"}",
	}},
	"ecr": {"repository_scanning_configurations": [{
		"repositoryName": "apps/web",
		"scanOnPush": true,
		"scanFrequency": "SCAN_ON_PUSH",
	}]},
	"token_mount_allowed": ["apps/reporter"],
	"attest": {
		"cluster_admin_usage_reviewed": true,
		"secrets_access_reviewed": true,
		"wildcard_use_reviewed": true,
		"pod_create_access_reviewed": true,
		"bind_impersonate_escalate_reviewed": true,
		"pv_create_access_reviewed": true,
		"node_proxy_access_reviewed": true,
		"webhook_config_access_reviewed": true,
		"sa_token_creation_reviewed": true,
		"network_policy_coverage_reviewed": true,
		"external_secret_storage_reviewed": true,
		"namespace_boundaries_reviewed": true,
		"ecr_least_privilege_reviewed": true,
		"ecr_pull_only_reviewed": true,
		"approved_registries_enforced": true,
		"secrets_cmk_envelope_encryption": true,
		"private_nodes": true,
		"lb_tls_listeners": true,
	},
}}

# ── Fail-closed: empty input fires every control ─────────────────────────────

test_empty_input_report_well_formed if {
	report := main.compliance_report with input as {}
	report.framework == "CIS Amazon EKS Benchmark"
	report.version == "v2.0.0"
	report.total_controls == 47
	report.compliant == false
	report.violation_count == 47
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
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/authentication/anonymous/enabled",
		"value": true,
	}])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS EKS 3.2.1:")
	report.section_summary["3"] == 1
	report.compliant == false
}

# v2.0.0 5.4.2: private-only endpoint. A public endpoint (even allowlisted) fails it.
test_managed_private_endpoint_single_violation if {
	inp := json.patch(compliant_input, [
		{"op": "replace", "path": "/cis_eks/cluster/resourcesVpcConfig/endpointPublicAccess", "value": true},
		{"op": "replace", "path": "/cis_eks/cluster/resourcesVpcConfig/publicAccessCidrs", "value": ["203.0.113.5/32"]},
	])
	report := main.compliance_report with input as inp
	report.violation_count == 1
	some msg in report.violations
	startswith(msg, "CIS EKS 5.4.2:")
	report.section_summary["5"] == 1
	report.compliant == false
}

# v2.0.0 4.1.7: access entries with scoped permissions.
test_rbac_cluster_access_manager_single_violation if {
	inp := json.patch(compliant_input, [{
		"op": "replace",
		"path": "/cis_eks/access_entries/0/accessPolicies",
		"value": [],
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
	report.section_summary["3"] == 12
	report.section_summary["4"] == 23
	report.section_summary["5"] == 11
}
