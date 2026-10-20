# Pass, evidence-missing and edge-case tests for cis_eks.main — CIS Amazon EKS Benchmark v2.0.0.

package cis_eks.main_test

import rego.v1

import data.cis_eks.main

p_base := {"cis_eks": {
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

# IDs that have at least one violation.
p_ids(v) := {substring(m, 8, indexof(m, ":") - 8) | some m in v}

p_run(ops) := v if {
	inp := json.patch(p_base, ops)
	v := main.violations with input as inp
}

test_pass_2_1_1 if {
	v := main.violations with input as p_base
	not "2.1.1" in p_ids(v)
}

test_pass_3_1_1 if {
	v := main.violations with input as p_base
	not "3.1.1" in p_ids(v)
}

test_pass_3_1_2 if {
	v := main.violations with input as p_base
	not "3.1.2" in p_ids(v)
}

test_pass_3_1_3 if {
	v := main.violations with input as p_base
	not "3.1.3" in p_ids(v)
}

test_pass_3_1_4 if {
	v := main.violations with input as p_base
	not "3.1.4" in p_ids(v)
}

test_pass_3_2_1 if {
	v := main.violations with input as p_base
	not "3.2.1" in p_ids(v)
}

test_pass_3_2_2 if {
	v := main.violations with input as p_base
	not "3.2.2" in p_ids(v)
}

test_pass_3_2_3 if {
	v := main.violations with input as p_base
	not "3.2.3" in p_ids(v)
}

test_pass_3_2_4 if {
	v := main.violations with input as p_base
	not "3.2.4" in p_ids(v)
}

test_pass_3_2_5 if {
	v := main.violations with input as p_base
	not "3.2.5" in p_ids(v)
}

test_pass_3_2_6 if {
	v := main.violations with input as p_base
	not "3.2.6" in p_ids(v)
}

test_pass_3_2_7 if {
	v := main.violations with input as p_base
	not "3.2.7" in p_ids(v)
}

test_pass_3_2_8 if {
	v := main.violations with input as p_base
	not "3.2.8" in p_ids(v)
}

test_pass_4_1_1 if {
	v := main.violations with input as p_base
	not "4.1.1" in p_ids(v)
}

test_pass_4_1_2 if {
	v := main.violations with input as p_base
	not "4.1.2" in p_ids(v)
}

test_pass_4_1_3 if {
	v := main.violations with input as p_base
	not "4.1.3" in p_ids(v)
}

test_pass_4_1_4 if {
	v := main.violations with input as p_base
	not "4.1.4" in p_ids(v)
}

test_pass_4_1_5 if {
	v := main.violations with input as p_base
	not "4.1.5" in p_ids(v)
}

test_pass_4_1_6 if {
	v := main.violations with input as p_base
	not "4.1.6" in p_ids(v)
}

test_pass_4_1_7 if {
	v := main.violations with input as p_base
	not "4.1.7" in p_ids(v)
}

test_pass_4_1_8 if {
	v := main.violations with input as p_base
	not "4.1.8" in p_ids(v)
}

test_pass_4_1_9 if {
	v := main.violations with input as p_base
	not "4.1.9" in p_ids(v)
}

test_pass_4_1_10 if {
	v := main.violations with input as p_base
	not "4.1.10" in p_ids(v)
}

test_pass_4_1_11 if {
	v := main.violations with input as p_base
	not "4.1.11" in p_ids(v)
}

test_pass_4_1_12 if {
	v := main.violations with input as p_base
	not "4.1.12" in p_ids(v)
}

test_pass_4_2_1 if {
	v := main.violations with input as p_base
	not "4.2.1" in p_ids(v)
}

test_pass_4_2_2 if {
	v := main.violations with input as p_base
	not "4.2.2" in p_ids(v)
}

test_pass_4_2_3 if {
	v := main.violations with input as p_base
	not "4.2.3" in p_ids(v)
}

test_pass_4_2_4 if {
	v := main.violations with input as p_base
	not "4.2.4" in p_ids(v)
}

test_pass_4_2_5 if {
	v := main.violations with input as p_base
	not "4.2.5" in p_ids(v)
}

test_pass_4_3_1 if {
	v := main.violations with input as p_base
	not "4.3.1" in p_ids(v)
}

test_pass_4_3_2 if {
	v := main.violations with input as p_base
	not "4.3.2" in p_ids(v)
}

test_pass_4_4_1 if {
	v := main.violations with input as p_base
	not "4.4.1" in p_ids(v)
}

test_pass_4_4_2 if {
	v := main.violations with input as p_base
	not "4.4.2" in p_ids(v)
}

test_pass_4_5_1 if {
	v := main.violations with input as p_base
	not "4.5.1" in p_ids(v)
}

test_pass_4_5_2 if {
	v := main.violations with input as p_base
	not "4.5.2" in p_ids(v)
}

test_pass_5_1_1 if {
	v := main.violations with input as p_base
	not "5.1.1" in p_ids(v)
}

test_pass_5_1_2 if {
	v := main.violations with input as p_base
	not "5.1.2" in p_ids(v)
}

test_pass_5_1_3 if {
	v := main.violations with input as p_base
	not "5.1.3" in p_ids(v)
}

test_pass_5_1_4 if {
	v := main.violations with input as p_base
	not "5.1.4" in p_ids(v)
}

test_pass_5_2_1 if {
	v := main.violations with input as p_base
	not "5.2.1" in p_ids(v)
}

test_pass_5_3_1 if {
	v := main.violations with input as p_base
	not "5.3.1" in p_ids(v)
}

test_pass_5_4_1 if {
	v := main.violations with input as p_base
	not "5.4.1" in p_ids(v)
}

test_pass_5_4_2 if {
	v := main.violations with input as p_base
	not "5.4.2" in p_ids(v)
}

test_pass_5_4_3 if {
	v := main.violations with input as p_base
	not "5.4.3" in p_ids(v)
}

test_pass_5_4_4 if {
	v := main.violations with input as p_base
	not "5.4.4" in p_ids(v)
}

test_pass_5_5_1 if {
	v := main.violations with input as p_base
	not "5.5.1" in p_ids(v)
}

test_missing_2_1_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/cluster/logging",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 2.1.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 2.1.1: evidence missing — ")
	contains(msgs[0], "cluster.logging.clusterLogging")
}

test_missing_3_1_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/0/kubeconfig_file",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.1.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.1.1: evidence missing — ")
	contains(msgs[0], "nodes[].kubeconfig_file")
}

test_missing_3_1_2 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/kubeconfig_file",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.1.2:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.1.2: evidence missing — ")
	contains(msgs[0], "nodes[].kubeconfig_file")
}

test_missing_3_1_3 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/0/kubelet_config_file",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.1.3:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.1.3: evidence missing — ")
	contains(msgs[0], "nodes[].kubelet_config_file")
}

test_missing_3_1_4 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/kubelet_config_file",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.1.4:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.1.4: evidence missing — ")
	contains(msgs[0], "nodes[].kubelet_config_file")
}

test_missing_3_2_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.1: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_2 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.2:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.2: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_3 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.3:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.3: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_4 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.4:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.4: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_5 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.5:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.5: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_6 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.6:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.6: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_7 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.7:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.7: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_3_2_8 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/nodes/1/configz",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 3.2.8:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 3.2.8: evidence missing — ")
	contains(msgs[0], "nodes[].configz.kubeletconfig")
}

test_missing_4_1_5 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/role_bindings",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.1.5:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.1.5: evidence missing — ")
	contains(msgs[0], "role_bindings")
}

test_missing_4_1_6 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/service_accounts",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.1.6:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.1.6: evidence missing — ")
	contains(msgs[0], "service_accounts")
}

test_missing_4_1_7 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/cluster/accessConfig",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.1.7:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.1.7: evidence missing — ")
	contains(msgs[0], "cluster.accessConfig.authenticationMode")
}

test_missing_4_2_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/namespaces",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.2.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.2.1: evidence missing — ")
	contains(msgs[0], "namespaces")
}

test_missing_4_2_2 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/namespaces",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.2.2:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.2.2: evidence missing — ")
	contains(msgs[0], "namespaces")
}

test_missing_4_2_3 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/namespaces",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.2.3:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.2.3: evidence missing — ")
	contains(msgs[0], "namespaces")
}

test_missing_4_2_4 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/namespaces",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.2.4:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.2.4: evidence missing — ")
	contains(msgs[0], "namespaces")
}

test_missing_4_2_5 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/namespaces",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.2.5:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.2.5: evidence missing — ")
	contains(msgs[0], "namespaces")
}

test_missing_4_3_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/vpc_cni",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.3.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.3.1: evidence missing — ")
	contains(msgs[0], "vpc_cni")
}

test_missing_4_4_1 if {
	v := p_run([{
		"op": "replace",
		"path": "/cis_eks/workloads",
		"value": [],
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.4.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.4.1: evidence missing — ")
	contains(msgs[0], "workloads")
}

test_missing_4_5_2 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/workloads",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 4.5.2:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 4.5.2: evidence missing — ")
	contains(msgs[0], "workloads")
}

test_missing_5_1_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/ecr",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 5.1.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 5.1.1: evidence missing — ")
	contains(msgs[0], "ecr.repository_scanning_configurations")
}

test_missing_5_2_1 if {
	v := p_run([{
		"op": "replace",
		"path": "/cis_eks/service_accounts",
		"value": [],
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 5.2.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 5.2.1: evidence missing — ")
	contains(msgs[0], "service_accounts")
}

test_missing_5_4_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/cluster/resourcesVpcConfig",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 5.4.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 5.4.1: evidence missing — ")
	contains(msgs[0], "cluster.resourcesVpcConfig")
}

test_missing_5_4_2 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/cluster/resourcesVpcConfig/endpointPublicAccess",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 5.4.2:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 5.4.2: evidence missing — ")
	contains(msgs[0], "cluster.resourcesVpcConfig")
}

test_missing_5_5_1 if {
	v := p_run([{
		"op": "remove",
		"path": "/cis_eks/access_entries",
	}])
	msgs := [m | some m in v; startswith(m, "CIS EKS 5.5.1:")]
	count(msgs) == 1
	startswith(msgs[0], "CIS EKS 5.5.1: evidence missing — ")
	contains(msgs[0], "access_entries")
}

# ── Edge cases ───────────────────────────────────────────────────────────────

# Every control is in the table, all Level 1, 29 Automated / 18 Manual.
test_controls_table_matches_workbook if {
	count(main.controls) == 47
	count([i | some i, c in main.controls; c.assessment == "Automated"]) == 29
	count([i | some i, c in main.controls; c.assessment == "Manual"]) == 18
	every _, c in main.controls {
		c.level == 1
	}
}

# Automated controls are exactly those with evidence requirements; Manual ones those with attestation keys.
test_automated_and_manual_partition if {
	auto := {i | some i, c in main.controls; c.assessment == "Automated"}
	manual := {i | some i, c in main.controls; c.assessment == "Manual"}
	auto == {i | some i, _ in main.requires}
	manual == {i | some i, _ in main.manual_attestations}
}

# 2.1.1: log types listed in a disabled entry do not count.
test_disabled_log_types_fail if {
	v := p_run([{"op": "add", "path": "/cis_eks/cluster/logging/clusterLogging/0/enabled", "value": false}])
	"CIS EKS 2.1.1: control plane log types not enabled: api, audit, authenticator, controllerManager, scheduler" in v
}

# An empty node list is not evidence.
test_empty_nodes_is_missing if {
	v := p_run([{"op": "replace", "path": "/cis_eks/nodes", "value": []}])
	"CIS EKS 3.2.1: evidence missing — nodes[].configz.kubeletconfig not collected" in v
	"CIS EKS 3.1.1: evidence missing — nodes[].kubeconfig_file not collected" in v
}

# Mode 0640 and 0400 are within 644; an unparsable mode fails closed.
test_mode_stricter_passes if {
	v := p_run([{"op": "replace", "path": "/cis_eks/nodes/0/kubelet_config_file/mode", "value": "0400"}])
	not "3.1.3" in p_ids(v)
}

test_mode_unparsable_fails if {
	v := p_run([{"op": "replace", "path": "/cis_eks/nodes/0/kubelet_config_file/mode", "value": "rw-r--r--"}])
	"3.1.3" in p_ids(v)
}

# 3.1.3 requires the kubelet config file; exists:false is a finding, not a pass.
test_kubelet_config_absent_fails if {
	v := p_run([{"op": "replace", "path": "/cis_eks/nodes/0/kubelet_config_file", "value": {"exists": false}}])
	"3.1.3" in p_ids(v)
	"3.1.4" in p_ids(v)
}

# 3.2.8: a missing feature gate is treated as not enabled.
test_missing_feature_gate_fails if {
	v := p_run([{"op": "remove", "path": "/cis_eks/nodes/0/configz/kubeletconfig/featureGates"}])
	"3.2.8" in p_ids(v)
}

# 3.2.6: a missing eventRecordQPS is a finding.
test_missing_event_qps_fails if {
	v := p_run([{"op": "remove", "path": "/cis_eks/nodes/0/configz/kubeletconfig/eventRecordQPS"}])
	"3.2.6" in p_ids(v)
}

# 4.3.1: self-managed aws-node with the network policy agent enabled passes.
test_vpc_cni_self_managed_passes if {
	v := p_run([{"op": "replace", "path": "/cis_eks/vpc_cni", "value": {"aws_node_args": ["--enable-network-policy=true"]}}])
	not "4.3.1" in p_ids(v)
}

# 4.3.1: invalid JSON in configurationValues fails instead of erroring.
test_vpc_cni_invalid_json_fails if {
	v := p_run([{"op": "replace", "path": "/cis_eks/vpc_cni/addon/configurationValues", "value": "not json"}])
	"CIS EKS 4.3.1: VPC CNI network policy support is not enabled" in v
}

test_vpc_cni_addon_inactive_fails if {
	v := p_run([{"op": "replace", "path": "/cis_eks/vpc_cni/addon/status", "value": "DEGRADED"}])
	"4.3.1" in p_ids(v)
}

# 5.1.1: an attested third-party scanner stands in for ECR scanning evidence.
test_third_party_scanner_passes if {
	v := p_run([
		{"op": "remove", "path": "/cis_eks/ecr"},
		{"op": "add", "path": "/cis_eks/attest/third_party_image_scanning", "value": true},
	])
	not "5.1.1" in p_ids(v)
}

# 5.4.1: public endpoint with a narrow allowlist plus private access passes 5.4.1.
test_public_endpoint_with_allowlist_passes_541 if {
	v := p_run([
		{"op": "replace", "path": "/cis_eks/cluster/resourcesVpcConfig/endpointPublicAccess", "value": true},
		{"op": "replace", "path": "/cis_eks/cluster/resourcesVpcConfig/publicAccessCidrs", "value": ["203.0.113.5/32"]},
	])
	not "5.4.1" in p_ids(v)
}

# 5.4.1: public endpoint with no allowlist fails.
test_public_endpoint_without_allowlist_fails_541 if {
	v := p_run([{"op": "replace", "path": "/cis_eks/cluster/resourcesVpcConfig/endpointPublicAccess", "value": true}])
	"5.4.1" in p_ids(v)
}

# 4.2.x: an unlabelled workload namespace fails every PSA control.
test_unlabelled_namespace_fails_psa if {
	v := p_run([{"op": "add", "path": "/cis_eks/namespaces/-", "value": {"metadata": {"name": "team-b"}}}])
	{"4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5"} == p_ids(v)
}

# 4.2.5: a container that leaves allowPrivilegeEscalation unset fails (restricted needs false).
test_unset_privilege_escalation_fails if {
	v := p_run([{"op": "remove", "path": "/cis_eks/workloads/1/spec/containers/0/securityContext"}])
	p_ids(v) == {"4.2.5"}
}

# exempt_namespaces moves a namespace out of scope for the workload checks.
test_exempt_namespace_respected if {
	v := p_run([
		{"op": "add", "path": "/cis_eks/namespaces/-", "value": {"metadata": {"name": "amazon-cloudwatch"}}},
		{"op": "add", "path": "/cis_eks/exempt_namespaces", "value": ["amazon-cloudwatch"]},
	])
	count(v) == 0
}

# 4.1.5 / 5.2.1: a workload that omits serviceAccountName runs as default.
test_implicit_default_sa_fails if {
	v := p_run([{"op": "remove", "path": "/cis_eks/workloads/0/spec/template/spec/serviceAccountName"}])
	"CIS EKS 4.1.5: default service accounts are in use: apps/Deployment/web" in v
	"CIS EKS 5.2.1: workloads do not use dedicated service accounts: apps/Deployment/web" in v
}

# 4.1.6: the ServiceAccount's automount setting applies when the pod does not set one.
test_token_mount_via_service_account if {
	v := p_run([{"op": "replace", "path": "/cis_eks/token_mount_allowed", "value": []}])
	"CIS EKS 4.1.6: service account tokens are mounted without a documented need: apps/CronJob/report" in v
}

# 4.4.1: envFrom secretRef is detected too.
test_env_from_secret_fails if {
	v := p_run([{"op": "add", "path": "/cis_eks/workloads/1/spec/containers/0/envFrom", "value": [{"secretRef": {"name": "db"}}]}])
	"CIS EKS 4.4.1: workloads read secrets from environment variables: apps/Pod/web-abc" in v
}

# 4.1.7 / 5.5.1: no access entries at all.
test_no_access_entries_fails if {
	v := p_run([{"op": "replace", "path": "/cis_eks/access_entries", "value": []}])
	"CIS EKS 4.1.7: no EKS access entries are defined" in v
	"5.5.1" in p_ids(v)
}

# Manual control: an attestation that is not literally true does not pass.
test_attestation_must_be_true if {
	v := p_run([{"op": "replace", "path": "/cis_eks/attest/private_nodes", "value": "yes"}])
	p_ids(v) == {"5.4.3"}
}

# Failing input still yields a fully populated report.
test_report_populated_on_failing_input if {
	r := main.compliance_report with input as json.patch(p_base, [{"op": "replace", "path": "/cis_eks/attest/private_nodes", "value": false}])
	r.compliant == false
	r.violation_count == 1
	r.total_controls == 47
	r.section_summary["5"] == 1
}

# {} is not evidence: an empty configz must not let 3.2.4 pass on an absent readOnlyPort.
test_empty_kubeletconfig_is_missing if {
	v := p_run([{"op": "replace", "path": "/cis_eks/nodes/1/configz/kubeletconfig", "value": {}}])
	"CIS EKS 3.2.4: evidence missing — nodes[].configz.kubeletconfig not collected" in v
	count([m | some m in v; startswith(m, "CIS EKS 3.2.4:")]) == 1
}

test_empty_kubelet_config_file_is_missing if {
	v := p_run([{"op": "replace", "path": "/cis_eks/nodes/0/kubelet_config_file", "value": {}}])
	"CIS EKS 3.1.3: evidence missing — nodes[].kubelet_config_file not collected" in v
	"CIS EKS 3.1.4: evidence missing — nodes[].kubelet_config_file not collected" in v
}
