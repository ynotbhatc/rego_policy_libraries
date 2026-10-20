# Per-control tests for cis_eks.main — CIS Amazon EKS Benchmark v2.0.0 (47 controls).
#
# test_ctl_<id>: a compliant base fixture with one change that breaks exactly that
# control; asserts the control's exact message (and that nothing unrelated fires).
# test_ctl_3_2_9 / test_ctl_5_4_5: those IDs were retired in v2.0.0 and must never appear.
# Shares package cis_eks.main_test with the other test files.

package cis_eks.main_test

import rego.v1

import data.cis_eks.main

# Fully compliant fixture.
v_base := {"cis_eks": {
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
v_ids(v) := {substring(m, 8, indexof(m, ":") - 8) | some m in v}

v_run(ops) := v if {
	inp := json.patch(v_base, ops)
	v := main.violations with input as inp
}

test_ctl_2_1_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/cluster/logging/clusterLogging/0/types",
		"value": [
			"api",
			"audit",
		],
	}])
	"CIS EKS 2.1.1: control plane log types not enabled: authenticator, controllerManager, scheduler" in v
	v_ids(v) == {"2.1.1"}
	count(v) == 1
}

test_ctl_3_1_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/kubeconfig_file/mode",
		"value": "0664",
	}])
	"CIS EKS 3.1.1: kubelet kubeconfig file mode is looser than 644 on nodes: node-a" in v
	v_ids(v) == {"3.1.1"}
	count(v) == 1
}

test_ctl_3_1_2 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/kubeconfig_file/group",
		"value": "ec2-user",
	}])
	"CIS EKS 3.1.2: kubelet kubeconfig file is not owned by root:root on nodes: node-a" in v
	v_ids(v) == {"3.1.2"}
	count(v) == 1
}

test_ctl_3_1_3 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/1/kubelet_config_file/mode",
		"value": "755",
	}])
	"CIS EKS 3.1.3: kubelet config file is missing or its mode is looser than 644 on nodes: node-b" in v
	v_ids(v) == {"3.1.3"}
	count(v) == 1
}

test_ctl_3_1_4 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/1/kubelet_config_file/owner",
		"value": "ec2-user",
	}])
	"CIS EKS 3.1.4: kubelet config file is missing or not owned by root:root on nodes: node-b" in v
	v_ids(v) == {"3.1.4"}
	count(v) == 1
}

test_ctl_3_2_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/authentication/anonymous/enabled",
		"value": true,
	}])
	"CIS EKS 3.2.1: kubelet anonymous authentication is not disabled on nodes: node-a" in v
	v_ids(v) == {"3.2.1"}
	count(v) == 1
}

test_ctl_3_2_2 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/authorization/mode",
		"value": "AlwaysAllow",
	}])
	"CIS EKS 3.2.2: kubelet authorization mode is not Webhook on nodes: node-a" in v
	v_ids(v) == {"3.2.2"}
	count(v) == 1
}

test_ctl_3_2_3 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/authentication/x509/clientCAFile",
		"value": "",
	}])
	"CIS EKS 3.2.3: kubelet X.509 client CA file is not configured on nodes: node-a" in v
	v_ids(v) == {"3.2.3"}
	count(v) == 1
}

test_ctl_3_2_4 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/nodes/1/configz/kubeletconfig/readOnlyPort",
		"value": 10255,
	}])
	"CIS EKS 3.2.4: kubelet read-only port is enabled on nodes: node-b" in v
	v_ids(v) == {"3.2.4"}
	count(v) == 1
}

test_ctl_3_2_5 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/makeIPTablesUtilChains",
		"value": false,
	}])
	"CIS EKS 3.2.5: kubelet makeIPTablesUtilChains is not true on nodes: node-a" in v
	v_ids(v) == {"3.2.5"}
	count(v) == 1
}

test_ctl_3_2_6 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/eventRecordQPS",
		"value": 0,
	}])
	"CIS EKS 3.2.6: kubelet eventRecordQPS is missing or 0 (unlimited) on nodes: node-a" in v
	v_ids(v) == {"3.2.6"}
	count(v) == 1
}

test_ctl_3_2_7 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/rotateCertificates",
		"value": false,
	}])
	"CIS EKS 3.2.7: kubelet client certificate rotation is not enabled on nodes: node-a" in v
	v_ids(v) == {"3.2.7"}
	count(v) == 1
}

test_ctl_3_2_8 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/nodes/0/configz/kubeletconfig/featureGates/RotateKubeletServerCertificate",
		"value": false,
	}])
	"CIS EKS 3.2.8: kubelet serverTLSBootstrap and RotateKubeletServerCertificate are not both true on nodes: node-a" in v
	v_ids(v) == {"3.2.8"}
	count(v) == 1
}

test_ctl_4_1_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/cluster_admin_usage_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.1: manual review not attested (set input.cis_eks.attest.cluster_admin_usage_reviewed after review)" in v
	v_ids(v) == {"4.1.1"}
	count(v) == 1
}

test_ctl_4_1_2 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/secrets_access_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.2: manual review not attested (set input.cis_eks.attest.secrets_access_reviewed after review)" in v
	v_ids(v) == {"4.1.2"}
	count(v) == 1
}

test_ctl_4_1_3 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/wildcard_use_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.3: manual review not attested (set input.cis_eks.attest.wildcard_use_reviewed after review)" in v
	v_ids(v) == {"4.1.3"}
	count(v) == 1
}

test_ctl_4_1_4 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/pod_create_access_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.4: manual review not attested (set input.cis_eks.attest.pod_create_access_reviewed after review)" in v
	v_ids(v) == {"4.1.4"}
	count(v) == 1
}

test_ctl_4_1_5 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/role_bindings/-",
		"value": {
			"kind": "RoleBinding",
			"metadata": {
				"namespace": "apps",
				"name": "legacy",
			},
			"subjects": [{
				"kind": "ServiceAccount",
				"name": "default",
				"namespace": "apps",
			}],
		},
	}])
	"CIS EKS 4.1.5: default service accounts are in use: binding RoleBinding/legacy" in v
	v_ids(v) == {"4.1.5"}
	count(v) == 1
}

test_ctl_4_1_6 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/workloads/0/spec/template/spec/automountServiceAccountToken",
		"value": true,
	}])
	"CIS EKS 4.1.6: service account tokens are mounted without a documented need: apps/Deployment/web" in v
	v_ids(v) == {"4.1.6"}
	count(v) == 1
}

test_ctl_4_1_7 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/access_entries/0/accessPolicies",
		"value": [],
	}])
	"CIS EKS 4.1.7: access entries have no access policy or Kubernetes group: arn:aws:iam::111122223333:role/eks-admins" in v
	v_ids(v) == {"4.1.7"}
	count(v) == 1
}

test_ctl_4_1_8 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/bind_impersonate_escalate_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.8: manual review not attested (set input.cis_eks.attest.bind_impersonate_escalate_reviewed after review)" in v
	v_ids(v) == {"4.1.8"}
	count(v) == 1
}

test_ctl_4_1_9 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/pv_create_access_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.9: manual review not attested (set input.cis_eks.attest.pv_create_access_reviewed after review)" in v
	v_ids(v) == {"4.1.9"}
	count(v) == 1
}

test_ctl_4_1_10 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/node_proxy_access_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.10: manual review not attested (set input.cis_eks.attest.node_proxy_access_reviewed after review)" in v
	v_ids(v) == {"4.1.10"}
	count(v) == 1
}

test_ctl_4_1_11 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/webhook_config_access_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.11: manual review not attested (set input.cis_eks.attest.webhook_config_access_reviewed after review)" in v
	v_ids(v) == {"4.1.11"}
	count(v) == 1
}

test_ctl_4_1_12 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/sa_token_creation_reviewed",
		"value": false,
	}])
	"CIS EKS 4.1.12: manual review not attested (set input.cis_eks.attest.sa_token_creation_reviewed after review)" in v
	v_ids(v) == {"4.1.12"}
	count(v) == 1
}

test_ctl_4_2_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/workloads/1/spec/containers/0/securityContext",
		"value": {
			"privileged": true,
			"allowPrivilegeEscalation": false,
		},
	}])
	"CIS EKS 4.2.1: admission of privileged containers is not blocked (PSA enforce level too weak, or running pods use it): apps/Pod/web-abc" in v
	v_ids(v) == {"4.2.1"}
	count(v) == 1
}

test_ctl_4_2_2 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/workloads/1/spec/hostPID",
		"value": true,
	}])
	"CIS EKS 4.2.2: admission of host PID sharing is not blocked (PSA enforce level too weak, or running pods use it): apps/Pod/web-abc" in v
	v_ids(v) == {"4.2.2"}
	count(v) == 1
}

test_ctl_4_2_3 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/workloads/1/spec/hostIPC",
		"value": true,
	}])
	"CIS EKS 4.2.3: admission of host IPC sharing is not blocked (PSA enforce level too weak, or running pods use it): apps/Pod/web-abc" in v
	v_ids(v) == {"4.2.3"}
	count(v) == 1
}

test_ctl_4_2_4 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/workloads/1/spec/hostNetwork",
		"value": true,
	}])
	"CIS EKS 4.2.4: admission of host network sharing is not blocked (PSA enforce level too weak, or running pods use it): apps/Pod/web-abc" in v
	v_ids(v) == {"4.2.4"}
	count(v) == 1
}

test_ctl_4_2_5 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/namespaces/1/metadata/labels/pod-security.kubernetes.io~1enforce",
		"value": "baseline",
	}])
	"CIS EKS 4.2.5: admission of allowPrivilegeEscalation is not blocked (PSA enforce level too weak, or running pods use it): namespace apps" in v
	v_ids(v) == {"4.2.5"}
	count(v) == 1
}

test_ctl_4_3_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/vpc_cni/addon/configurationValues",
		"value": "{}",
	}])
	"CIS EKS 4.3.1: VPC CNI network policy support is not enabled" in v
	v_ids(v) == {"4.3.1"}
	count(v) == 1
}

test_ctl_4_3_2 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/network_policy_coverage_reviewed",
		"value": false,
	}])
	"CIS EKS 4.3.2: manual review not attested (set input.cis_eks.attest.network_policy_coverage_reviewed after review)" in v
	v_ids(v) == {"4.3.2"}
	count(v) == 1
}

test_ctl_4_4_1 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/workloads/0/spec/template/spec/containers/0/env",
		"value": [{
			"name": "DB_PASS",
			"valueFrom": {"secretKeyRef": {
				"name": "db",
				"key": "pass",
			}},
		}],
	}])
	"CIS EKS 4.4.1: workloads read secrets from environment variables: apps/Deployment/web" in v
	v_ids(v) == {"4.4.1"}
	count(v) == 1
}

test_ctl_4_4_2 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/external_secret_storage_reviewed",
		"value": false,
	}])
	"CIS EKS 4.4.2: manual review not attested (set input.cis_eks.attest.external_secret_storage_reviewed after review)" in v
	v_ids(v) == {"4.4.2"}
	count(v) == 1
}

test_ctl_4_5_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/namespace_boundaries_reviewed",
		"value": false,
	}])
	"CIS EKS 4.5.1: manual review not attested (set input.cis_eks.attest.namespace_boundaries_reviewed after review)" in v
	v_ids(v) == {"4.5.1"}
	count(v) == 1
}

test_ctl_4_5_2 if {
	v := v_run([{
		"op": "add",
		"path": "/cis_eks/workloads/-",
		"value": {
			"kind": "Deployment",
			"metadata": {
				"namespace": "default",
				"name": "legacy",
			},
			"spec": {"template": {"spec": {
				"serviceAccountName": "legacy",
				"automountServiceAccountToken": false,
				"containers": [{
					"name": "l",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			}}},
		},
	}])
	"CIS EKS 4.5.2: workloads run in the default namespace: default/Deployment/legacy" in v
	v_ids(v) == {"4.5.2"}
	count(v) == 1
}

test_ctl_5_1_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/ecr/repository_scanning_configurations/0",
		"value": {
			"repositoryName": "apps/web",
			"scanOnPush": false,
			"scanFrequency": "MANUAL",
		},
	}])
	"CIS EKS 5.1.1: ECR repositories are not scanned on push or continuously: apps/web" in v
	v_ids(v) == {"5.1.1"}
	count(v) == 1
}

test_ctl_5_1_2 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/ecr_least_privilege_reviewed",
		"value": false,
	}])
	"CIS EKS 5.1.2: manual review not attested (set input.cis_eks.attest.ecr_least_privilege_reviewed after review)" in v
	v_ids(v) == {"5.1.2"}
	count(v) == 1
}

test_ctl_5_1_3 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/ecr_pull_only_reviewed",
		"value": false,
	}])
	"CIS EKS 5.1.3: manual review not attested (set input.cis_eks.attest.ecr_pull_only_reviewed after review)" in v
	v_ids(v) == {"5.1.3"}
	count(v) == 1
}

test_ctl_5_1_4 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/approved_registries_enforced",
		"value": false,
	}])
	"CIS EKS 5.1.4: manual review not attested (set input.cis_eks.attest.approved_registries_enforced after review)" in v
	v_ids(v) == {"5.1.4"}
	count(v) == 1
}

test_ctl_5_2_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/service_accounts/0/automountServiceAccountToken",
		"value": true,
	}])
	"CIS EKS 5.2.1: workloads do not use dedicated service accounts: serviceaccount apps/default" in v
	v_ids(v) == {"5.2.1"}
	count(v) == 1
}

test_ctl_5_3_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/secrets_cmk_envelope_encryption",
		"value": false,
	}])
	"CIS EKS 5.3.1: manual review not attested (set input.cis_eks.attest.secrets_cmk_envelope_encryption after review)" in v
	v_ids(v) == {"5.3.1"}
	count(v) == 1
}

test_ctl_5_4_1 if {
	v := v_run([
		{
			"op": "replace",
			"path": "/cis_eks/cluster/resourcesVpcConfig/endpointPublicAccess",
			"value": true,
		},
		{
			"op": "replace",
			"path": "/cis_eks/cluster/resourcesVpcConfig/publicAccessCidrs",
			"value": ["0.0.0.0/0"],
		},
	])
	"CIS EKS 5.4.1: control plane endpoint is not private-enabled with a restricted public CIDR allowlist" in v
	v_ids(v) == {"5.4.1", "5.4.2"}
	count(v) == 2
}

test_ctl_5_4_2 if {
	v := v_run([
		{
			"op": "replace",
			"path": "/cis_eks/cluster/resourcesVpcConfig/endpointPublicAccess",
			"value": true,
		},
		{
			"op": "replace",
			"path": "/cis_eks/cluster/resourcesVpcConfig/publicAccessCidrs",
			"value": ["203.0.113.5/32"],
		},
	])
	"CIS EKS 5.4.2: control plane endpoint is not private-only (public endpoint enabled or private endpoint disabled)" in v
	v_ids(v) == {"5.4.2"}
	count(v) == 1
}

test_ctl_5_4_3 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/private_nodes",
		"value": false,
	}])
	"CIS EKS 5.4.3: manual review not attested (set input.cis_eks.attest.private_nodes after review)" in v
	v_ids(v) == {"5.4.3"}
	count(v) == 1
}

test_ctl_5_4_4 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/attest/lb_tls_listeners",
		"value": false,
	}])
	"CIS EKS 5.4.4: manual review not attested (set input.cis_eks.attest.lb_tls_listeners after review)" in v
	v_ids(v) == {"5.4.4"}
	count(v) == 1
}

test_ctl_5_5_1 if {
	v := v_run([{
		"op": "replace",
		"path": "/cis_eks/cluster/accessConfig/authenticationMode",
		"value": "CONFIG_MAP",
	}])
	"CIS EKS 5.5.1: IAM principal access is not managed through EKS access entries" in v
	v_ids(v) == {"5.5.1", "4.1.7"}
	count(v) == 2
}

# 3.2.9 was removed in v2.0.0 — no message may carry it, on empty or compliant input.
test_ctl_3_2_9 if {
	empty := main.violations with input as {}
	base := main.violations with input as v_base
	not "3.2.9" in v_ids(empty)
	not "3.2.9" in v_ids(base)
	not "3.2.9" in object.keys(main.controls)
}

# 5.4.5 was removed in v2.0.0 — no message may carry it, on empty or compliant input.
test_ctl_5_4_5 if {
	empty := main.violations with input as {}
	base := main.violations with input as v_base
	not "5.4.5" in v_ids(empty)
	not "5.4.5" in v_ids(base)
	not "5.4.5" in object.keys(main.controls)
}

# ── Compliant input yields an empty violation set ────────────────────────────

test_ctl_compliant_no_violations if {
	v := main.violations with input as v_base
	count(v) == 0
}

# ── Report rule is a populated object on empty input ─────────────────────────

test_ctl_report_populated_on_empty_input if {
	result := main.compliance_report with input as {}
	is_object(result)
	count(result) > 0
}
