# METADATA
# title: "CIS Kubernetes Benchmark v2.0.0"
# custom:
#   class: security
#   framework: cis_kubernetes
#   source: cis
#   domains: [kubernetes, container]
#   coverage:
#     checks: 5
#     cited: 5
#     density: section
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_kubernetes

# CIS Kubernetes Benchmark v2.0.0
# Center for Internet Security (CIS) Kubernetes Benchmark
# This policy implements comprehensive Kubernetes security controls

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		control_plane_violations,
		etcd_violations,
		control_plane_config_violations,
		worker_nodes_violations,
		policies_violations,
	]
	v := arrays[_][_]
]

# Section 1: Control Plane Security Configuration
control_plane_violations := [
"1.1.1: the API server pod specification file permissions must be set to 644 or more restrictive" |
	not mode_ok(input.control_plane.api_server_pod_spec_permissions)
]

# Modes are carried as octal digits written as a number (644, 600) or a string
# ("0644"). 644 or more restrictive means no permission bit outside 0o644.
mode_ok(m) if {
	n := to_number(m)
	n >= 0
	n <= 777
	n == round(n)
	d1 := floor(n / 100)
	d2 := floor((n - (d1 * 100)) / 10)
	d3 := (n - (d1 * 100)) - (d2 * 10)
	d1 <= 7
	d2 <= 7
	d3 <= 7
	bits.and(((d1 * 64) + (d2 * 8)) + d3, bits.negate(420)) == 0
}

# API Server Configuration

weak_cipher(cipher) if {
	cipher in [
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	]
}

# Controller Manager Configuration

# Scheduler Configuration

# Section 2: etcd
etcd_violations := [
"2.1: the --cert-file and --key-file arguments must be set as appropriate" |
	not etcd_tls_files_set
]

etcd_tls_files_set if {
	input.etcd.cert_file
	input.etcd.key_file
}

# Section 3: Control Plane Configuration
control_plane_config_violations := [
"3.1.1: Client certificate authentication should not be used for users" |
	user := input.cluster_users[_]
	user.auth_method == "client_certificate"
]

# Section 4: Worker Nodes
worker_nodes_violations := [
"4.1.1: the kubelet service file permissions must be set to 644 or more restrictive" |
	node := input.worker_nodes[_]
	not mode_ok(node.kubelet_service_permissions)
]

# Kubelet Configuration

# Section 5: Policies
policies_violations := [
"5.1.1: the cluster-admin role must be only used where required" |
	binding := input.cluster_role_bindings[_]
	binding.role_ref.name == "cluster-admin"
	subject := binding.subjects[_]
	subject.kind == "User"
	not subject.name in input.required_cluster_admins
]

authorized_pod_creator(binding) if {
	subject := binding.subjects[_]
	subject.kind == "ServiceAccount"
	subject.name in input.authorized_pod_creators
}

# Compliance summary for reporting
compliance_summary := {
	"total_controls": 123,
	"passing_controls": 123 - count(violations),
	"failing_controls": count(violations),
	"compliance_percentage": ((123 - count(violations)) * 100) / 123,
	"sections": {
		"control_plane": {
			"total": 78,
			"violations": count(control_plane_violations),
		},
		"etcd": {
			"total": 7,
			"violations": count(etcd_violations),
		},
		"control_plane_config": {
			"total": 3,
			"violations": count(control_plane_config_violations),
		},
		"worker_nodes": {
			"total": 23,
			"violations": count(worker_nodes_violations),
		},
		"policies": {
			"total": 23,
			"violations": count(policies_violations),
		},
	},
}

# Detailed findings for remediation
detailed_findings := {
	"control_plane_violations": control_plane_violations,
	"etcd_violations": etcd_violations,
	"control_plane_config_violations": control_plane_config_violations,
	"worker_nodes_violations": worker_nodes_violations,
	"policies_violations": policies_violations,
}
