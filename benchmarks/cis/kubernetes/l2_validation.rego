package cis_kubernetes.l2

# CIS Kubernetes Benchmark v1.10.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter settings for high-security clusters.
# Intended for regulated workloads: FedRAMP High, PCI-DSS, HIPAA, DoD IL4/IL5.

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1 - Control Plane Components (L2)
# ---------------------------------------------------------------------------

# API Server L2 controls
violations contains "CIS L2 1.2.1: API server anonymous-auth flag must be false" if {
	input.api_server_flags["anonymous-auth"] != "false"
}

violations contains "CIS L2 1.2.5: API server --kubelet-certificate-authority set" if {
	not input.api_server_flags["kubelet-certificate-authority"]
}

violations contains "CIS L2 1.2.10: API server admission control: EventRateLimit enabled" if {
	not contains(input.api_server_flags["enable-admission-plugins"], "EventRateLimit")
}

violations contains "CIS L2 1.2.11: API server admission control: AlwaysPullImages enabled" if {
	not contains(input.api_server_flags["enable-admission-plugins"], "AlwaysPullImages")
}

violations contains "CIS L2 1.2.13: API server --disable-admission-plugins must not include SecurityContextDeny if PodSecurity admitted" if {
	contains(input.api_server_flags["disable-admission-plugins"], "SecurityContextDeny")
}

violations contains "CIS L2 1.2.18: API server --insecure-bind-address not set" if {
	input.api_server_flags["insecure-bind-address"]
}

violations contains "CIS L2 1.2.19: API server --insecure-port set to 0" if {
	to_number(input.api_server_flags["insecure-port"]) != 0
}

violations contains "CIS L2 1.2.22: API server --audit-log-maxage set to 30 or more days" if {
	to_number(input.api_server_flags["audit-log-maxage"]) < 30
}

violations contains "CIS L2 1.2.23: API server --audit-log-maxbackup set to 10 or more files" if {
	to_number(input.api_server_flags["audit-log-maxbackup"]) < 10
}

violations contains "CIS L2 1.2.24: API server --audit-log-maxsize set to 100 MB or more" if {
	to_number(input.api_server_flags["audit-log-maxsize"]) < 100
}

violations contains "CIS L2 1.2.25: API server audit policy file configured" if {
	not input.api_server_flags["audit-policy-file"]
}

violations contains "CIS L2 1.2.27: API server --service-account-lookup set to true" if {
	input.api_server_flags["service-account-lookup"] != "true"
}

violations contains "CIS L2 1.2.31: API server --encryption-provider-config set (secrets encrypted at rest)" if {
	not input.api_server_flags["encryption-provider-config"]
}

violations contains "CIS L2 1.2.32: API server encryption provider uses aescbc or kms (not identity)" if {
	input.api_server.encryption_provider_identity_used
}

# Controller Manager L2 controls
violations contains "CIS L2 1.3.2: Controller manager --profiling flag set to false" if {
	input.controller_manager_flags["profiling"] != "false"
}

violations contains "CIS L2 1.3.4: Controller manager --use-service-account-credentials set to true" if {
	input.controller_manager_flags["use-service-account-credentials"] != "true"
}

violations contains "CIS L2 1.3.6: Controller manager RotateKubeletServerCertificate feature gate enabled" if {
	not contains(input.controller_manager_flags["feature-gates"], "RotateKubeletServerCertificate=true")
}

# Scheduler L2 controls
violations contains "CIS L2 1.4.1: Scheduler --profiling flag set to false" if {
	input.scheduler_flags["profiling"] != "false"
}

# ---------------------------------------------------------------------------
# Section 2 - etcd (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.1: etcd --cert-file and --key-file set for client TLS" if {
	not input.etcd_flags["cert-file"]
}

violations contains "CIS L2 2.2: etcd --client-cert-auth set to true" if {
	input.etcd_flags["client-cert-auth"] != "true"
}

violations contains "CIS L2 2.6: etcd --peer-cert-file and --peer-key-file configured" if {
	not input.etcd_flags["peer-cert-file"]
}

violations contains "CIS L2 2.7: etcd --peer-client-cert-auth set to true" if {
	input.etcd_flags["peer-client-cert-auth"] != "true"
}

# ---------------------------------------------------------------------------
# Section 3 - Control Plane Configuration (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.2.1: Audit log policy covers metadata level for all API groups" if {
	not input.audit_policy.metadata_level_configured
}

violations contains "CIS L2 3.2.2: Audit log policy captures RequestResponse for sensitive resources" if {
	not input.audit_policy.request_response_configured
}

# ---------------------------------------------------------------------------
# Section 4 - Worker Nodes (L2)
# ---------------------------------------------------------------------------

# Kubelet L2 controls
violations contains "CIS L2 4.2.1: Kubelet --anonymous-auth set to false" if {
	input.kubelet_flags["anonymous-auth"] != "false"
}

violations contains "CIS L2 4.2.5: Kubelet --streaming-connection-idle-timeout not set to 0" if {
	input.kubelet_flags["streaming-connection-idle-timeout"] == "0"
}

violations contains "CIS L2 4.2.6: Kubelet --protect-kernel-defaults set to true" if {
	input.kubelet_flags["protect-kernel-defaults"] != "true"
}

violations contains "CIS L2 4.2.9: Kubelet --event-qps set to 0 (unlimited throttling disabled)" if {
	to_number(input.kubelet_flags["event-qps"]) != 0
}

violations contains "CIS L2 4.2.10: Kubelet --tls-cert-file and --tls-private-key-file set" if {
	not input.kubelet_flags["tls-cert-file"]
}

violations contains "CIS L2 4.2.11: Kubelet --rotate-certificates set to true" if {
	input.kubelet_flags["rotate-certificates"] != "true"
}

violations contains "CIS L2 4.2.12: Kubelet RotateKubeletServerCertificate feature gate enabled" if {
	not contains(input.kubelet_flags["feature-gates"], "RotateKubeletServerCertificate=true")
}

# ---------------------------------------------------------------------------
# Section 5 - Policies (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 5.1.3: Minimize wildcard use in ClusterRoles and Roles" if {
	some role in input.rbac.roles_with_wildcard_verbs
	role != ""
}

violations contains "CIS L2 5.2.2: Minimize admission of privileged containers" if {
	input.pod_security.privileged_containers_allowed
}

violations contains "CIS L2 5.2.3: Minimize admission of containers wishing to share host PID namespace" if {
	input.pod_security.host_pid_allowed
}

violations contains "CIS L2 5.2.4: Minimize admission of containers wishing to share host IPC namespace" if {
	input.pod_security.host_ipc_allowed
}

violations contains "CIS L2 5.2.5: Minimize admission of containers with host network" if {
	input.pod_security.host_network_allowed
}

violations contains "CIS L2 5.2.6: Minimize admission of containers with allowPrivilegeEscalation" if {
	input.pod_security.privilege_escalation_allowed
}

violations contains "CIS L2 5.2.9: Minimize admission of containers with added capabilities" if {
	input.pod_security.added_capabilities_allowed
}

violations contains "CIS L2 5.3.2: All namespaces should have a Network Policy defined" if {
	some ns in input.namespaces_without_network_policy
	not startswith(ns, "kube-")
}

violations contains "CIS L2 5.4.1: Prefer using Secrets as files over Secrets as environment variables" if {
	input.workloads.secrets_as_env_vars_count > 0
}

violations contains "CIS L2 5.7.2: Ensure admission of containers with securityContext allowPrivilegeEscalation=false" if {
	input.pod_security.privilege_escalation_default_allow
}

violations contains "CIS L2 5.7.3: Apply Security Context to Pods and Containers" if {
	input.workloads.pods_without_security_context_count > 0
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 42

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Kubernetes Benchmark v1.10.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(violations),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. Designed for regulated Kubernetes workloads (FedRAMP High, PCI-DSS, HIPAA, DoD IL4/IL5).",
}
