package stig.kubernetes

# DISA STIG for Kubernetes
# Version: V2R1 baseline (released 2024-Q1)
# https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=container-platform
#
# Covers the DISA Kubernetes STIG controls across API server, etcd,
# scheduler, controller manager, kubelet, RBAC, pod security, network
# policy, and audit logging. Severity categories CAT I (critical) /
# CAT II (high) / CAT III (medium) per DISA convention.
#
# Input is the JSON facts document emitted by an Ansible fact
# collector against the cluster — kubectl get componentstatus,
# kube-apiserver flags, kubelet config, etcd config, audit policy,
# RBAC bindings, PodSecurityPolicy / PSA admission, NetworkPolicy
# counts, etc.

import rego.v1

# =============================================================================
# CAT I — CRITICAL
# =============================================================================

finding_v_242390_anonymous_auth := {
	"vuln_id": "V-242390",
	"stig_id": "CNTR-K8-000990",
	"severity": "CAT I",
	"rule_title": "Kubernetes API server must disable anonymous authentication",
	"status": anonymous_auth_status,
}
anonymous_auth_status := "Open" if {
	input.api_server.anonymous_auth_enabled == true
} else := "Not_a_Finding"

finding_v_242391_basic_auth := {
	"vuln_id": "V-242391",
	"stig_id": "CNTR-K8-001000",
	"severity": "CAT I",
	"rule_title": "Kubernetes Kubelet must have anonymous authentication disabled",
	"status": kubelet_anonymous_auth_status,
}
kubelet_anonymous_auth_status := "Open" if {
	input.kubelet.anonymous_auth_enabled == true
} else := "Not_a_Finding"

finding_v_242392_kubelet_authorization := {
	"vuln_id": "V-242392",
	"stig_id": "CNTR-K8-001010",
	"severity": "CAT I",
	"rule_title": "Kubernetes Kubelet must have the read-only port flag disabled",
	"status": kubelet_readonly_port_status,
}
kubelet_readonly_port_status := "Open" if {
	input.kubelet.readonly_port != 0
} else := "Not_a_Finding"

finding_v_242393_etcd_tls_client := {
	"vuln_id": "V-242393",
	"stig_id": "CNTR-K8-001020",
	"severity": "CAT I",
	"rule_title": "Kubernetes etcd must use TLS to protect the confidentiality of communication with clients",
	"status": etcd_client_tls_status,
}
etcd_client_tls_status := "Open" if {
	input.etcd.client_cert_auth_enabled != true
} else := "Not_a_Finding"

finding_v_242394_etcd_tls_peer := {
	"vuln_id": "V-242394",
	"stig_id": "CNTR-K8-001030",
	"severity": "CAT I",
	"rule_title": "Kubernetes etcd must use TLS for peer-to-peer communication",
	"status": etcd_peer_tls_status,
}
etcd_peer_tls_status := "Open" if {
	input.etcd.peer_client_cert_auth_enabled != true
} else := "Not_a_Finding"

finding_v_242395_etcd_encryption_at_rest := {
	"vuln_id": "V-242395",
	"stig_id": "CNTR-K8-001040",
	"severity": "CAT I",
	"rule_title": "Kubernetes Secrets must be encrypted at rest in etcd",
	"status": etcd_encryption_status,
}
etcd_encryption_status := "Open" if {
	input.api_server.encryption_provider_config_set != true
} else := "Not_a_Finding"

finding_v_242396_kubectl_anonymous_token := {
	"vuln_id": "V-242396",
	"stig_id": "CNTR-K8-001050",
	"severity": "CAT I",
	"rule_title": "Kubernetes kubectl must not have insecure-skip-tls-verify set",
	"status": kubectl_skip_tls_status,
}
kubectl_skip_tls_status := "Open" if {
	input.kubeconfig.insecure_skip_tls_verify == true
} else := "Not_a_Finding"

# =============================================================================
# CAT II — HIGH
# =============================================================================

finding_v_242400_audit_logging_enabled := {
	"vuln_id": "V-242400",
	"stig_id": "CNTR-K8-002000",
	"severity": "CAT II",
	"rule_title": "Kubernetes API server must enable audit logging",
	"status": audit_logging_status,
}
audit_logging_status := "Open" if {
	input.api_server.audit_log_path == ""
} else := "Open" if {
	not input.api_server.audit_log_path
} else := "Not_a_Finding"

finding_v_242401_audit_policy_required := {
	"vuln_id": "V-242401",
	"stig_id": "CNTR-K8-002010",
	"severity": "CAT II",
	"rule_title": "Kubernetes API server must have an audit policy configured",
	"status": audit_policy_status,
}
audit_policy_status := "Open" if {
	not input.api_server.audit_policy_file
} else := "Not_a_Finding"

finding_v_242402_authorization_mode := {
	"vuln_id": "V-242402",
	"stig_id": "CNTR-K8-002020",
	"severity": "CAT II",
	"rule_title": "Kubernetes API server must use RBAC for authorization",
	"status": authz_rbac_status,
}
authz_rbac_status := "Open" if {
	not "RBAC" in input.api_server.authorization_modes
} else := "Not_a_Finding"

finding_v_242403_always_admit_off := {
	"vuln_id": "V-242403",
	"stig_id": "CNTR-K8-002030",
	"severity": "CAT II",
	"rule_title": "Kubernetes API server must not have AlwaysAdmit admission controller enabled",
	"status": always_admit_status,
}
always_admit_status := "Open" if {
	"AlwaysAdmit" in input.api_server.enable_admission_plugins
} else := "Not_a_Finding"

finding_v_242404_psa_admission := {
	"vuln_id": "V-242404",
	"stig_id": "CNTR-K8-002040",
	"severity": "CAT II",
	"rule_title": "Kubernetes must have Pod Security Admission enabled",
	"status": psa_status,
}
psa_status := "Open" if {
	not "PodSecurity" in input.api_server.enable_admission_plugins
} else := "Not_a_Finding"

finding_v_242405_namespace_isolation := {
	"vuln_id": "V-242405",
	"stig_id": "CNTR-K8-002050",
	"severity": "CAT II",
	"rule_title": "Kubernetes must use NamespaceLifecycle admission controller",
	"status": namespace_lifecycle_status,
}
namespace_lifecycle_status := "Open" if {
	not "NamespaceLifecycle" in input.api_server.enable_admission_plugins
} else := "Not_a_Finding"

finding_v_242406_default_deny_netpol := {
	"vuln_id": "V-242406",
	"stig_id": "CNTR-K8-002060",
	"severity": "CAT II",
	"rule_title": "Kubernetes namespaces must have a default-deny NetworkPolicy",
	"status": default_deny_netpol_status,
}
default_deny_netpol_status := "Open" if {
	ns := input.namespaces[_]
	ns.is_system == false
	ns.has_default_deny_netpol == false
	some _ in ["check"]
} else := "Not_a_Finding"

finding_v_242407_kubelet_client_ca := {
	"vuln_id": "V-242407",
	"stig_id": "CNTR-K8-002070",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must have client CA file configured",
	"status": kubelet_ca_status,
}
kubelet_ca_status := "Open" if {
	not input.kubelet.client_ca_file
} else := "Open" if {
	input.kubelet.client_ca_file == ""
} else := "Not_a_Finding"

finding_v_242408_kubelet_tls_min_version := {
	"vuln_id": "V-242408",
	"stig_id": "CNTR-K8-002080",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must use TLS 1.2 or higher",
	"status": kubelet_tls_status,
}
kubelet_tls_status := "Open" if {
	not input.kubelet.tls_min_version in {"VersionTLS12", "VersionTLS13"}
} else := "Not_a_Finding"

finding_v_242409_scheduler_profiling := {
	"vuln_id": "V-242409",
	"stig_id": "CNTR-K8-002090",
	"severity": "CAT II",
	"rule_title": "Kubernetes Scheduler must disable profiling",
	"status": scheduler_profiling_status,
}
scheduler_profiling_status := "Open" if {
	input.scheduler.profiling_enabled == true
} else := "Not_a_Finding"

finding_v_242410_controller_profiling := {
	"vuln_id": "V-242410",
	"stig_id": "CNTR-K8-002100",
	"severity": "CAT II",
	"rule_title": "Kubernetes Controller Manager must disable profiling",
	"status": controller_profiling_status,
}
controller_profiling_status := "Open" if {
	input.controller_manager.profiling_enabled == true
} else := "Not_a_Finding"

finding_v_242411_controller_service_account_key := {
	"vuln_id": "V-242411",
	"stig_id": "CNTR-K8-002110",
	"severity": "CAT II",
	"rule_title": "Kubernetes Controller Manager must have service-account-private-key-file set",
	"status": controller_sa_key_status,
}
controller_sa_key_status := "Open" if {
	not input.controller_manager.service_account_private_key_file
} else := "Not_a_Finding"

finding_v_242412_api_server_profiling := {
	"vuln_id": "V-242412",
	"stig_id": "CNTR-K8-002120",
	"severity": "CAT II",
	"rule_title": "Kubernetes API Server must disable profiling",
	"status": api_profiling_status,
}
api_profiling_status := "Open" if {
	input.api_server.profiling_enabled == true
} else := "Not_a_Finding"

finding_v_242413_rbac_no_cluster_admin_default_sa := {
	"vuln_id": "V-242413",
	"stig_id": "CNTR-K8-002130",
	"severity": "CAT II",
	"rule_title": "Kubernetes must not grant cluster-admin to the default service account",
	"status": cluster_admin_default_sa_status,
}
cluster_admin_default_sa_status := "Open" if {
	binding := input.rbac.cluster_role_bindings[_]
	binding.role_name == "cluster-admin"
	some subject in binding.subjects
	subject.name == "default"
	subject.kind == "ServiceAccount"
} else := "Not_a_Finding"

finding_v_242414_no_privileged_pods := {
	"vuln_id": "V-242414",
	"stig_id": "CNTR-K8-002140",
	"severity": "CAT II",
	"rule_title": "Kubernetes must not permit privileged containers in non-system namespaces",
	"status": privileged_pods_status,
}
privileged_pods_status := "Open" if {
	pod := input.pods[_]
	pod.namespace != "kube-system"
	pod.spec.containers[_].security_context.privileged == true
} else := "Not_a_Finding"

finding_v_242415_no_host_network := {
	"vuln_id": "V-242415",
	"stig_id": "CNTR-K8-002150",
	"severity": "CAT II",
	"rule_title": "Kubernetes pods must not run with hostNetwork in user namespaces",
	"status": host_network_status,
}
host_network_status := "Open" if {
	pod := input.pods[_]
	pod.namespace != "kube-system"
	pod.spec.host_network == true
} else := "Not_a_Finding"

# =============================================================================
# CAT III — MEDIUM
# =============================================================================

finding_v_242420_log_max_age := {
	"vuln_id": "V-242420",
	"stig_id": "CNTR-K8-003000",
	"severity": "CAT III",
	"rule_title": "Kubernetes audit log retention must be at least 30 days",
	"status": log_max_age_status,
}
log_max_age_status := "Open" if {
	input.api_server.audit_log_max_age < 30
} else := "Not_a_Finding"

finding_v_242421_log_max_size := {
	"vuln_id": "V-242421",
	"stig_id": "CNTR-K8-003010",
	"severity": "CAT III",
	"rule_title": "Kubernetes audit log rotation must be configured",
	"status": log_max_size_status,
}
log_max_size_status := "Open" if {
	input.api_server.audit_log_max_size <= 0
} else := "Not_a_Finding"

finding_v_242422_kubelet_event_qps := {
	"vuln_id": "V-242422",
	"stig_id": "CNTR-K8-003020",
	"severity": "CAT III",
	"rule_title": "Kubernetes Kubelet must not have event-qps set to 0 (unlimited)",
	"status": kubelet_event_qps_status,
}
kubelet_event_qps_status := "Open" if {
	input.kubelet.event_qps == 0
} else := "Not_a_Finding"

finding_v_242423_kubelet_streaming_idle := {
	"vuln_id": "V-242423",
	"stig_id": "CNTR-K8-003030",
	"severity": "CAT III",
	"rule_title": "Kubernetes Kubelet streaming-connection-idle-timeout must be ≥ 5 minutes",
	"status": kubelet_streaming_status,
}
kubelet_streaming_status := "Open" if {
	input.kubelet.streaming_connection_idle_timeout_seconds < 300
} else := "Not_a_Finding"

finding_v_242424_no_default_sa_token_automount := {
	"vuln_id": "V-242424",
	"stig_id": "CNTR-K8-003040",
	"severity": "CAT III",
	"rule_title": "Default service accounts must not automount API tokens",
	"status": default_sa_automount_status,
}
default_sa_automount_status := "Open" if {
	ns := input.namespaces[_]
	ns.default_sa_automount_token == true
} else := "Not_a_Finding"

finding_v_242425_no_dashboard := {
	"vuln_id": "V-242425",
	"stig_id": "CNTR-K8-003050",
	"severity": "CAT III",
	"rule_title": "Kubernetes Dashboard must not be installed",
	"status": dashboard_status,
}
dashboard_status := "Open" if {
	input.workloads.kubernetes_dashboard_installed == true
} else := "Not_a_Finding"

# =============================================================================
# AGGREGATE REPORT
# =============================================================================

all_findings := [
	finding_v_242390_anonymous_auth,
	finding_v_242391_basic_auth,
	finding_v_242392_kubelet_authorization,
	finding_v_242393_etcd_tls_client,
	finding_v_242394_etcd_tls_peer,
	finding_v_242395_etcd_encryption_at_rest,
	finding_v_242396_kubectl_anonymous_token,
	finding_v_242400_audit_logging_enabled,
	finding_v_242401_audit_policy_required,
	finding_v_242402_authorization_mode,
	finding_v_242403_always_admit_off,
	finding_v_242404_psa_admission,
	finding_v_242405_namespace_isolation,
	finding_v_242406_default_deny_netpol,
	finding_v_242407_kubelet_client_ca,
	finding_v_242408_kubelet_tls_min_version,
	finding_v_242409_scheduler_profiling,
	finding_v_242410_controller_profiling,
	finding_v_242411_controller_service_account_key,
	finding_v_242412_api_server_profiling,
	finding_v_242413_rbac_no_cluster_admin_default_sa,
	finding_v_242414_no_privileged_pods,
	finding_v_242415_no_host_network,
	finding_v_242420_log_max_age,
	finding_v_242421_log_max_size,
	finding_v_242422_kubelet_event_qps,
	finding_v_242423_kubelet_streaming_idle,
	finding_v_242424_no_default_sa_token_automount,
	finding_v_242425_no_dashboard,
]

default compliant := false

open_findings := [f | some f in all_findings; f.status == "Open"]
passed_findings := [f | some f in all_findings; f.status == "Not_a_Finding"]

cat_i_count := count([f | some f in all_findings; f.severity == "CAT I"])
cat_ii_count := count([f | some f in all_findings; f.severity == "CAT II"])
cat_iii_count := count([f | some f in all_findings; f.severity == "CAT III"])

cat_i_open := count([f | some f in open_findings; f.severity == "CAT I"])
cat_ii_open := count([f | some f in open_findings; f.severity == "CAT II"])
cat_iii_open := count([f | some f in open_findings; f.severity == "CAT III"])

total_controls := count(all_findings)
passed_controls := count(passed_findings)
failed_controls := count(open_findings)
pct := round((passed_controls / total_controls) * 100)

compliant if {
	cat_i_open == 0
	cat_ii_open == 0
	cat_iii_open == 0
}

compliance_report := {
	"framework": "DISA STIG Kubernetes",
	"version": "V2R1",
	"total_controls": total_controls,
	"passed_controls": passed_controls,
	"failed_controls": failed_controls,
	"compliance_percentage": pct,
	"compliant": compliant,
	"category_breakdown": {
		"cat_i": {"total": cat_i_count, "open": cat_i_open},
		"cat_ii": {"total": cat_ii_count, "open": cat_ii_open},
		"cat_iii": {"total": cat_iii_count, "open": cat_iii_open},
	},
	"open_findings": [f | some f in open_findings],
	"all_findings": [f | some f in all_findings],
}
