package stig.openshift_4

# DISA STIG for Red Hat OpenShift Container Platform 4.x
# Version: V2R1 baseline (released 2024)
# https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=container-platform
#
# Covers the OCP-specific DISA STIG controls in addition to the
# underlying Kubernetes controls (which are evaluated separately —
# see stig.kubernetes package).
#
# OCP-specific concerns: cluster operators, OAuth, SCCs (Security
# Context Constraints), MachineConfigOperator, image registry,
# router/ingress, monitoring stack, cluster logging, FIPS mode,
# etcd operator, OperatorHub policy, certificate rotation.
#
# Input is the JSON facts document emitted by an Ansible fact
# collector or oc client wrapper against the cluster.

import rego.v1

# =============================================================================
# CAT I — CRITICAL
# =============================================================================

finding_v_257501_fips_mode := {
	"vuln_id": "V-257501",
	"stig_id": "OCP-04-000010",
	"severity": "CAT I",
	"rule_title": "OpenShift must be running in FIPS mode",
	"status": fips_mode_status,
}
fips_mode_status := "Open" if {
	input.cluster.fips_enabled != true
} else := "Not_a_Finding"

finding_v_257502_etcd_encryption := {
	"vuln_id": "V-257502",
	"stig_id": "OCP-04-000020",
	"severity": "CAT I",
	"rule_title": "OpenShift etcd must encrypt secrets and configmaps at rest",
	"status": etcd_encryption_status,
}
etcd_encryption_status := "Open" if {
	input.etcd.encryption_at_rest_enabled != true
} else := "Open" if {
	not input.etcd.encryption_type in {"aescbc", "aesgcm"}
} else := "Not_a_Finding"

finding_v_257503_oauth_no_htpasswd_only := {
	"vuln_id": "V-257503",
	"stig_id": "OCP-04-000030",
	"severity": "CAT I",
	"rule_title": "OpenShift OAuth must use an approved enterprise identity provider, not htpasswd alone",
	"status": oauth_idp_status,
}
oauth_idp_status := "Open" if {
	idps := input.oauth.identity_providers
	count(idps) == 1
	idps[0].type == "htpasswd"
} else := "Open" if {
	count(input.oauth.identity_providers) == 0
} else := "Not_a_Finding"

finding_v_257504_no_kubeadmin := {
	"vuln_id": "V-257504",
	"stig_id": "OCP-04-000040",
	"severity": "CAT I",
	"rule_title": "OpenShift kubeadmin user must be removed after enterprise IDP is configured",
	"status": kubeadmin_status,
}
kubeadmin_status := "Open" if {
	input.cluster.kubeadmin_user_exists == true
	count(input.oauth.identity_providers) > 0
} else := "Not_a_Finding"

finding_v_257505_scc_anyuid_restricted := {
	"vuln_id": "V-257505",
	"stig_id": "OCP-04-000050",
	"severity": "CAT I",
	"rule_title": "OpenShift SCC 'anyuid' must not be bound to default service accounts",
	"status": anyuid_binding_status,
}
anyuid_binding_status := "Open" if {
	binding := input.scc.bindings[_]
	binding.scc_name == "anyuid"
	subject := binding.subjects[_]
	subject.name == "default"
	subject.kind == "ServiceAccount"
} else := "Not_a_Finding"

finding_v_257506_scc_privileged_restricted := {
	"vuln_id": "V-257506",
	"stig_id": "OCP-04-000060",
	"severity": "CAT I",
	"rule_title": "OpenShift SCC 'privileged' must only be bound to platform service accounts",
	"status": privileged_scc_status,
}
privileged_scc_status := "Open" if {
	binding := input.scc.bindings[_]
	binding.scc_name == "privileged"
	subject := binding.subjects[_]
	not startswith(subject.namespace, "openshift-")
	subject.namespace != "kube-system"
} else := "Not_a_Finding"

# =============================================================================
# CAT II — HIGH
# =============================================================================

finding_v_257510_audit_logging := {
	"vuln_id": "V-257510",
	"stig_id": "OCP-04-001000",
	"severity": "CAT II",
	"rule_title": "OpenShift API server must enable audit logging at WriteRequestBodies or higher",
	"status": audit_logging_status,
}
audit_logging_status := "Open" if {
	not input.api_server.audit_profile in {"WriteRequestBodies", "AllRequestBodies"}
} else := "Not_a_Finding"

finding_v_257511_cluster_logging := {
	"vuln_id": "V-257511",
	"stig_id": "OCP-04-001010",
	"severity": "CAT II",
	"rule_title": "OpenShift cluster logging operator must be installed and healthy",
	"status": cluster_logging_status,
}
cluster_logging_status := "Open" if {
	input.operators.cluster_logging.installed != true
} else := "Open" if {
	input.operators.cluster_logging.health != "Healthy"
} else := "Not_a_Finding"

finding_v_257512_monitoring_stack := {
	"vuln_id": "V-257512",
	"stig_id": "OCP-04-001020",
	"severity": "CAT II",
	"rule_title": "OpenShift monitoring stack must be enabled (Prometheus + Alertmanager)",
	"status": monitoring_status,
}
monitoring_status := "Open" if {
	input.operators.cluster_monitoring.installed != true
} else := "Not_a_Finding"

finding_v_257513_image_registry_tls := {
	"vuln_id": "V-257513",
	"stig_id": "OCP-04-001030",
	"severity": "CAT II",
	"rule_title": "OpenShift internal image registry must require TLS",
	"status": registry_tls_status,
}
registry_tls_status := "Open" if {
	input.image_registry.tls_enabled != true
} else := "Not_a_Finding"

finding_v_257514_ingress_tls := {
	"vuln_id": "V-257514",
	"stig_id": "OCP-04-001040",
	"severity": "CAT II",
	"rule_title": "OpenShift Ingress Controller default certificate must be DoD-compliant (not self-signed)",
	"status": ingress_cert_status,
}
ingress_cert_status := "Open" if {
	input.ingress.default_certificate_self_signed == true
} else := "Not_a_Finding"

finding_v_257515_console_session_timeout := {
	"vuln_id": "V-257515",
	"stig_id": "OCP-04-001050",
	"severity": "CAT II",
	"rule_title": "OpenShift web console session timeout must be ≤ 15 minutes",
	"status": console_timeout_status,
}
console_timeout_status := "Open" if {
	input.console.session_timeout_minutes > 15
} else := "Not_a_Finding"

finding_v_257516_oauth_token_max_age := {
	"vuln_id": "V-257516",
	"stig_id": "OCP-04-001060",
	"severity": "CAT II",
	"rule_title": "OpenShift OAuth access token max age must be ≤ 24 hours",
	"status": token_max_age_status,
}
token_max_age_status := "Open" if {
	input.oauth.access_token_max_age_seconds > 86400
} else := "Not_a_Finding"

finding_v_257517_oauth_token_inactivity := {
	"vuln_id": "V-257517",
	"stig_id": "OCP-04-001070",
	"severity": "CAT II",
	"rule_title": "OpenShift OAuth access token inactivity timeout must be ≤ 15 minutes",
	"status": token_inactivity_status,
}
token_inactivity_status := "Open" if {
	input.oauth.access_token_inactivity_timeout_seconds > 900
} else := "Open" if {
	input.oauth.access_token_inactivity_timeout_seconds == 0
} else := "Not_a_Finding"

finding_v_257518_default_deny_netpol := {
	"vuln_id": "V-257518",
	"stig_id": "OCP-04-001080",
	"severity": "CAT II",
	"rule_title": "User-created namespaces must have a default-deny NetworkPolicy",
	"status": default_deny_netpol_status,
}
default_deny_netpol_status := "Open" if {
	ns := input.namespaces[_]
	not startswith(ns.name, "openshift-")
	not startswith(ns.name, "kube-")
	ns.name != "default"
	ns.has_default_deny_netpol == false
} else := "Not_a_Finding"

finding_v_257519_operator_hub_restricted := {
	"vuln_id": "V-257519",
	"stig_id": "OCP-04-001090",
	"severity": "CAT II",
	"rule_title": "OperatorHub default sources must be limited to approved catalogs",
	"status": operator_hub_status,
}
operator_hub_status := "Open" if {
	src := input.operator_hub.enabled_sources[_]
	not src in {"redhat-operators", "certified-operators", "redhat-marketplace"}
} else := "Not_a_Finding"

finding_v_257520_image_signature_policy := {
	"vuln_id": "V-257520",
	"stig_id": "OCP-04-001100",
	"severity": "CAT II",
	"rule_title": "Container images must be verified with image signature policies",
	"status": image_signature_status,
}
image_signature_status := "Open" if {
	input.image_policy.signature_verification_enabled != true
} else := "Not_a_Finding"

finding_v_257521_machine_config_drift := {
	"vuln_id": "V-257521",
	"stig_id": "OCP-04-001110",
	"severity": "CAT II",
	"rule_title": "MachineConfigOperator must report nodes as updated (no drift)",
	"status": mco_status,
}
mco_status := "Open" if {
	pool := input.machine_config_pools[_]
	pool.degraded == true
} else := "Open" if {
	pool := input.machine_config_pools[_]
	pool.updated == false
} else := "Not_a_Finding"

finding_v_257522_certificate_expiry := {
	"vuln_id": "V-257522",
	"stig_id": "OCP-04-001120",
	"severity": "CAT II",
	"rule_title": "Cluster certificates must not be within 30 days of expiry",
	"status": cert_expiry_status,
}
cert_expiry_status := "Open" if {
	cert := input.certificates[_]
	cert.days_until_expiry < 30
} else := "Not_a_Finding"

# =============================================================================
# CAT III — MEDIUM
# =============================================================================

finding_v_257530_telemetry_dod := {
	"vuln_id": "V-257530",
	"stig_id": "OCP-04-002000",
	"severity": "CAT III",
	"rule_title": "Telemetry must be disabled in disconnected / classified environments",
	"status": telemetry_status,
}
telemetry_status := "Open" if {
	input.cluster.disconnected_install == true
	input.cluster.telemetry_enabled == true
} else := "Not_a_Finding"

finding_v_257531_dashboard_disabled := {
	"vuln_id": "V-257531",
	"stig_id": "OCP-04-002010",
	"severity": "CAT III",
	"rule_title": "Kubernetes Dashboard must not be installed (use OpenShift web console)",
	"status": dashboard_status,
}
dashboard_status := "Open" if {
	input.workloads.kubernetes_dashboard_installed == true
} else := "Not_a_Finding"

finding_v_257532_log_retention := {
	"vuln_id": "V-257532",
	"stig_id": "OCP-04-002020",
	"severity": "CAT III",
	"rule_title": "Cluster logging retention must be at least 30 days",
	"status": log_retention_status,
}
log_retention_status := "Open" if {
	input.cluster_logging.retention_days < 30
} else := "Not_a_Finding"

finding_v_257533_pod_security_admission := {
	"vuln_id": "V-257533",
	"stig_id": "OCP-04-002030",
	"severity": "CAT III",
	"rule_title": "User namespaces must enforce Pod Security Standards at 'restricted' level",
	"status": psa_level_status,
}
psa_level_status := "Open" if {
	ns := input.namespaces[_]
	not startswith(ns.name, "openshift-")
	not startswith(ns.name, "kube-")
	ns.name != "default"
	ns.pod_security_enforce_level != "restricted"
} else := "Not_a_Finding"

finding_v_257534_root_account_use := {
	"vuln_id": "V-257534",
	"stig_id": "OCP-04-002040",
	"severity": "CAT III",
	"rule_title": "Workload containers should run as non-root by default",
	"status": root_workload_status,
}
root_workload_status := "Open" if {
	pod := input.pods[_]
	not startswith(pod.namespace, "openshift-")
	not startswith(pod.namespace, "kube-")
	container := pod.spec.containers[_]
	container.security_context.run_as_user == 0
} else := "Not_a_Finding"

# =============================================================================
# AGGREGATE REPORT
# =============================================================================

all_findings := [
	finding_v_257501_fips_mode,
	finding_v_257502_etcd_encryption,
	finding_v_257503_oauth_no_htpasswd_only,
	finding_v_257504_no_kubeadmin,
	finding_v_257505_scc_anyuid_restricted,
	finding_v_257506_scc_privileged_restricted,
	finding_v_257510_audit_logging,
	finding_v_257511_cluster_logging,
	finding_v_257512_monitoring_stack,
	finding_v_257513_image_registry_tls,
	finding_v_257514_ingress_tls,
	finding_v_257515_console_session_timeout,
	finding_v_257516_oauth_token_max_age,
	finding_v_257517_oauth_token_inactivity,
	finding_v_257518_default_deny_netpol,
	finding_v_257519_operator_hub_restricted,
	finding_v_257520_image_signature_policy,
	finding_v_257521_machine_config_drift,
	finding_v_257522_certificate_expiry,
	finding_v_257530_telemetry_dod,
	finding_v_257531_dashboard_disabled,
	finding_v_257532_log_retention,
	finding_v_257533_pod_security_admission,
	finding_v_257534_root_account_use,
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
	"framework": "DISA STIG Red Hat OpenShift Container Platform 4.x",
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
	"note": "Evaluate alongside stig.kubernetes for the underlying K8s controls.",
}
