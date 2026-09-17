# NSA/CISA Kubernetes Hardening Guidance v1.2 (August 2022)
# CTR_KUBERNETES_HARDENING_GUIDANCE_1.2 — the current version; v1.2
# corrected automountServiceAccountToken guidance and clarified
# ClusterRoleBinding (per the document's own change history).
#
# 43 controls across the guide's five sections:
#   1. Kubernetes Pod security                       (12)
#   2. Network separation and hardening              (14)
#   3. Authentication and authorization               (6)
#   4. Audit logging and threat detection             (7)
#   5. Upgrading and application security practices   (4)
#
# The guide's recommendations mix cluster-config facts (collectable from
# the cluster API / apiserver flags), admission posture, and program
# practices (scanning cadence, patching). The input contract below is one
# field per control; the header notes per group where the fact naturally
# comes from. For manifest-level enforcement of the Pod-security items,
# see the companion Pod Security Standards module (k8s_pss) and the
# admission policies under enforcement/kubernetes/.
#
# Input contract — input.nsa_cisa.* (all booleans):
#   pod_security.{nonroot_containers, readonly_root_filesystems,
#     image_scanning_in_pipeline, privileged_containers_prevented,
#     host_namespaces_denied, hostpath_denied, root_execution_rejected,
#     kernel_hardening_applied, pod_security_admission_enforced,
#     trusted_registries_enforced, image_signature_verification,
#     sa_token_automount_disabled_where_unneeded}
#   network.{control_plane_firewalled, control_plane_separate_network,
#     etcd_access_limited, control_plane_tls, etcd_encrypted_at_rest,
#     etcd_dedicated_tls, namespaces_partition_resources,
#     network_policies_defined, default_deny_policy,
#     resource_limits_enforced, secrets_encrypted_not_in_config,
#     api_server_not_internet_exposed, traffic_tls12_plus,
#     cloud_metadata_access_blocked}
#   authn_authz.{anonymous_auth_disabled, strong_user_authentication,
#     rbac_enabled, least_privilege_roles, kubelet_anonymous_disabled,
#     kubelet_client_tls_auth}
#   logging.{audit_logging_enabled, audit_policy_configured,
#     logs_survive_node_failure, logs_aggregated_externally,
#     monitoring_alerting_configured, pod_baselines_established,
#     rbac_periodically_audited}
#   updates.{patches_promptly_applied, periodic_scans_and_pentests,
#     unused_components_removed, cis_benchmark_adherence}
#
# Fail-closed: absent facts fire all 43 controls.
#
# OPA query path: /v1/data/nsa_cisa_k8s/main/compliance_report

package nsa_cisa_k8s.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Section 1 — Kubernetes Pod security ──────────────────────────────────────

violations contains msg if {
	not input.nsa_cisa.pod_security.nonroot_containers
	msg := "NSA-K8S 1 (Pod security): Containers are not built/forced to run as non-root users"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.readonly_root_filesystems
	msg := "NSA-K8S 1 (Pod security): Containers do not run with immutable (read-only) root filesystems where possible"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.image_scanning_in_pipeline
	msg := "NSA-K8S 1 (Pod security): Container images are not scanned for vulnerabilities or misconfigurations throughout the build workflow"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.privileged_containers_prevented
	msg := "NSA-K8S 1 (Pod security): Privileged containers are not prevented by a technical control"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.host_namespaces_denied
	msg := "NSA-K8S 1 (Pod security): Breakout-prone features (hostPID, hostIPC, hostNetwork) are not denied"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.hostpath_denied
	msg := "NSA-K8S 1 (Pod security): hostPath volume mounts are not denied"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.root_execution_rejected
	msg := "NSA-K8S 1 (Pod security): Containers executing as root or allowing elevation to root are not rejected"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.kernel_hardening_applied
	msg := "NSA-K8S 1 (Pod security): Kernel-level hardening (SELinux, AppArmor, seccomp) is not applied to workloads"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.pod_security_admission_enforced
	msg := "NSA-K8S 1 (Pod security): Pod Security Admission (baseline or stricter) is not enforced cluster-wide"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.trusted_registries_enforced
	msg := "NSA-K8S 1 (Pod security): Deployments are not restricted to trusted image registries"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.image_signature_verification
	msg := "NSA-K8S 1 (Pod security): Only digitally signed images are not enforced via admission control"
}

violations contains msg if {
	not input.nsa_cisa.pod_security.sa_token_automount_disabled_where_unneeded
	msg := "NSA-K8S 1 (Pod security): automountServiceAccountToken is not set to false for Pods that do not need API access"
}

# ── Section 2 — Network separation and hardening ─────────────────────────────

violations contains msg if {
	not input.nsa_cisa.network.control_plane_firewalled
	msg := "NSA-K8S 2 (Network): Access to control plane nodes is not locked down with a firewall and RBAC"
}

violations contains msg if {
	not input.nsa_cisa.network.control_plane_separate_network
	msg := "NSA-K8S 2 (Network): Control plane components and worker nodes do not use separate networks"
}

violations contains msg if {
	not input.nsa_cisa.network.etcd_access_limited
	msg := "NSA-K8S 2 (Network): Access to the etcd server is not further limited (dedicated node, firewall restricted to API servers)"
}

violations contains msg if {
	not input.nsa_cisa.network.control_plane_tls
	msg := "NSA-K8S 2 (Network): Control plane components do not use authenticated, TLS-encrypted communications"
}

violations contains msg if {
	not input.nsa_cisa.network.etcd_encrypted_at_rest
	msg := "NSA-K8S 2 (Network): etcd is not encrypted at rest"
}

violations contains msg if {
	not input.nsa_cisa.network.etcd_dedicated_tls
	msg := "NSA-K8S 2 (Network): etcd does not use a separate TLS certificate (and trusts more than the API server certificates)"
}

violations contains msg if {
	not input.nsa_cisa.network.namespaces_partition_resources
	msg := "NSA-K8S 2 (Network): Namespaces are not used to partition resources (or user Pods run in kube-system/kube-public)"
}

violations contains msg if {
	not input.nsa_cisa.network.network_policies_defined
	msg := "NSA-K8S 2 (Network): Network policies isolating resources are not defined (CNI must support the NetworkPolicy API)"
}

violations contains msg if {
	not input.nsa_cisa.network.default_deny_policy
	msg := "NSA-K8S 2 (Network): No explicit default-deny (ingress and egress) network policy exists"
}

violations contains msg if {
	not input.nsa_cisa.network.resource_limits_enforced
	msg := "NSA-K8S 2 (Network): LimitRange / ResourceQuota / PID limits are not enforced to prevent resource exhaustion"
}

violations contains msg if {
	not input.nsa_cisa.network.secrets_encrypted_not_in_config
	msg := "NSA-K8S 2 (Network): Credentials are kept in configuration files, or Kubernetes Secrets are not encrypted with a strong method (they are not encrypted by default)"
}

violations contains msg if {
	not input.nsa_cisa.network.api_server_not_internet_exposed
	msg := "NSA-K8S 2 (Network): The API server (port 6443) is exposed to the internet or untrusted networks"
}

violations contains msg if {
	not input.nsa_cisa.network.traffic_tls12_plus
	msg := "NSA-K8S 2 (Network): Cluster traffic is not encrypted with TLS 1.2 or 1.3 throughout"
}

violations contains msg if {
	not input.nsa_cisa.network.cloud_metadata_access_blocked
	msg := "NSA-K8S 2 (Network): Pods can reach the cloud instance metadata service (privilege-escalation vector)"
}

# ── Section 3 — Authentication and authorization ─────────────────────────────

violations contains msg if {
	not input.nsa_cisa.authn_authz.anonymous_auth_disabled
	msg := "NSA-K8S 3 (AuthN/AuthZ): API server anonymous authentication is not disabled (--anonymous-auth=false)"
}

violations contains msg if {
	not input.nsa_cisa.authn_authz.strong_user_authentication
	msg := "NSA-K8S 3 (AuthN/AuthZ): Strong user authentication is not implemented (or weak methods like static password files are in use)"
}

violations contains msg if {
	not input.nsa_cisa.authn_authz.rbac_enabled
	msg := "NSA-K8S 3 (AuthN/AuthZ): RBAC is not enabled (--authorization-mode=RBAC), or AlwaysAllow is in effect"
}

violations contains msg if {
	not input.nsa_cisa.authn_authz.least_privilege_roles
	msg := "NSA-K8S 3 (AuthN/AuthZ): RBAC policies with unique least-privilege roles per users, administrators, developers, service accounts, and infrastructure team are not in place"
}

violations contains msg if {
	not input.nsa_cisa.authn_authz.kubelet_anonymous_disabled
	msg := "NSA-K8S 3 (AuthN/AuthZ): Anonymous access to the kubelet service is not disabled"
}

violations contains msg if {
	not input.nsa_cisa.authn_authz.kubelet_client_tls_auth
	msg := "NSA-K8S 3 (AuthN/AuthZ): Kubelet client TLS authentication is not enforced"
}

# ── Section 4 — Audit logging and threat detection ───────────────────────────

violations contains msg if {
	not input.nsa_cisa.logging.audit_logging_enabled
	msg := "NSA-K8S 4 (Logging): Kubernetes audit logging is not enabled (it is disabled by default)"
}

violations contains msg if {
	not input.nsa_cisa.logging.audit_policy_configured
	msg := "NSA-K8S 4 (Logging): No audit policy is configured (security-critical events at RequestResponse; requests involving Secrets reduced to Metadata level)"
}

violations contains msg if {
	not input.nsa_cisa.logging.logs_survive_node_failure
	msg := "NSA-K8S 4 (Logging): Logs are not persisted to survive node, Pod, or container failure"
}

violations contains msg if {
	not input.nsa_cisa.logging.logs_aggregated_externally
	msg := "NSA-K8S 4 (Logging): Logs are not aggregated external to the cluster (TLS 1.2/1.3 in transit, append-only forwarder access)"
}

violations contains msg if {
	not input.nsa_cisa.logging.monitoring_alerting_configured
	msg := "NSA-K8S 4 (Logging): No log monitoring and alerting system (SIEM or equivalent) is tailored to the cluster"
}

violations contains msg if {
	not input.nsa_cisa.logging.pod_baselines_established
	msg := "NSA-K8S 4 (Logging): Pod behavioral baselines (network, requests, resource consumption) are not established at creation for anomaly detection"
}

violations contains msg if {
	not input.nsa_cisa.logging.rbac_periodically_audited
	msg := "NSA-K8S 4 (Logging): RBAC policy configuration is not periodically reviewed (and on personnel changes)"
}

# ── Section 5 — Upgrading and application security practices ─────────────────

violations contains msg if {
	not input.nsa_cisa.updates.patches_promptly_applied
	msg := "NSA-K8S 5 (Upgrading): Security patches and updates are not promptly applied (Kubernetes, hosts, hypervisors, plugins, CI/CD elements)"
}

violations contains msg if {
	not input.nsa_cisa.updates.periodic_scans_and_pentests
	msg := "NSA-K8S 5 (Upgrading): Periodic vulnerability scans and penetration tests are not performed"
}

violations contains msg if {
	not input.nsa_cisa.updates.unused_components_removed
	msg := "NSA-K8S 5 (Upgrading): Unused components are not uninstalled and deleted from the environment"
}

violations contains msg if {
	not input.nsa_cisa.updates.cis_benchmark_adherence
	msg := "NSA-K8S 5 (Upgrading): CIS benchmarks for Kubernetes and system components are not adhered to / periodically verified"
}

# ── Per-section rollup ───────────────────────────────────────────────────────

section_summary := {
	"pod_security": count([v | some v in violations; startswith(v, "NSA-K8S 1")]),
	"network_separation": count([v | some v in violations; startswith(v, "NSA-K8S 2")]),
	"authn_authz": count([v | some v in violations; startswith(v, "NSA-K8S 3")]),
	"audit_logging": count([v | some v in violations; startswith(v, "NSA-K8S 4")]),
	"upgrading_appsec": count([v | some v in violations; startswith(v, "NSA-K8S 5")]),
}

# ── Compliance Report ────────────────────────────────────────────────────────

default assessment_date := "unknown"

assessment_date := input.assessment_date

default cluster_name := "unknown"

cluster_name := input.cluster_name

compliance_report := {
	"framework": "NSA/CISA Kubernetes Hardening Guidance",
	"version": "v1.2 (August 2022)",
	"cluster_name": cluster_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 43,
	"violations": violations,
	"violation_count": count(violations),
	"section_summary": section_summary,
}
