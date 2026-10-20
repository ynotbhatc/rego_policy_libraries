# CIS Amazon EKS Benchmark v2.0.0
#
# All 47 recommendations of the benchmark (29 Automated, 18 Manual; every one is
# Level 1 — the benchmark's Level 2 profile is empty). IDs, titles, levels and
# Automated/Manual status are taken from the official CIS workbook; messages are
# our own words. The `controls` rule below is the full table.
#
# Query: POST /v1/data/cis_eks/main/compliance_report
#
# Fail-closed:
#   - Automated: each control evaluates raw evidence. When the evidence it needs
#     is absent the control emits "CIS EKS <id>: evidence missing — <field> not
#     collected" (never a pass).
#   - Manual: each control passes only on an explicit attestation
#     (input.cis_eks.attest.<key> == true).
#   Each control emits at most one message, so empty input yields exactly 47.
#
# Input contract — input.cis_eks.*
#
#   cluster                    — `aws eks describe-cluster` .cluster object (AWS field names)
#     logging.clusterLogging[]           {types[], enabled}               2.1.1
#     accessConfig.authenticationMode    API | API_AND_CONFIG_MAP | CONFIG_MAP   4.1.7, 5.5.1
#     resourcesVpcConfig.{endpointPublicAccess, endpointPrivateAccess, publicAccessCidrs[]}
#                                                                          5.4.1, 5.4.2
#   access_entries[]           — `aws eks list-access-entries` + `list-associated-access-policies`
#     {principalArn, accessPolicies[], kubernetesGroups[]}                4.1.7, 5.5.1
#   nodes[]                    — one object per worker node
#     name
#     kubeconfig_file      {exists, mode, owner, group}   (stat of the --kubeconfig file)   3.1.1, 3.1.2
#     kubelet_config_file  {exists, mode, owner, group}   (stat of the --config file)       3.1.3, 3.1.4
#     configz.kubeletconfig  — GET /api/v1/nodes/<node>/proxy/configz, verbatim             3.2.1–3.2.8
#   workloads[]                — `kubectl get deploy,sts,ds,job,cronjob,pod -A -o json` .items
#                                                       4.1.5, 4.1.6, 4.2.x, 4.4.1, 4.5.2, 5.2.1
#   namespaces[]               — `kubectl get ns -o json` .items (labels used for PSA)       4.2.x
#   service_accounts[]         — `kubectl get sa -A -o json` .items                         4.1.6, 5.2.1
#   role_bindings[]            — `kubectl get rolebindings,clusterrolebindings -A -o json` .items  4.1.5
#   vpc_cni.addon              — `aws eks describe-addon --addon-name vpc-cni` .addon       4.3.1
#   vpc_cni.aws_node_args[]    — container args of the self-managed aws-node DaemonSet       4.3.1
#   ecr.repository_scanning_configurations[]
#                              — `aws ecr batch-get-repository-scanning-configuration`
#                                .scanningConfigurations for the repos EKS pulls from        5.1.1
#   attest.third_party_image_scanning  bool — alternative evidence for 5.1.1
#   attest.<key>               bool — attestations for the 18 Manual controls (see `manual_attestations`)
#
# Optional organisation settings (absent = strictest):
#   exempt_namespaces[]        — namespaces added to kube-system/kube-public/kube-node-lease
#                                as out of scope for the workload checks
#   token_mount_allowed[]      — "namespace/serviceaccount" pairs documented as needing a
#                                mounted API token (4.1.6)

# METADATA
# title: "CIS Amazon EKS Benchmark v2.0.0"
# custom:
#   class: security
#   framework: cis_eks
#   source: cis
#   domains: [kubernetes, cloud, aws]
#   coverage:
#     checks: 69
#     cited: 63
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_eks.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Control table (from the CIS workbook) ────────────────────────────────────

controls := {
	"2.1.1": {"title": "Enable EKS control plane logging", "level": 1, "assessment": "Automated"},
	"3.1.1": {"title": "Ensure that the kubeconfig file permissions are set to 644 or more restrictive", "level": 1, "assessment": "Automated"},
	"3.1.2": {"title": "Ensure that the kubeconfig file ownership is set to root:root", "level": 1, "assessment": "Automated"},
	"3.1.3": {"title": "Ensure that the kubelet configuration file has permissions set to 644 or more restrictive", "level": 1, "assessment": "Automated"},
	"3.1.4": {"title": "Ensure that the kubelet configuration file ownership is set to root:root", "level": 1, "assessment": "Automated"},
	"3.2.1": {"title": "Ensure kubelet anonymous authentication is disabled", "level": 1, "assessment": "Automated"},
	"3.2.2": {"title": "Ensure kubelet authorization mode is set to Webhook", "level": 1, "assessment": "Automated"},
	"3.2.3": {"title": "Ensure the kubelet X.509 client CA file is configured", "level": 1, "assessment": "Automated"},
	"3.2.4": {"title": "Ensure the kubelet read-only port is disabled", "level": 1, "assessment": "Automated"},
	"3.2.5": {"title": "Ensure the kubelet iptables utility chains are enabled", "level": 1, "assessment": "Automated"},
	"3.2.6": {"title": "Ensure the kubelet event recording QPS is set to an appropriate value", "level": 1, "assessment": "Automated"},
	"3.2.7": {"title": "Ensure the kubelet client certificate rotation is enabled", "level": 1, "assessment": "Automated"},
	"3.2.8": {"title": "Ensure serverTLSBootstrap and RotateKubeletServerCertificate are enabled", "level": 1, "assessment": "Automated"},
	"4.1.1": {"title": "Ensure that the cluster-admin role is only used where required", "level": 1, "assessment": "Manual"},
	"4.1.2": {"title": "Ensure access to Secrets is minimized and granted only where required", "level": 1, "assessment": "Manual"},
	"4.1.3": {"title": "Minimize wildcard use in Roles and ClusterRoles", "level": 1, "assessment": "Manual"},
	"4.1.4": {"title": "Minimize access to create pods", "level": 1, "assessment": "Manual"},
	"4.1.5": {"title": "Ensure that default service accounts are not actively used.", "level": 1, "assessment": "Automated"},
	"4.1.6": {"title": "Ensure that Service Account Tokens are only mounted where necessary", "level": 1, "assessment": "Automated"},
	"4.1.7": {"title": "Standardize EKS cluster access by using access entries, policies, and scoped permissions", "level": 1, "assessment": "Automated"},
	"4.1.8": {"title": "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster", "level": 1, "assessment": "Manual"},
	"4.1.9": {"title": "Minimize access to create persistent volumes", "level": 1, "assessment": "Manual"},
	"4.1.10": {"title": "Minimize access to the proxy sub-resource of nodes", "level": 1, "assessment": "Manual"},
	"4.1.11": {"title": "Minimize access to webhook configuration objects", "level": 1, "assessment": "Manual"},
	"4.1.12": {"title": "Minimize access to the service account token creation", "level": 1, "assessment": "Manual"},
	"4.2.1": {"title": "Minimize the admission of privileged containers", "level": 1, "assessment": "Automated"},
	"4.2.2": {"title": "Minimize the admission of containers wishing to share the host process ID namespace", "level": 1, "assessment": "Automated"},
	"4.2.3": {"title": "Minimize the admission of containers wishing to share the host IPC namespace", "level": 1, "assessment": "Automated"},
	"4.2.4": {"title": "Minimize the admission of containers wishing to share the host network namespace", "level": 1, "assessment": "Automated"},
	"4.2.5": {"title": "Minimize the admission of containers with allowPrivilegeEscalation", "level": 1, "assessment": "Automated"},
	"4.3.1": {"title": "Ensure VPC CNI network policy support is enabled", "level": 1, "assessment": "Automated"},
	"4.3.2": {"title": "Ensure required workloads are covered by Kubernetes network policies", "level": 1, "assessment": "Manual"},
	"4.4.1": {"title": "Prefer exposing secrets as mounted files rather than environment variables", "level": 1, "assessment": "Automated"},
	"4.4.2": {"title": "Consider external secret storage", "level": 1, "assessment": "Manual"},
	"4.5.1": {"title": "Create administrative boundaries between resources using namespaces", "level": 1, "assessment": "Manual"},
	"4.5.2": {"title": "The default namespace should not be used", "level": 1, "assessment": "Automated"},
	"5.1.1": {"title": "Ensure Image Vulnerability Scanning using Amazon ECR image scanning or a third party provider", "level": 1, "assessment": "Automated"},
	"5.1.2": {"title": "Ensure least-privilege access is enforced for Amazon ECR repositories used by EKS workloads", "level": 1, "assessment": "Manual"},
	"5.1.3": {"title": "Restrict ECR access for EKS runtime identities to pull-only permissions", "level": 1, "assessment": "Manual"},
	"5.1.4": {"title": "Allow only approved container registries for images used by EKS workloads", "level": 1, "assessment": "Manual"},
	"5.2.1": {"title": "Prefer using dedicated EKS Service Accounts", "level": 1, "assessment": "Automated"},
	"5.3.1": {"title": "Use customer managed KMS keys for EKS envelope encryption of Kubernetes secrets", "level": 1, "assessment": "Manual"},
	"5.4.1": {"title": "Restrict EKS control plane endpoint access with private access and public CIDR allowlists", "level": 1, "assessment": "Automated"},
	"5.4.2": {"title": "Enable private-only EKS control plane access and disable the public endpoint", "level": 1, "assessment": "Automated"},
	"5.4.3": {"title": "Ensure clusters are created with Private Nodes", "level": 1, "assessment": "Manual"},
	"5.4.4": {"title": "Use TLS certificates on EKS load balancer listeners for encrypted client connections", "level": 1, "assessment": "Manual"},
	"5.5.1": {"title": "Use EKS access entries to manage IAM principal access to Kubernetes", "level": 1, "assessment": "Automated"},
}

# ── Generic helpers ──────────────────────────────────────────────────────────

eks := object.get(input, "cis_eks", {})

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

joined(xs) := concat(", ", sort(xs))

nonempty_array(x) if {
	is_array(x)
	count(x) > 0
}

# ── Evidence collection ──────────────────────────────────────────────────────
# A field is "collected" only when it carries real evidence ({} and [] do not,
# except where noted).

nodes := eks.nodes if nonempty_array(eks.nodes)

workloads := eks.workloads if nonempty_array(eks.workloads)

collected contains "cluster.logging.clusterLogging" if is_array(eks.cluster.logging.clusterLogging)

collected contains "cluster.accessConfig.authenticationMode" if is_string(eks.cluster.accessConfig.authenticationMode)

collected contains "cluster.resourcesVpcConfig" if {
	is_boolean(eks.cluster.resourcesVpcConfig.endpointPublicAccess)
	is_boolean(eks.cluster.resourcesVpcConfig.endpointPrivateAccess)
}

# An empty list is evidence here: it means the cluster has no access entries.
collected contains "access_entries" if is_array(eks.access_entries)

collected contains "nodes[].kubeconfig_file" if {
	every n in nodes {
		is_object(n.kubeconfig_file)
		count(n.kubeconfig_file) > 0
	}
}

collected contains "nodes[].kubelet_config_file" if {
	every n in nodes {
		is_object(n.kubelet_config_file)
		count(n.kubelet_config_file) > 0
	}
}

collected contains "nodes[].configz.kubeletconfig" if {
	every n in nodes {
		is_object(n.configz.kubeletconfig)
		count(n.configz.kubeletconfig) > 0
	}
}

# A running EKS cluster always has kube-system pods, so an empty inventory is not evidence.
collected contains "workloads" if workloads

collected contains "namespaces" if nonempty_array(eks.namespaces)

collected contains "service_accounts" if nonempty_array(eks.service_accounts)

collected contains "role_bindings" if nonempty_array(eks.role_bindings)

collected contains "vpc_cni" if is_object(eks.vpc_cni.addon)

collected contains "vpc_cni" if is_array(eks.vpc_cni.aws_node_args)

collected contains "ecr.repository_scanning_configurations" if nonempty_array(eks.ecr.repository_scanning_configurations)

collected contains "ecr.repository_scanning_configurations" if eks.attest.third_party_image_scanning == true

# Evidence each Automated control needs.
requires := {
	"2.1.1": ["cluster.logging.clusterLogging"],
	"3.1.1": ["nodes[].kubeconfig_file"],
	"3.1.2": ["nodes[].kubeconfig_file"],
	"3.1.3": ["nodes[].kubelet_config_file"],
	"3.1.4": ["nodes[].kubelet_config_file"],
	"3.2.1": ["nodes[].configz.kubeletconfig"],
	"3.2.2": ["nodes[].configz.kubeletconfig"],
	"3.2.3": ["nodes[].configz.kubeletconfig"],
	"3.2.4": ["nodes[].configz.kubeletconfig"],
	"3.2.5": ["nodes[].configz.kubeletconfig"],
	"3.2.6": ["nodes[].configz.kubeletconfig"],
	"3.2.7": ["nodes[].configz.kubeletconfig"],
	"3.2.8": ["nodes[].configz.kubeletconfig"],
	"4.1.5": ["workloads", "role_bindings"],
	"4.1.6": ["workloads", "service_accounts"],
	"4.1.7": ["cluster.accessConfig.authenticationMode", "access_entries"],
	"4.2.1": ["namespaces", "workloads"],
	"4.2.2": ["namespaces", "workloads"],
	"4.2.3": ["namespaces", "workloads"],
	"4.2.4": ["namespaces", "workloads"],
	"4.2.5": ["namespaces", "workloads"],
	"4.3.1": ["vpc_cni"],
	"4.4.1": ["workloads"],
	"4.5.2": ["workloads"],
	"5.1.1": ["ecr.repository_scanning_configurations"],
	"5.2.1": ["workloads", "service_accounts"],
	"5.4.1": ["cluster.resourcesVpcConfig"],
	"5.4.2": ["cluster.resourcesVpcConfig"],
	"5.5.1": ["cluster.accessConfig.authenticationMode", "access_entries"],
}

missing_evidence(id) := [f | some f in requires[id]; not f in collected]

violations contains msg if {
	some id, _ in requires
	m := missing_evidence(id)
	count(m) > 0
	msg := sprintf("CIS EKS %s: evidence missing — %s not collected", [id, concat(", ", m)])
}

# A control's logic runs only when all its evidence is present, so the
# evidence-missing message and the finding are mutually exclusive.
evaluated(id) if {
	requires[id]
	count(missing_evidence(id)) == 0
}

# ── Manual controls: attestation ─────────────────────────────────────────────

manual_attestations := {
	"4.1.1": "cluster_admin_usage_reviewed",
	"4.1.2": "secrets_access_reviewed",
	"4.1.3": "wildcard_use_reviewed",
	"4.1.4": "pod_create_access_reviewed",
	"4.1.8": "bind_impersonate_escalate_reviewed",
	"4.1.9": "pv_create_access_reviewed",
	"4.1.10": "node_proxy_access_reviewed",
	"4.1.11": "webhook_config_access_reviewed",
	"4.1.12": "sa_token_creation_reviewed",
	"4.3.2": "network_policy_coverage_reviewed",
	"4.4.2": "external_secret_storage_reviewed",
	"4.5.1": "namespace_boundaries_reviewed",
	"5.1.2": "ecr_least_privilege_reviewed",
	"5.1.3": "ecr_pull_only_reviewed",
	"5.1.4": "approved_registries_enforced",
	"5.3.1": "secrets_cmk_envelope_encryption",
	"5.4.3": "private_nodes",
	"5.4.4": "lb_tls_listeners",
}

attested(key) if eks.attest[key] == true

violations contains msg if {
	some id, key in manual_attestations
	not attested(key)
	msg := sprintf("CIS EKS %s: manual review not attested (set input.cis_eks.attest.%s after review)", [id, key])
}

# ── 2.1 Logging ──────────────────────────────────────────────────────────────

required_log_types := {"api", "audit", "authenticator", "controllerManager", "scheduler"}

enabled_log_types contains t if {
	some e in eks.cluster.logging.clusterLogging
	e.enabled == true
	some t in e.types
}

violations contains msg if {
	evaluated("2.1.1")
	off := required_log_types - enabled_log_types
	count(off) > 0
	msg := sprintf("CIS EKS 2.1.1: control plane log types not enabled: %s", [joined(off)])
}

# ── 3.1 Worker node configuration files ──────────────────────────────────────

node_name(n) := sprintf("%v", [object.get(n, "name", "<unnamed>")])

file_absent(f) if f.exists == false

file_mode_ok(f) if mode_within(f.mode, "644")

file_owner_ok(f) if {
	f.owner == "root"
	f.group == "root"
}

# 3.1.1/3.1.2: a kubeconfig file the kubelet does not use (exists: false) is out of scope.
violations contains msg if {
	evaluated("3.1.1")
	bad := [node_name(n) | some n in nodes; not file_absent(n.kubeconfig_file); not file_mode_ok(n.kubeconfig_file)]
	count(bad) > 0
	msg := sprintf("CIS EKS 3.1.1: kubelet kubeconfig file mode is looser than 644 on nodes: %s", [joined(bad)])
}

violations contains msg if {
	evaluated("3.1.2")
	bad := [node_name(n) | some n in nodes; not file_absent(n.kubeconfig_file); not file_owner_ok(n.kubeconfig_file)]
	count(bad) > 0
	msg := sprintf("CIS EKS 3.1.2: kubelet kubeconfig file is not owned by root:root on nodes: %s", [joined(bad)])
}

violations contains msg if {
	evaluated("3.1.3")
	bad := [node_name(n) | some n in nodes; not file_mode_ok(n.kubelet_config_file)]
	count(bad) > 0
	msg := sprintf("CIS EKS 3.1.3: kubelet config file is missing or its mode is looser than 644 on nodes: %s", [joined(bad)])
}

violations contains msg if {
	evaluated("3.1.4")
	bad := [node_name(n) | some n in nodes; not file_owner_ok(n.kubelet_config_file)]
	count(bad) > 0
	msg := sprintf("CIS EKS 3.1.4: kubelet config file is missing or not owned by root:root on nodes: %s", [joined(bad)])
}

# ── 3.2 Kubelet (effective config from configz) ──────────────────────────────

kc(n) := n.configz.kubeletconfig

kubelet_ok("3.2.1", n) if kc(n).authentication.anonymous.enabled == false

kubelet_ok("3.2.2", n) if kc(n).authorization.mode == "Webhook"

kubelet_ok("3.2.3", n) if {
	f := kc(n).authentication.x509.clientCAFile
	is_string(f)
	trim_space(f) != ""
}

# Documented exception: configz omits zero-valued fields, so an absent
# readOnlyPort in a collected configz means 0 (disabled), as the benchmark notes.
kubelet_ok("3.2.4", n) if not "readOnlyPort" in object.keys(kc(n))

kubelet_ok("3.2.4", n) if kc(n).readOnlyPort == 0

kubelet_ok("3.2.5", n) if kc(n).makeIPTablesUtilChains == true

# 0 means no limit on event creation; any positive rate limit is accepted.
kubelet_ok("3.2.6", n) if {
	q := kc(n).eventRecordQPS
	is_number(q)
	q > 0
}

kubelet_ok("3.2.7", n) if kc(n).rotateCertificates == true

kubelet_ok("3.2.8", n) if {
	kc(n).serverTLSBootstrap == true
	kc(n).featureGates.RotateKubeletServerCertificate == true
}

kubelet_finding := {
	"3.2.1": "kubelet anonymous authentication is not disabled",
	"3.2.2": "kubelet authorization mode is not Webhook",
	"3.2.3": "kubelet X.509 client CA file is not configured",
	"3.2.4": "kubelet read-only port is enabled",
	"3.2.5": "kubelet makeIPTablesUtilChains is not true",
	"3.2.6": "kubelet eventRecordQPS is missing or 0 (unlimited)",
	"3.2.7": "kubelet client certificate rotation is not enabled",
	"3.2.8": "kubelet serverTLSBootstrap and RotateKubeletServerCertificate are not both true",
}

violations contains msg if {
	some id, text in kubelet_finding
	evaluated(id)
	bad := [node_name(n) | some n in nodes; not kubelet_ok(id, n)]
	count(bad) > 0
	msg := sprintf("CIS EKS %s: %s on nodes: %s", [id, text, joined(bad)])
}

# ── 4 Workload helpers ───────────────────────────────────────────────────────

exempt_namespaces := {"kube-system", "kube-public", "kube-node-lease"} | {ns | some ns in object.get(eks, "exempt_namespaces", [])}

ns_of(obj) := object.get(obj.metadata, "namespace", "default")

kind_of(w) := object.get(w, "kind", "")

wid(w) := sprintf("%s/%s/%s", [ns_of(w), kind_of(w), object.get(w.metadata, "name", "<unnamed>")])

pod_spec(w) := s if {
	kind_of(w) == "CronJob"
	s := w.spec.jobTemplate.spec.template.spec
} else := s if {
	kind_of(w) == "Pod"
	s := w.spec
} else := s if {
	s := w.spec.template.spec
}

sa_name(w) := object.get(pod_spec(w), "serviceAccountName", "default")

scoped_workloads := [w | some w in workloads; not ns_of(w) in exempt_namespaces]

scoped_pods := [w | some w in scoped_workloads; kind_of(w) == "Pod"]

all_containers(s) := array.concat(
	array.concat(object.get(s, "containers", []), object.get(s, "initContainers", [])),
	object.get(s, "ephemeralContainers", []),
)

default_sa_users := [wid(w) | some w in scoped_workloads; sa_name(w) == "default"]

# ── 4.1 RBAC and service accounts ────────────────────────────────────────────

default_sa_bindings contains sprintf("%s/%s", [kind_of(b), object.get(b.metadata, "name", "<unnamed>")]) if {
	some b in eks.role_bindings
	some s in object.get(b, "subjects", [])
	s.kind == "ServiceAccount"
	s.name == "default"
	not object.get(s, "namespace", ns_of(b)) in exempt_namespaces
}

violations contains msg if {
	evaluated("4.1.5")
	offenders := array.concat(default_sa_users, [sprintf("binding %s", [b]) | some b in default_sa_bindings])
	count(offenders) > 0
	msg := sprintf("CIS EKS 4.1.5: default service accounts are in use: %s", [joined(offenders)])
}

sa_automount_false(ns, name) if {
	some sa in eks.service_accounts
	ns_of(sa) == ns
	sa.metadata.name == name
	sa.automountServiceAccountToken == false
}

# Pod setting wins; otherwise the ServiceAccount setting; otherwise Kubernetes mounts the token.
token_mounted(w) if pod_spec(w).automountServiceAccountToken == true

token_mounted(w) if {
	not "automountServiceAccountToken" in object.keys(pod_spec(w))
	not sa_automount_false(ns_of(w), sa_name(w))
}

token_mount_allowed(w) if sprintf("%s/%s", [ns_of(w), sa_name(w)]) in object.get(eks, "token_mount_allowed", [])

violations contains msg if {
	evaluated("4.1.6")
	bad := [wid(w) | some w in scoped_workloads; token_mounted(w); not token_mount_allowed(w)]
	count(bad) > 0
	msg := sprintf("CIS EKS 4.1.6: service account tokens are mounted without a documented need: %s", [joined(bad)])
}

access_entry_modes := {"API", "API_AND_CONFIG_MAP"}

access_entries_enabled if eks.cluster.accessConfig.authenticationMode in access_entry_modes

entry_scoped(e) if nonempty_array(e.accessPolicies)

entry_scoped(e) if nonempty_array(e.kubernetesGroups)

violations contains "CIS EKS 4.1.7: cluster authentication mode is CONFIG_MAP only; access entries are not available" if {
	evaluated("4.1.7")
	not access_entries_enabled
}

violations contains "CIS EKS 4.1.7: no EKS access entries are defined" if {
	evaluated("4.1.7")
	access_entries_enabled
	count(eks.access_entries) == 0
}

violations contains msg if {
	evaluated("4.1.7")
	access_entries_enabled
	bad := [sprintf("%v", [object.get(e, "principalArn", "<unknown>")]) | some e in eks.access_entries; not entry_scoped(e)]
	count(bad) > 0
	msg := sprintf("CIS EKS 4.1.7: access entries have no access policy or Kubernetes group: %s", [joined(bad)])
}

# ── 4.2 Pod Security Standards ───────────────────────────────────────────────

psa_enforce(ns) := object.get(object.get(ns.metadata, "labels", {}), "pod-security.kubernetes.io/enforce", "")

scoped_namespaces := [ns | some ns in eks.namespaces; not ns.metadata.name in exempt_namespaces]

weak_psa(levels) := [sprintf("namespace %s", [ns.metadata.name]) | some ns in scoped_namespaces; not psa_enforce(ns) in levels]

baseline_levels := {"baseline", "restricted"}

privileged_container(s) if {
	some c in all_containers(s)
	c.securityContext.privileged == true
}

escalation_allowed(s) if {
	some c in all_containers(s)
	not object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", true) == false
}

pod_breaks("4.2.1", s) if privileged_container(s)

pod_breaks("4.2.2", s) if s.hostPID == true

pod_breaks("4.2.3", s) if s.hostIPC == true

pod_breaks("4.2.4", s) if s.hostNetwork == true

pod_breaks("4.2.5", s) if escalation_allowed(s)

psa_finding := {
	"4.2.1": "privileged containers",
	"4.2.2": "host PID sharing",
	"4.2.3": "host IPC sharing",
	"4.2.4": "host network sharing",
	"4.2.5": "allowPrivilegeEscalation",
}

psa_levels(id) := {"restricted"} if id == "4.2.5"

psa_levels(id) := baseline_levels if id != "4.2.5"

violations contains msg if {
	some id, text in psa_finding
	evaluated(id)
	offenders := array.concat(weak_psa(psa_levels(id)), [wid(p) | some p in scoped_pods; pod_breaks(id, p.spec)])
	count(offenders) > 0
	msg := sprintf("CIS EKS %s: admission of %s is not blocked (PSA enforce level too weak, or running pods use it): %s", [id, text, joined(offenders)])
}

# ── 4.3 VPC CNI ──────────────────────────────────────────────────────────────

addon_network_policy_on if {
	a := eks.vpc_cni.addon
	a.status == "ACTIVE"
	is_string(a.configurationValues)
	json.is_valid(a.configurationValues)
	cfg := json.unmarshal(a.configurationValues)
	is_object(cfg)
	cfg.enableNetworkPolicy in {true, "true"}
}

self_managed_network_policy_on if "--enable-network-policy=true" in eks.vpc_cni.aws_node_args

violations contains "CIS EKS 4.3.1: VPC CNI network policy support is not enabled" if {
	evaluated("4.3.1")
	not addon_network_policy_on
	not self_managed_network_policy_on
}

# ── 4.4 Secrets management ───────────────────────────────────────────────────

secret_in_env(s) if {
	some c in all_containers(s)
	some e in object.get(c, "env", [])
	e.valueFrom.secretKeyRef
}

secret_in_env(s) if {
	some c in all_containers(s)
	some e in object.get(c, "envFrom", [])
	e.secretRef
}

violations contains msg if {
	evaluated("4.4.1")
	bad := [wid(w) | some w in scoped_workloads; secret_in_env(pod_spec(w))]
	count(bad) > 0
	msg := sprintf("CIS EKS 4.4.1: workloads read secrets from environment variables: %s", [joined(bad)])
}

# ── 4.5 General policies ─────────────────────────────────────────────────────

violations contains msg if {
	evaluated("4.5.2")
	bad := [wid(w) | some w in workloads; ns_of(w) == "default"]
	count(bad) > 0
	msg := sprintf("CIS EKS 4.5.2: workloads run in the default namespace: %s", [joined(bad)])
}

# ── 5.1 Image registry and scanning ──────────────────────────────────────────

repo_scanned(r) if r.scanOnPush == true

repo_scanned(r) if r.scanFrequency in {"SCAN_ON_PUSH", "CONTINUOUS_SCAN"}

violations contains msg if {
	evaluated("5.1.1")
	not eks.attest.third_party_image_scanning == true
	bad := [sprintf("%v", [object.get(r, "repositoryName", "<unknown>")]) | some r in eks.ecr.repository_scanning_configurations; not repo_scanned(r)]
	count(bad) > 0
	msg := sprintf("CIS EKS 5.1.1: ECR repositories are not scanned on push or continuously: %s", [joined(bad)])
}

# ── 5.2 IAM ──────────────────────────────────────────────────────────────────

default_sa_automounting := [sprintf("serviceaccount %s/default", [ns_of(sa)]) |
	some sa in eks.service_accounts
	sa.metadata.name == "default"
	not ns_of(sa) in exempt_namespaces
	not sa.automountServiceAccountToken == false
]

violations contains msg if {
	evaluated("5.2.1")
	offenders := array.concat(default_sa_users, default_sa_automounting)
	count(offenders) > 0
	msg := sprintf("CIS EKS 5.2.1: workloads do not use dedicated service accounts: %s", [joined(offenders)])
}

# ── 5.4 Cluster networking ───────────────────────────────────────────────────

vpc := eks.cluster.resourcesVpcConfig

open_cidrs := {"0.0.0.0/0", "::/0"}

public_access_restricted if vpc.endpointPublicAccess == false

public_access_restricted if {
	vpc.endpointPublicAccess == true
	nonempty_array(vpc.publicAccessCidrs)
	every c in vpc.publicAccessCidrs {
		not c in open_cidrs
	}
}

violations contains "CIS EKS 5.4.1: control plane endpoint is not private-enabled with a restricted public CIDR allowlist" if {
	evaluated("5.4.1")
	not public_access_ok_541
}

public_access_ok_541 if {
	vpc.endpointPrivateAccess == true
	public_access_restricted
}

violations contains "CIS EKS 5.4.2: control plane endpoint is not private-only (public endpoint enabled or private endpoint disabled)" if {
	evaluated("5.4.2")
	not private_only
}

private_only if {
	vpc.endpointPrivateAccess == true
	vpc.endpointPublicAccess == false
}

# ── 5.5 Authentication and authorization ─────────────────────────────────────

violations contains "CIS EKS 5.5.1: IAM principal access is not managed through EKS access entries" if {
	evaluated("5.5.1")
	not access_entries_in_use
}

access_entries_in_use if {
	access_entries_enabled
	count(eks.access_entries) > 0
}

# ── Section rollup ───────────────────────────────────────────────────────────

section_violations(prefix) := [v | some v in violations; startswith(v, prefix)]

section_summary := {
	"2": count(section_violations("CIS EKS 2.")),
	"3": count(section_violations("CIS EKS 3.")),
	"4": count(section_violations("CIS EKS 4.")),
	"5": count(section_violations("CIS EKS 5.")),
}

# ── Compliance Report ────────────────────────────────────────────────────────

compliance_report := {
	"framework": "CIS Amazon EKS Benchmark",
	"version": "v2.0.0",
	"compliant": compliant,
	"total_controls": count(controls),
	"passed_controls": count(controls) - count(failed_control_ids),
	"failed_controls": count(failed_control_ids),
	"compliance_percentage": _pct,
	"violations": _report_violations,
	"violation_count": count(violations),
	"section_summary": section_summary,
}

# distinct failing controls, parsed from "CIS EKS <id>: ..." (each control emits at most one message)
failed_control_ids := {id |
	some v in violations
	m := regex.find_all_string_submatch_n(`^CIS EKS ([0-9.]+):`, v, 1)
	count(m) > 0
	id := m[0][1]
	controls[id]
}

_pct := round(((count(controls) - count(failed_control_ids)) * 100) / count(controls)) if count(controls) > 0

default _pct := 0

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

# FAIL-CLOSED gate (see benchmarks/cis/network_devices/pfsense/cis_pfsense_main.rego): with no facts at all the
# report says so explicitly, so an empty assessment can never read as a result.
_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_eks"],
)

_report_violations := array.concat(sort([v | some v in violations]), [_no_facts_msg]) if not _facts_supplied

_report_violations := sort([v | some v in violations]) if _facts_supplied
