# METADATA
# title: "Sentinel Policy Enforcement — Kubernetes Manifests"
# custom:
#   class: enforcement
#   framework: enforcement_kubernetes
#   source: aac
#   domains: [kubernetes]
#   coverage:
#     checks: 31
#     cited: 15
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.5.0
package sentinel.kubernetes

import rego.v1

# =============================================================================
# Sentinel Policy Enforcement — Kubernetes Manifests
# Validates Kubernetes YAML manifests before git merge / cluster apply
#
# Policy IDs:
#   SENTINEL-K8S-000 — The manifest must be readable (malformed input is denied)
#   SENTINEL-K8S-001 — No privileged containers
#   SENTINEL-K8S-002 — No containers running as root
#   SENTINEL-K8S-003 — Read-only root filesystem required
#   SENTINEL-K8S-004 — Resource limits must be set
#   SENTINEL-K8S-005 — No hostNetwork, hostPID, or hostIPC
#   SENTINEL-K8S-006 — No hostPath volumes
#   SENTINEL-K8S-007 — Image must use specific tag (not :latest)
#   SENTINEL-K8S-008 — Liveness and readiness probes required
#   SENTINEL-K8S-009 — No privileged escalation
#   SENTINEL-K8S-010 — Namespace must be explicitly set
#   SENTINEL-K8S-011 — Required labels must be present
#   SENTINEL-K8S-012 — No secrets in environment variables
#   SENTINEL-K8S-013 — NetworkPolicy must exist for namespace
#   SENTINEL-K8S-014 — Service accounts must not auto-mount tokens
#
# Input shape:
#   input.manifest              - Kubernetes manifest (parsed YAML/JSON)
#   input.kind                  - resource kind (Deployment, Pod, StatefulSet, etc.)
#   input.namespace             - target namespace
#   input.existing_policies[]   - existing NetworkPolicies in namespace
#   input.policy.additional_kinds - optional list of strings: extra kinds (custom resources) recognised but not judged
# =============================================================================

# ReplicaSet and ReplicationController carry a pod template and are judged like the controllers that normally
# create them (2026-11-24, in line with kubernetes.admission).
workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job", "CronJob", "Pod"}

# Pod spec location differs by kind:
#   Pod      -> spec
#   CronJob  -> spec.jobTemplate.spec.template.spec
#   others   -> spec.template.spec
pod_spec := input.manifest.spec if {
	input.kind == "Pod"
}

pod_spec := input.manifest.spec.jobTemplate.spec.template.spec if {
	input.kind == "CronJob"
}

pod_spec := input.manifest.spec.template.spec if {
	input.kind in workload_kinds
	not input.kind in {"Pod", "CronJob"}
}

# Extract containers from any workload kind
containers := pod_spec.containers

# A name for messages. A finding must never disappear because the object it names has no name.
_name(o) := n if {
	n := o.name
	is_string(n)
} else := "<unnamed>"

_manifest_name := _name(object.get(input, ["manifest", "metadata"], {}))

# A switch that must stay off is off only as the boolean false or when unset: true, and also "true",
# "false" and numbers (which the API server would reject), turn the finding on.
_on(value) if {
	not is_null(value)
	value != false
}

_nonempty_string(v) if {
	is_string(v)
	trim_space(v) != ""
}

# A resource quantity is a non-empty string ("500m", "256Mi") or a number. null, false and "" are no limit
# (`not x` is false for null, so a null limit used to count as set).
_quantity(v) if _nonempty_string(v)

_quantity(v) if is_number(v)

# ---------------------------------------------------------------------------
# SENTINEL-K8S-000 — The manifest must be readable
# A document that is not a manifest is denied, never waved through. So is a manifest whose kind is missing,
# empty, not a string, or not one the gate knows how to judge (judged_kinds, below): 2026-11-24, see the note
# at the end of this file.
# ---------------------------------------------------------------------------

violation_k8s_000 contains "SENTINEL-K8S-000: Malformed input: input.manifest is missing or is not an object; nothing was evaluated." if {
	not is_object(object.get(input, "manifest", null))
}

violation_k8s_000 contains msg if {
	"kind" in object.keys(input)
	not is_string(input.kind)
	msg := sprintf("SENTINEL-K8S-000: Malformed input: input.kind must be a string, got %v.", [type_name(input.kind)])
}

# The kinds the gate judges: the workloads (pod rules, K8S-001 to 009 and 012 to 014) and the resources named by
# the namespace and label rules (K8S-010, 011). Those two rules read only these kinds: a recognised built-in kind
# the gate does not judge (builtin_kinds below), and a kind listed in additional_kinds, is admitted with nothing judged.
judged_kinds := workload_kinds | {"Namespace", "ClusterRole", "ClusterRoleBinding", "ConfigMap", "Secret", "Service", "ServiceAccount", "NetworkPolicy", "Ingress", "Role", "RoleBinding", "PersistentVolumeClaim"}

# Recognised but not judged: the other standard built-in Kubernetes API kinds. A manifest of one of these is
# admitted with nothing judged (no gate rule reads it), so an ordinary deployment is not blocked. Source: the
# Kubernetes API reference, https://kubernetes.io/docs/reference/kubernetes-api/ (read 2026-11-24; its version
# menu lists v1.37 first, which the page does not label "stable"), stable (v1, v2) kinds of the groups core, apps,
# batch, networking.k8s.io, rbac.authorization.k8s.io, policy, autoscaling, storage.k8s.io, scheduling.k8s.io,
# coordination.k8s.io, discovery.k8s.io, admissionregistration.k8s.io, apiextensions.k8s.io, node.k8s.io,
# certificates.k8s.io, flowcontrol.apiserver.k8s.io, plus events.k8s.io. Alpha and beta kinds are left out: allow
# one with input.policy.additional_kinds.
builtin_kinds := {
	# core
	"ComponentStatus", "Endpoints", "Event", "LimitRange", "Node", "PersistentVolume", "PodTemplate",
	"ResourceQuota",
	# apps
	"ControllerRevision",
	# autoscaling, policy, node.k8s.io, scheduling.k8s.io
	"HorizontalPodAutoscaler", "PodDisruptionBudget", "RuntimeClass", "PriorityClass",
	# networking.k8s.io
	"IPAddress", "IngressClass", "ServiceCIDR",
	# storage.k8s.io
	"CSIDriver", "CSINode", "CSIStorageCapacity", "StorageClass", "VolumeAttachment", "VolumeAttributesClass",
	# coordination.k8s.io, discovery.k8s.io
	"Lease", "EndpointSlice",
	# admissionregistration.k8s.io, apiextensions.k8s.io
	"MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding", "MutatingWebhookConfiguration",
	"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding", "ValidatingWebhookConfiguration",
	"CustomResourceDefinition",
	# certificates.k8s.io, flowcontrol.apiserver.k8s.io
	"CertificateSigningRequest", "ClusterTrustBundle", "PodCertificateRequest", "FlowSchema", "PriorityLevelConfiguration",
}

# input.policy.additional_kinds: an operator's list of extra kinds (custom resources) the gate should recognise but not
# judge. It must be a list of non-empty strings; anything else is an evidence finding and none of it is honoured.
_additional_kinds_present if {
	is_object(input.policy)
	"additional_kinds" in object.keys(input.policy)
}

_additional_kinds_value := input.policy.additional_kinds

_additional_kinds_valid if {
	is_array(_additional_kinds_value)
	every k in _additional_kinds_value {
		is_string(k)
		trim_space(k) != ""
	}
}

additional_kinds := {k | some k in _additional_kinds_value; _additional_kinds_valid}

_kind_judged if {
	is_string(input.kind)
	input.kind in judged_kinds
}

_kind_recognised if _kind_judged

_kind_recognised if {
	is_string(input.kind)
	input.kind in builtin_kinds
}

_kind_recognised if {
	is_string(input.kind)
	input.kind in additional_kinds
}

violation_k8s_000 contains msg if {
	is_object(object.get(input, "policy", null))
	_additional_kinds_present
	not _additional_kinds_valid
	msg := sprintf("SENTINEL-K8S-000: Malformed input: input.policy.additional_kinds must be a list of non-empty strings, got %v; it was ignored.", [type_name(_additional_kinds_value)])
}

violation_k8s_000 contains "SENTINEL-K8S-000: Malformed input: input.kind is missing; the gate cannot tell what kind of resource this is, so nothing was judged." if {
	not "kind" in object.keys(input)
}

violation_k8s_000 contains "SENTINEL-K8S-000: Malformed input: input.kind is empty; the gate cannot tell what kind of resource this is, so nothing was judged." if {
	is_string(input.kind)
	trim_space(input.kind) == ""
}

violation_k8s_000 contains msg if {
	is_string(input.kind)
	trim_space(input.kind) != ""
	not _kind_recognised
	msg := sprintf("SENTINEL-K8S-000: Unrecognised kind: input.kind %q is not a standard built-in Kubernetes kind or a kind this gate judges, so nothing was judged. If it is a custom resource you accept, list it in input.policy.additional_kinds (a list of strings).", [input.kind])
}

violation_k8s_000 contains msg if {
	input.kind in workload_kinds
	is_object(object.get(input, "manifest", null))
	not _containers_readable
	msg := sprintf("SENTINEL-K8S-000: Malformed manifest: %v '%v' has no pod spec with a non-empty containers list of objects.", [input.kind, _manifest_name])
}

_containers_readable if {
	is_array(containers)
	count(containers) > 0
	every c in containers {
		is_object(c)
	}
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-001 — No privileged containers
# ---------------------------------------------------------------------------

violation_k8s_001 contains msg if {
	some container in containers
	_on(object.get(container, ["securityContext", "privileged"], null))
	msg := sprintf(
		"SENTINEL-K8S-001: Container '%v' runs as privileged. Privileged containers have full host access and are not permitted.",
		[_name(container)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-002 — No containers running as root (UID 0)
# ---------------------------------------------------------------------------

violation_k8s_002 contains msg if {
	some container in containers
	container.securityContext.runAsUser == 0
	msg := sprintf(
		"SENTINEL-K8S-002: Container '%v' runs as root (UID 0). Containers must run as non-root users.",
		[_name(container)],
	)
}

# runAsNonRoot of another type ("true", 1) is not a statement that the container runs as non-root
violation_k8s_002 contains msg if {
	some container in containers
	flag := object.get(container, ["securityContext", "runAsNonRoot"], null)
	flag != null
	not is_boolean(flag)
	msg := sprintf(
		"SENTINEL-K8S-002: Container '%v' sets runAsNonRoot to a %v. runAsNonRoot must be the boolean true.",
		[_name(container), type_name(flag)],
	)
}

# runAsUser of another type ("0", "1000", true) is not a non-root UID
violation_k8s_002 contains msg if {
	some container in containers
	uid := object.get(container, ["securityContext", "runAsUser"], null)
	uid != null
	not is_number(uid)
	msg := sprintf(
		"SENTINEL-K8S-002: Container '%v' sets runAsUser to a %v. runAsUser must be a number other than 0.",
		[_name(container), type_name(uid)],
	)
}

violation_k8s_002 contains msg if {
	some container in containers
	not container.securityContext.runAsNonRoot == true
	not is_number(object.get(container, ["securityContext", "runAsUser"], null))
	msg := sprintf(
		"SENTINEL-K8S-002: Container '%v' does not set runAsNonRoot or runAsUser. Explicitly set runAsNonRoot: true.",
		[_name(container)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-003 — Read-only root filesystem
# ---------------------------------------------------------------------------

violation_k8s_003 contains msg if {
	some container in containers
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf(
		"SENTINEL-K8S-003: Container '%v' does not set readOnlyRootFilesystem: true. Read-only root filesystem prevents runtime modification.",
		[_name(container)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-004 — Resource limits
# ---------------------------------------------------------------------------

violation_k8s_004 contains msg if {
	some container in containers
	not _quantity(object.get(container, ["resources", "limits", "cpu"], null))
	msg := sprintf(
		"SENTINEL-K8S-004: Container '%v' has no CPU limit. CPU limits prevent noisy-neighbor issues and resource exhaustion.",
		[_name(container)],
	)
}

violation_k8s_004 contains msg if {
	some container in containers
	not _quantity(object.get(container, ["resources", "limits", "memory"], null))
	msg := sprintf(
		"SENTINEL-K8S-004: Container '%v' has no memory limit. Memory limits prevent OOM conditions from affecting other workloads.",
		[_name(container)],
	)
}

violation_k8s_004 contains msg if {
	some container in containers
	not _quantity(object.get(container, ["resources", "requests", "cpu"], null))
	msg := sprintf(
		"SENTINEL-K8S-004: Container '%v' has no CPU request. Resource requests are required for proper scheduler decisions.",
		[_name(container)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-005 — No hostNetwork, hostPID, hostIPC
# ---------------------------------------------------------------------------

violation_k8s_005 contains msg if {
	_on(object.get(pod_spec, "hostNetwork", null))
	msg := "SENTINEL-K8S-005: hostNetwork is enabled. Pods must not share the host network namespace."
}

violation_k8s_005 contains msg if {
	_on(object.get(pod_spec, "hostPID", null))
	msg := "SENTINEL-K8S-005: hostPID is enabled. Pods must not share the host process namespace."
}

violation_k8s_005 contains msg if {
	_on(object.get(pod_spec, "hostIPC", null))
	msg := "SENTINEL-K8S-005: hostIPC is enabled. Pods must not share the host IPC namespace."
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-006 — No hostPath volumes
# ---------------------------------------------------------------------------

violation_k8s_006 contains msg if {
	some volume in pod_spec.volumes
	volume.hostPath
	msg := sprintf(
		"SENTINEL-K8S-006: Volume '%v' uses hostPath. hostPath volumes mount from the host filesystem and create security risks.",
		[_name(volume)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-007 — No :latest image tags
# ---------------------------------------------------------------------------

violation_k8s_007 contains msg if {
	some container in containers
	not _nonempty_string(object.get(container, "image", null))
	msg := sprintf("SENTINEL-K8S-007: Container '%v' has no image. Specify an image with an explicit version tag.", [_name(container)])
}

violation_k8s_007 contains msg if {
	some container in containers
	endswith(container.image, ":latest")
	msg := sprintf(
		"SENTINEL-K8S-007: Container '%v' uses image tag ':latest' (%v). Specify an immutable tag or digest for reproducible deployments.",
		[_name(container), object.get(container, "image", null)],
	)
}

violation_k8s_007 contains msg if {
	some container in containers
	not contains(container.image, ":")
	msg := sprintf(
		"SENTINEL-K8S-007: Container '%v' image '%v' has no tag. Specify an explicit version tag.",
		[_name(container), object.get(container, "image", null)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-008 — Liveness and readiness probes
# ---------------------------------------------------------------------------

violation_k8s_008 contains msg if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"}
	some container in containers
	not is_object(object.get(container, "livenessProbe", null))
	msg := sprintf(
		"SENTINEL-K8S-008: Container '%v' has no livenessProbe. Liveness probes enable automatic recovery from deadlocked containers.",
		[_name(container)],
	)
}

violation_k8s_008 contains msg if {
	input.kind in {"Deployment", "StatefulSet", "ReplicaSet", "ReplicationController"}
	some container in containers
	not is_object(object.get(container, "readinessProbe", null))
	msg := sprintf(
		"SENTINEL-K8S-008: Container '%v' has no readinessProbe. Readiness probes prevent traffic routing to unready containers.",
		[_name(container)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-009 — No privilege escalation
# ---------------------------------------------------------------------------

violation_k8s_009 contains msg if {
	some container in containers
	not container.securityContext.allowPrivilegeEscalation == false
	msg := sprintf(
		"SENTINEL-K8S-009: Container '%v' does not set allowPrivilegeEscalation: false. Set this explicitly to prevent privilege escalation.",
		[_name(container)],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-010 — Namespace must be set
# ---------------------------------------------------------------------------

# kinds that live outside a namespace
_not_namespaced if input.kind in {"Namespace", "ClusterRole", "ClusterRoleBinding"}

violation_k8s_010 contains msg if {
	not _nonempty_string(object.get(input, ["manifest", "metadata", "namespace"], null))
	_kind_judged
	not _not_namespaced
	msg := sprintf(
		"SENTINEL-K8S-010: %v '%v' does not specify a namespace. All namespaced resources must explicitly set metadata.namespace.",
		[input.kind, _manifest_name],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-011 — Required labels
# ---------------------------------------------------------------------------

required_labels := {"app", "version", "team"}

violation_k8s_011 contains msg if {
	_kind_judged
	some label in required_labels
	not _nonempty_string(object.get(input, ["manifest", "metadata", "labels", label], null))
	msg := sprintf(
		"SENTINEL-K8S-011: Required label '%v' is missing from %v '%v'. Labels are required for observability and incident response.",
		[label, input.kind, _manifest_name],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-012 — No secrets in environment variables
# ---------------------------------------------------------------------------

secret_patterns := {"password", "secret", "key", "token", "api_key", "apikey", "passwd", "credential"}

violation_k8s_012 contains msg if {
	some container in containers
	some env in container.env
	lower_name := lower(env.name)
	some pattern in secret_patterns
	contains(lower_name, pattern)
	env.value # has a hardcoded value (not a secretKeyRef)
	msg := sprintf(
		"SENTINEL-K8S-012: Container '%v' env var '%v' appears to contain a hardcoded secret. Use secretKeyRef or external secret management instead.",
		[_name(container), env.name],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-013 — NetworkPolicy must exist for namespace
# ---------------------------------------------------------------------------

violation_k8s_013 contains msg if {
	ns := input.manifest.metadata.namespace
	ns != "kube-system"
	count([p | some p in input.existing_policies; p.namespace == ns]) == 0
	msg := sprintf(
		"SENTINEL-K8S-013: Namespace '%v' has no NetworkPolicy. All application namespaces must have at least one NetworkPolicy for network segmentation.",
		[ns],
	)
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-014 — Service account token auto-mount
# ---------------------------------------------------------------------------

violation_k8s_014 contains msg if {
	input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController"}
	not pod_spec.automountServiceAccountToken == false
	msg := sprintf(
		"SENTINEL-K8S-014: %v '%v' does not set automountServiceAccountToken: false. Disable auto-mounting of service account tokens unless required.",
		[input.kind, _manifest_name],
	)
}

# ---------------------------------------------------------------------------
# Aggregate all violations
# ---------------------------------------------------------------------------

all_violations := array.concat(
	array.concat(
		array.concat([v | some v in violation_k8s_000], [v | some v in violation_k8s_001]),
		[v | some v in violation_k8s_002],
	),
	array.concat(
		array.concat(
			[v | some v in violation_k8s_003],
			[v | some v in violation_k8s_004],
		),
		array.concat(
			array.concat(
				[v | some v in violation_k8s_005],
				[v | some v in violation_k8s_006],
			),
			array.concat(
				array.concat(
					[v | some v in violation_k8s_007],
					[v | some v in violation_k8s_008],
				),
				array.concat(
					array.concat(
						[v | some v in violation_k8s_009],
						[v | some v in violation_k8s_010],
					),
					array.concat(
						array.concat(
							[v | some v in violation_k8s_011],
							[v | some v in violation_k8s_012],
						),
						array.concat(
							[v | some v in violation_k8s_013],
							[v | some v in violation_k8s_014],
						),
					),
				),
			),
		),
	),
)

# Gate exception (b) is withdrawn (2026-11-24). It was kept by the decision of 2026-10-19: a manifest with no
# `kind`, or a kind outside workload_kinds, was not judged and passed. The owner has superseded it ("do the
# correct one"), in line with kubernetes.admission, which already rejects a blank kind: SENTINEL-K8S-000 now denies
# a manifest whose kind is missing, empty, not a string, or not recognised (judged_kinds, builtin_kinds, input.policy.additional_kinds). SENTINEL-K8S-000 also denies input
# whose manifest is not an object or whose workload has no readable containers.
# Gate semantics: judges only what is present in the manifest, so a manifest with no
# workload containers has nothing to violate. A failing manifest still yields a result.
default compliant := false

compliant if count(all_violations) == 0

result := {
	"compliant": compliant,
	"violation_count": count(all_violations),
	"violations": all_violations,
	"resource": object.get(input, ["manifest", "metadata", "name"], null),
	"kind": object.get(input, ["kind"], null),
	"namespace": object.get(input, ["manifest", "metadata", "namespace"], null),
}
