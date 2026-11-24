# METADATA
# title: "Sentinel Policy Enforcement — Kubernetes Manifests"
# custom:
#   class: enforcement
#   framework: enforcement_kubernetes
#   source: aac
#   domains: [kubernetes]
#   coverage:
#     checks: 27
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
# =============================================================================

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}

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

# ---------------------------------------------------------------------------
# SENTINEL-K8S-000 — The manifest must be readable
# A document that is not a manifest is denied, never waved through. (A readable manifest of a kind
# outside workload_kinds is still not judged on the workload rules: decision 2026-10-19, below.)
# ---------------------------------------------------------------------------

violation_k8s_000 contains "SENTINEL-K8S-000: Malformed input: input.manifest is missing or is not an object; nothing was evaluated." if {
	not is_object(object.get(input, "manifest", null))
}

violation_k8s_000 contains msg if {
	"kind" in object.keys(input)
	not is_string(input.kind)
	msg := sprintf("SENTINEL-K8S-000: Malformed input: input.kind must be a string, got %v.", [type_name(input.kind)])
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
	not container.resources.limits.cpu
	msg := sprintf(
		"SENTINEL-K8S-004: Container '%v' has no CPU limit. CPU limits prevent noisy-neighbor issues and resource exhaustion.",
		[_name(container)],
	)
}

violation_k8s_004 contains msg if {
	some container in containers
	not container.resources.limits.memory
	msg := sprintf(
		"SENTINEL-K8S-004: Container '%v' has no memory limit. Memory limits prevent OOM conditions from affecting other workloads.",
		[_name(container)],
	)
}

violation_k8s_004 contains msg if {
	some container in containers
	not container.resources.requests.cpu
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
	input.kind in {"Deployment", "StatefulSet", "DaemonSet"}
	some container in containers
	not is_object(object.get(container, "livenessProbe", null))
	msg := sprintf(
		"SENTINEL-K8S-008: Container '%v' has no livenessProbe. Liveness probes enable automatic recovery from deadlocked containers.",
		[_name(container)],
	)
}

violation_k8s_008 contains msg if {
	input.kind in {"Deployment", "StatefulSet"}
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

violation_k8s_010 contains msg if {
	not _nonempty_string(object.get(input, ["manifest", "metadata", "namespace"], null))
	input.kind != "Namespace"
	input.kind != "ClusterRole"
	input.kind != "ClusterRoleBinding"
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
	some label in required_labels
	not input.manifest.metadata.labels[label]
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
	input.kind in {"Deployment", "StatefulSet", "DaemonSet"}
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

# Gate exception (b), kept by decision 2026-10-19: a manifest with no `kind` (or a kind outside
# workload_kinds) is not judged and passes; the gate judges only what is present. Callers that
# must reject unidentifiable manifests need to check input.kind themselves.
# That exception covers readable manifests only. SENTINEL-K8S-000 (2026-11-24) denies input whose
# manifest is not an object, whose kind is not a string, or whose workload has no readable containers.
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
