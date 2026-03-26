package sentinel.kubernetes

import rego.v1

# =============================================================================
# Sentinel Policy Enforcement — Kubernetes Manifests
# Validates Kubernetes YAML manifests before git merge / cluster apply
#
# Policy IDs:
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

# Extract containers from any workload kind
containers := input.manifest.spec.template.spec.containers if {
    input.kind in workload_kinds
    input.kind != "Pod"
}

containers := input.manifest.spec.containers if {
    input.kind == "Pod"
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-001 — No privileged containers
# ---------------------------------------------------------------------------

violation_k8s_001 contains msg if {
    some container in containers
    container.securityContext.privileged == true
    msg := sprintf(
        "SENTINEL-K8S-001: Container '%v' runs as privileged. Privileged containers have full host access and are not permitted.",
        [container.name]
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
        [container.name]
    )
}

violation_k8s_002 contains msg if {
    some container in containers
    not container.securityContext.runAsNonRoot
    not container.securityContext.runAsUser
    msg := sprintf(
        "SENTINEL-K8S-002: Container '%v' does not set runAsNonRoot or runAsUser. Explicitly set runAsNonRoot: true.",
        [container.name]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-003 — Read-only root filesystem
# ---------------------------------------------------------------------------

violation_k8s_003 contains msg if {
    some container in containers
    container.securityContext.readOnlyRootFilesystem != true
    msg := sprintf(
        "SENTINEL-K8S-003: Container '%v' does not set readOnlyRootFilesystem: true. Read-only root filesystem prevents runtime modification.",
        [container.name]
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
        [container.name]
    )
}

violation_k8s_004 contains msg if {
    some container in containers
    not container.resources.limits.memory
    msg := sprintf(
        "SENTINEL-K8S-004: Container '%v' has no memory limit. Memory limits prevent OOM conditions from affecting other workloads.",
        [container.name]
    )
}

violation_k8s_004 contains msg if {
    some container in containers
    not container.resources.requests.cpu
    msg := sprintf(
        "SENTINEL-K8S-004: Container '%v' has no CPU request. Resource requests are required for proper scheduler decisions.",
        [container.name]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-005 — No hostNetwork, hostPID, hostIPC
# ---------------------------------------------------------------------------

violation_k8s_005 contains msg if {
    input.manifest.spec.template.spec.hostNetwork == true
    msg := "SENTINEL-K8S-005: hostNetwork is enabled. Pods must not share the host network namespace."
}

violation_k8s_005 contains msg if {
    input.manifest.spec.template.spec.hostPID == true
    msg := "SENTINEL-K8S-005: hostPID is enabled. Pods must not share the host process namespace."
}

violation_k8s_005 contains msg if {
    input.manifest.spec.template.spec.hostIPC == true
    msg := "SENTINEL-K8S-005: hostIPC is enabled. Pods must not share the host IPC namespace."
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-006 — No hostPath volumes
# ---------------------------------------------------------------------------

violation_k8s_006 contains msg if {
    some volume in input.manifest.spec.template.spec.volumes
    volume.hostPath
    msg := sprintf(
        "SENTINEL-K8S-006: Volume '%v' uses hostPath. hostPath volumes mount from the host filesystem and create security risks.",
        [volume.name]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-007 — No :latest image tags
# ---------------------------------------------------------------------------

violation_k8s_007 contains msg if {
    some container in containers
    endswith(container.image, ":latest")
    msg := sprintf(
        "SENTINEL-K8S-007: Container '%v' uses image tag ':latest' (%v). Specify an immutable tag or digest for reproducible deployments.",
        [container.name, container.image]
    )
}

violation_k8s_007 contains msg if {
    some container in containers
    not contains(container.image, ":")
    msg := sprintf(
        "SENTINEL-K8S-007: Container '%v' image '%v' has no tag. Specify an explicit version tag.",
        [container.name, container.image]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-008 — Liveness and readiness probes
# ---------------------------------------------------------------------------

violation_k8s_008 contains msg if {
    input.kind in {"Deployment", "StatefulSet", "DaemonSet"}
    some container in containers
    not container.livenessProbe
    msg := sprintf(
        "SENTINEL-K8S-008: Container '%v' has no livenessProbe. Liveness probes enable automatic recovery from deadlocked containers.",
        [container.name]
    )
}

violation_k8s_008 contains msg if {
    input.kind in {"Deployment", "StatefulSet"}
    some container in containers
    not container.readinessProbe
    msg := sprintf(
        "SENTINEL-K8S-008: Container '%v' has no readinessProbe. Readiness probes prevent traffic routing to unready containers.",
        [container.name]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-009 — No privilege escalation
# ---------------------------------------------------------------------------

violation_k8s_009 contains msg if {
    some container in containers
    container.securityContext.allowPrivilegeEscalation != false
    msg := sprintf(
        "SENTINEL-K8S-009: Container '%v' does not set allowPrivilegeEscalation: false. Set this explicitly to prevent privilege escalation.",
        [container.name]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-010 — Namespace must be set
# ---------------------------------------------------------------------------

violation_k8s_010 contains msg if {
    not input.manifest.metadata.namespace
    input.kind != "Namespace"
    input.kind != "ClusterRole"
    input.kind != "ClusterRoleBinding"
    msg := sprintf(
        "SENTINEL-K8S-010: %v '%v' does not specify a namespace. All namespaced resources must explicitly set metadata.namespace.",
        [input.kind, input.manifest.metadata.name]
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
        [label, input.kind, input.manifest.metadata.name]
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
    env.value  # has a hardcoded value (not a secretKeyRef)
    msg := sprintf(
        "SENTINEL-K8S-012: Container '%v' env var '%v' appears to contain a hardcoded secret. Use secretKeyRef or external secret management instead.",
        [container.name, env.name]
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
        [ns]
    )
}

# ---------------------------------------------------------------------------
# SENTINEL-K8S-014 — Service account token auto-mount
# ---------------------------------------------------------------------------

violation_k8s_014 contains msg if {
    input.manifest.spec.template.spec.automountServiceAccountToken != false
    input.kind in {"Deployment", "StatefulSet", "DaemonSet"}
    msg := sprintf(
        "SENTINEL-K8S-014: %v '%v' does not set automountServiceAccountToken: false. Disable auto-mounting of service account tokens unless required.",
        [input.kind, input.manifest.metadata.name]
    )
}

# ---------------------------------------------------------------------------
# Aggregate all violations
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_k8s_001],
        [v | some v in violation_k8s_002]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_k8s_003],
            [v | some v in violation_k8s_004]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_k8s_005],
                [v | some v in violation_k8s_006]
            ),
            array.concat(
                array.concat(
                    [v | some v in violation_k8s_007],
                    [v | some v in violation_k8s_008]
                ),
                array.concat(
                    array.concat(
                        [v | some v in violation_k8s_009],
                        [v | some v in violation_k8s_010]
                    ),
                    array.concat(
                        array.concat(
                            [v | some v in violation_k8s_011],
                            [v | some v in violation_k8s_012]
                        ),
                        array.concat(
                            [v | some v in violation_k8s_013],
                            [v | some v in violation_k8s_014]
                        )
                    )
                )
            )
        )
    )
)

compliant if { count(all_violations) == 0 }

result := {
    "compliant":        compliant,
    "violation_count":  count(all_violations),
    "violations":       all_violations,
    "resource":         input.manifest.metadata.name,
    "kind":             input.kind,
    "namespace":        input.manifest.metadata.namespace,
}
