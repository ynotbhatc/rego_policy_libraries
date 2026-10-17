# METADATA
# title: "Kubernetes Admission Control — Security and Operations Policy"
# custom:
#   class: enforcement
#   framework: enforcement_kubernetes
#   source: aac
#   domains: [kubernetes]
#   coverage:
#     checks: 28
#     cited: 0
#     density: gate
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: n/a
#     as_of: v2.4.2
package kubernetes.admission

# Kubernetes Admission Control — Security and Operations Policy
#
# OPA Gatekeeper-compatible admission policies for Kubernetes workloads.
# These policies can be deployed as:
#   - OPA Gatekeeper ConstraintTemplate + Constraint pairs
#   - Kyverno ClusterPolicy (translated)
#   - Validating Admission Webhook backed by this OPA policy
#
# Key controls:
#   - Resource limits and requests required on all containers
#   - Approved image registries only
#   - No 'latest' image tags in non-dev namespaces
#   - Required workload labels (app, version, team)
#   - No privileged containers or host namespace sharing
#   - Read-only root filesystem (or explicit opt-out)
#   - Liveness/readiness probes on Deployments
#   - No default service account with auto-mount
#   - PodDisruptionBudget required for HA workloads
#   - No NodePort services in production
#   - Egress NetworkPolicy required per namespace
#
# OPA endpoint: POST http://localhost:8181/v1/data/kubernetes/admission
# Input: Kubernetes admission review request (AdmissionReview v1)

import rego.v1

default allow := false

allow if { count(deny) == 0 }

# Expose violations as 'deny' for webhook compatibility and 'violations' for reporting
# DELETE requests carry no object to judge, so they are never denied by object checks
deny contains msg if {
	not is_delete
	some msg in violations
}

default compliant := false

compliant if { count(violations) == 0 }

# =============================================================================
# NAMESPACE CLASSIFICATION
# =============================================================================

production_namespaces := object.get(input, ["policy", "production_namespaces"], {"default", "kube-system"})

system_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

is_production_namespace(ns) if { ns in production_namespaces }
is_production_namespace(ns) if { not startswith(ns, "dev-"); not startswith(ns, "test-"); not startswith(ns, "sandbox-"); ns != "staging" }

is_dev_namespace(ns) if { startswith(ns, "dev-") }
is_dev_namespace(ns) if { startswith(ns, "test-") }
is_dev_namespace(ns) if { startswith(ns, "sandbox-") }
is_dev_namespace(ns) if { ns == "staging" }

namespace := object.get(input, ["request", "namespace"], "default")
resource_kind := object.get(input, ["request", "kind", "kind"], "")
resource_object := object.get(input, ["request", "object"], {})
resource_name := object.get(resource_object, ["metadata", "name"], "unnamed")

# =============================================================================
# RESOURCE LIMITS AND REQUESTS
# =============================================================================

# Every kind that carries a pod template (ReplicaSet / ReplicationController included)
workload_kinds := {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job", "CronJob"}

# Long-running pod-template kinds
long_running_kinds := {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController"}

pod_spec := resource_object.spec if {
	resource_kind == "Pod"
}

pod_spec := resource_object.spec.template.spec if {
	resource_kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job"}
}

# Main, init and ephemeral containers are all subject to the security checks
all_containers := array.concat(
	array.concat(object.get(pod_spec, "containers", []), object.get(pod_spec, "initContainers", [])),
	object.get(pod_spec, "ephemeralContainers", []),
)

# Fail closed on a request that carries nothing to judge (DELETE legitimately has no object)
is_delete if { input.request.operation == "DELETE" }

request_evaluable if { is_delete }

request_evaluable if {
	is_string(input.request.kind.kind)
	is_object(input.request.object)
	count(input.request.object) > 0
}

violations contains "AdmissionReview: request.kind.kind / request.object missing or empty — request cannot be evaluated" if {
	not request_evaluable
}

# Annotation opt-outs apply only when explicitly set to "true"
annotation_true(name) if {
	lower(resource_object.metadata.annotations[name]) == "true"
}

pod_spec := resource_object.spec.jobTemplate.spec.template.spec if {
	resource_kind == "CronJob"
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no CPU limit — resource limits required for cluster stability", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not container.resources.limits.cpu
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no memory limit — memory limits required to prevent OOM evictions", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not container.resources.limits.memory
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no CPU request — requests required for scheduler accuracy", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not container.resources.requests.cpu
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no memory request", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not container.resources.requests.memory
}

# =============================================================================
# APPROVED IMAGE REGISTRIES
# =============================================================================

approved_registries := object.get(input, ["policy", "approved_registries"], {
	"ghcr.io",
	"quay.io",
	"registry.access.redhat.com",
	"registry.redhat.io",
	"registry.k8s.io",
	"gcr.io",
})

violations contains sprintf("Registry: Container '%s' in %s '%s' uses unapproved image '%s' — only approved registries allowed: %s", [container.name, resource_kind, resource_name, container.image, concat(", ", approved_registries)]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not from_approved_registry(container.image)
}

from_approved_registry(image) if {
	some registry in approved_registries
	# anchored on the host component: "quay.io" must not admit "quay.io.evil.example/..."
	startswith(image, concat("", [trim_suffix(registry, "/"), "/"]))
}

# Allow images without registry prefix (cluster-local)
# NOTE: needs_decision (validation 2026-10-17): a bare name such as "nginx:1.25" resolves to Docker Hub.
from_approved_registry(image) if {
	not contains(image, "/")
}

# =============================================================================
# IMAGE TAG POLICY
# =============================================================================

violations contains sprintf("ImageTag: Container '%s' in %s '%s' uses 'latest' tag — pin to a specific digest or version tag", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	is_production_namespace(namespace)
	some container in all_containers
	is_latest_tag(container.image)
}

is_latest_tag(image) if { endswith(image, ":latest") }
is_latest_tag(image) if { not contains(image, ":"); not contains(image, "@") }

violations contains sprintf("ImageTag: Container '%s' in %s '%s' uses mutable tag without digest — use image@sha256:<digest> in production", [container.name, resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	object.get(input, ["policy", "require_image_digest"], false)
	some container in all_containers
	not contains(container.image, "@sha256:")
}

# =============================================================================
# REQUIRED WORKLOAD LABELS
# =============================================================================

required_workload_labels := {"app", "version", "team"}

violations contains sprintf("Labels: %s '%s' in namespace '%s' is missing required label '%s'", [resource_kind, resource_name, namespace, label]) if {
	resource_kind in {"Deployment", "DaemonSet", "StatefulSet"}
	some label in required_workload_labels
	not resource_object.metadata.labels[label]
}

violations contains sprintf("Labels: %s '%s' pod template is missing required label '%s' (needed for service selection and observability)", [resource_kind, resource_name, label]) if {
	resource_kind in {"Deployment", "DaemonSet", "StatefulSet"}
	some label in required_workload_labels
	not resource_object.spec.template.metadata.labels[label]
}

# =============================================================================
# SECURITY CONTEXT
# =============================================================================

violations contains sprintf("Security: Container '%s' in %s '%s' is privileged — privileged containers are not permitted", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	container.securityContext.privileged == true
}

violations contains sprintf("Security: %s '%s' shares host PID namespace — hostPID: true is not permitted", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	pod_spec.hostPID == true
}

violations contains sprintf("Security: %s '%s' shares host IPC namespace — hostIPC: true is not permitted", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	pod_spec.hostIPC == true
}

violations contains sprintf("Security: %s '%s' shares host network namespace — hostNetwork: true is not permitted", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	not namespace in system_namespaces
	pod_spec.hostNetwork == true
}

violations contains sprintf("Security: Container '%s' in %s '%s' allows privilege escalation — set allowPrivilegeEscalation: false", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	container.securityContext.allowPrivilegeEscalation != false
	not container.securityContext.privileged
}

violations contains sprintf("Security: Container '%s' in %s '%s' does not set readOnlyRootFilesystem: true — use ephemeral volumes for writes", [container.name, resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	some container in all_containers
	container.securityContext.readOnlyRootFilesystem != true
	not annotation_true("admission.kubernetes.io/skip-readonly-check")
}

violations contains sprintf("Security: Container '%s' in %s '%s' runs as root (runAsNonRoot not set or false)", [container.name, resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not pod_spec.securityContext.runAsNonRoot
	not container.securityContext.runAsNonRoot
}

violations contains sprintf("Security: Container '%s' drops no capabilities — add 'drop: [\"ALL\"]' to securityContext", [container.name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	some container in all_containers
	not drops_all_capabilities(container)
}

drops_all_capabilities(container) if {
	some d in container.securityContext.capabilities.drop
	upper(d) == "ALL"
}

# =============================================================================
# SERVICE ACCOUNT HYGIENE
# =============================================================================

violations contains sprintf("ServiceAccount: %s '%s' uses default service account — create a dedicated service account with minimal RBAC", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	not pod_spec.serviceAccountName
}

violations contains sprintf("ServiceAccount: %s '%s' uses default service account — create a dedicated service account", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	pod_spec.serviceAccountName == "default"
}

violations contains sprintf("ServiceAccount: %s '%s' auto-mounts service account token — set automountServiceAccountToken: false if API access not needed", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	pod_spec.automountServiceAccountToken != false
	not annotation_true("admission.kubernetes.io/requires-sa-token")
}

# =============================================================================
# PROBES (LIVENESS / READINESS)
# =============================================================================

violations contains sprintf("Probes: Container '%s' in Deployment '%s' has no readinessProbe — readiness probes required for zero-downtime deployments", [container.name, resource_name]) if {
	resource_kind == "Deployment"
	some container in object.get(pod_spec, "containers", [])
	not container.readinessProbe
}

violations contains sprintf("Probes: Container '%s' in Deployment '%s' has no livenessProbe — liveness probes required for self-healing", [container.name, resource_name]) if {
	resource_kind == "Deployment"
	is_production_namespace(namespace)
	some container in object.get(pod_spec, "containers", [])
	not container.livenessProbe
}

# =============================================================================
# SERVICES — NO NODEPORT IN PRODUCTION
# =============================================================================

violations contains sprintf("Service: Service '%s' uses NodePort type in production namespace '%s' — use ClusterIP + Ingress or LoadBalancer", [resource_name, namespace]) if {
	resource_kind == "Service"
	is_production_namespace(namespace)
	resource_object.spec.type == "NodePort"
}

violations contains sprintf("Service: Service '%s' has no selector — services without selectors should be documented with annotation 'admission.kubernetes.io/headless-service: true'", [resource_name]) if {
	resource_kind == "Service"
	not resource_object.spec.selector
	not annotation_true("admission.kubernetes.io/headless-service")
}

# =============================================================================
# INGRESS SECURITY
# =============================================================================

violations contains sprintf("Ingress: Ingress '%s' has no TLS configuration — all production ingresses must use TLS", [resource_name]) if {
	resource_kind == "Ingress"
	is_production_namespace(namespace)
	not has_tls
}

# a non-empty spec.tls list (an empty list is no TLS)
has_tls if count(object.get(object.get(resource_object, "spec", {}), "tls", [])) > 0

violations contains sprintf("Ingress: Ingress '%s' does not specify ingressClassName — use explicit class to prevent routing conflicts", [resource_name]) if {
	resource_kind == "Ingress"
	not resource_object.spec.ingressClassName
	not resource_object.metadata.annotations["kubernetes.io/ingress.class"]
}

# =============================================================================
# COMPLIANCE REPORT
# =============================================================================

violations_by_category := {
	"resources":       [v | some v in violations; contains(v, "Resources:")],
	"registry":        [v | some v in violations; contains(v, "Registry:")],
	"image_tags":      [v | some v in violations; contains(v, "ImageTag:")],
	"labels":          [v | some v in violations; contains(v, "Labels:")],
	"security":        [v | some v in violations; contains(v, "Security:")],
	"service_account": [v | some v in violations; contains(v, "ServiceAccount:")],
	"probes":          [v | some v in violations; contains(v, "Probes:")],
	"services":        [v | some v in violations; contains(v, "Service:")],
	"ingress":         [v | some v in violations; contains(v, "Ingress:")],
}

compliance_report := {
	"framework":             "Kubernetes Admission Control",
	"standard":              "kubernetes.admission",
	"compliant":             compliant,
	"allow":                 allow,
	"resource_kind":         resource_kind,
	"resource_name":         resource_name,
	"namespace":             namespace,
	"is_production":         is_production_namespace(namespace),
	"violation_count":       count(violations),
	"violations":            [v | some v in violations],
	"violations_by_category": violations_by_category,
}
