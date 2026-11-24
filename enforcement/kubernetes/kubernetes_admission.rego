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

allow if count(deny) == 0

# Expose violations as 'deny' for webhook compatibility and 'violations' for reporting
# DELETE requests carry no object to judge, so they are never denied by object checks
deny contains msg if {
	not is_delete
	some msg in violations
}

# The review as an object. With no input document at all, or an input that is not an object, object.get on
# `input` is undefined or an error and the whole report used to go undefined (the product then drops the
# row). It now reads as an empty review: the request is not evaluable, which is a reported violation.
default _input := {}

_input := input if is_object(input)

default compliant := false

compliant if count(violations) == 0

# =============================================================================
# NAMESPACE CLASSIFICATION
# =============================================================================

production_namespaces := object.get(_input, ["policy", "production_namespaces"], {"default", "kube-system"})

system_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

is_production_namespace(ns) if ns in production_namespaces

is_production_namespace(ns) if {
	not startswith(ns, "dev-")
	not startswith(ns, "test-")
	not startswith(ns, "sandbox-")
	ns != "staging"
}

is_dev_namespace(ns) if startswith(ns, "dev-")
is_dev_namespace(ns) if startswith(ns, "test-")
is_dev_namespace(ns) if startswith(ns, "sandbox-")
is_dev_namespace(ns) if ns == "staging"

namespace := object.get(_input, ["request", "namespace"], "default")
resource_kind := object.get(_input, ["request", "kind", "kind"], "")

# request.object that is not an object (a string, a list) reads as empty: object.get on it would be an
# error and take the report with it. request_evaluable reports it.
default resource_object := {}

resource_object := obj if {
	obj := object.get(_input, ["request", "object"], {})
	is_object(obj)
}

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
	array.concat(_container_list("containers"), _container_list("initContainers")),
	_container_list("ephemeralContainers"),
)

# A container list as the pod spec states it; missing, null or anything that is not a list reads as empty
# here (array.concat on it would be an error) and the readable-workload rule below reports it.
_container_list(field) := list if {
	list := object.get(pod_spec, field, null)
	is_array(list)
} else := []

# A name for messages. A finding must never disappear because the object it names has no name.
_name(o) := n if {
	n := o.name
	is_string(n)
} else := "<unnamed>"

# A switch that must stay off is off only as the boolean false or when unset (null is unset to the API
# server): true, and also "true", "false" and numbers, turn the finding on.
_on(value) if {
	not is_null(value)
	value != false
}

_nonempty_string(v) if {
	is_string(v)
	trim_space(v) != ""
}

# A resource quantity is a non-empty string ("500m", "1Gi") or a number; null, false and "" are no limit.
_quantity(v) if _nonempty_string(v)

_quantity(v) if is_number(v)

# A workload must carry something to judge: a pod spec whose containers are a non-empty list of objects,
# and init / ephemeral container lists that are lists of objects when they are set. The API server
# rejects anything else, so this never denies a real workload; it denies a review this policy cannot read.
violations contains sprintf("AdmissionReview: %s '%s' has no pod spec with a non-empty containers list of objects — request cannot be evaluated", [resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	request_evaluable
	not is_delete
	not _containers_readable
}

_containers_readable if {
	main := object.get(pod_spec, "containers", null)
	is_array(main)
	count(main) > 0
	every field in ["containers", "initContainers", "ephemeralContainers"] {
		list := object.get(pod_spec, field, [])
		_list_of_objects(list)
	}
}

_list_of_objects(list) if is_null(list)

_list_of_objects(list) if {
	is_array(list)
	every c in list {
		is_object(c)
	}
}

# Fail closed on a request that carries nothing to judge (DELETE legitimately has no object)
is_delete if input.request.operation == "DELETE"

request_evaluable if is_delete

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

violations contains sprintf("Resources: Container '%s' in %s '%s' has no CPU limit — resource limits required for cluster stability", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not _quantity(object.get(container, ["resources", "limits", "cpu"], null))
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no memory limit — memory limits required to prevent OOM evictions", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not _quantity(object.get(container, ["resources", "limits", "memory"], null))
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no CPU request — requests required for scheduler accuracy", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not _quantity(object.get(container, ["resources", "requests", "cpu"], null))
}

violations contains sprintf("Resources: Container '%s' in %s '%s' has no memory request", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not _quantity(object.get(container, ["resources", "requests", "memory"], null))
}

# =============================================================================
# APPROVED IMAGE REGISTRIES
# =============================================================================

default_approved_registries := {
	"ghcr.io",
	"quay.io",
	"registry.access.redhat.com",
	"registry.redhat.io",
	"registry.k8s.io",
	"gcr.io",
}

# The operator's list when it is one (a list or set of strings); the default when none is stated. A stated
# list that cannot be read approves nothing and is reported: it used to make every Registry finding vanish
# (the message joins the list, and joining null or a number is an error).
approved_registries := default_approved_registries if not _registries_stated

approved_registries := {r | some r in _input.policy.approved_registries; _nonempty_string(r)} if {
	_registries_stated
	_registries_readable
}

approved_registries := set() if {
	_registries_stated
	not _registries_readable
}

_registries_stated if "approved_registries" in object.keys(object.get(_input, "policy", {}))

_registries_readable if {
	list := _input.policy.approved_registries
	_is_collection(list)
	every r in list {
		_nonempty_string(r)
	}
}

_is_collection(x) if is_array(x)

_is_collection(x) if is_set(x)

violations contains "Registry: policy.approved_registries must be a list of registry host names — no registry is approved until it is" if {
	_registries_stated
	not _registries_readable
}

violations contains sprintf("Registry: Container '%s' in %s '%s' uses unapproved image '%v' — only approved registries allowed: %s", [_name(container), resource_kind, resource_name, object.get(container, "image", null), concat(", ", sort(approved_registries))]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not from_approved_registry(object.get(container, "image", null))
}

from_approved_registry(image) if {
	is_string(image)
	some registry in approved_registries

	# anchored on the host component: "quay.io" must not admit "quay.io.evil.example/..."
	startswith(image, concat("", [trim_suffix(registry, "/"), "/"]))
}

# An image with no registry host (nginx:1.25, myorg/app:1) is resolved by the
# container runtime to docker.io. It is therefore admitted only when docker.io
# is on the approved list (decisions 2026-10-19; previously treated as
# cluster-local). A registry host is a first path component containing "." or
# ":" or equal to "localhost".
from_approved_registry(image) if {
	_nonempty_string(image)
	not has_registry_host(image)
	some registry in approved_registries
	trim_suffix(registry, "/") in {"docker.io", "index.docker.io"}
}

has_registry_host(image) if {
	contains(image, "/")
	first := split(image, "/")[0]
	regex.match(`[.:]`, first)
}

has_registry_host(image) if startswith(image, "localhost/")

# =============================================================================
# IMAGE TAG POLICY
# =============================================================================

violations contains sprintf("ImageTag: Container '%s' in %s '%s' uses 'latest' tag — pin to a specific digest or version tag", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	is_production_namespace(namespace)
	some container in all_containers
	is_latest_tag(object.get(container, "image", null))
}

is_latest_tag(image) if endswith(image, ":latest")

# no image, or an image that is not a string, has no pinned tag
is_latest_tag(image) if not is_string(image)

is_latest_tag(image) if {
	not contains(image, ":")
	not contains(image, "@")
}

violations contains sprintf("ImageTag: Container '%s' in %s '%s' uses mutable tag without digest — use image@sha256:<digest> in production", [_name(container), resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	object.get(_input, ["policy", "require_image_digest"], false)
	some container in all_containers
	not _has_digest(container)
}

_has_digest(container) if contains(container.image, "@sha256:")

# =============================================================================
# REQUIRED WORKLOAD LABELS
# =============================================================================

required_workload_labels := {"app", "version", "team"}

violations contains sprintf("Labels: %s '%s' in namespace '%s' is missing required label '%s'", [resource_kind, resource_name, namespace, label]) if {
	resource_kind in {"Deployment", "DaemonSet", "StatefulSet"}
	some label in required_workload_labels
	not _nonempty_string(object.get(resource_object, ["metadata", "labels", label], null))
}

violations contains sprintf("Labels: %s '%s' pod template is missing required label '%s' (needed for service selection and observability)", [resource_kind, resource_name, label]) if {
	resource_kind in {"Deployment", "DaemonSet", "StatefulSet"}
	some label in required_workload_labels
	not _nonempty_string(object.get(resource_object, ["spec", "template", "metadata", "labels", label], null))
}

# =============================================================================
# SECURITY CONTEXT
# =============================================================================

violations contains sprintf("Security: Container '%s' in %s '%s' is privileged — privileged containers are not permitted", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	_on(object.get(container, ["securityContext", "privileged"], null))
}

violations contains sprintf("Security: %s '%s' shares host PID namespace — hostPID: true is not permitted", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	_on(object.get(pod_spec, "hostPID", null))
}

violations contains sprintf("Security: %s '%s' shares host IPC namespace — hostIPC: true is not permitted", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	_on(object.get(pod_spec, "hostIPC", null))
}

violations contains sprintf("Security: %s '%s' shares host network namespace — hostNetwork: true is not permitted", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	not namespace in system_namespaces
	_on(object.get(pod_spec, "hostNetwork", null))
}

violations contains sprintf("Security: Container '%s' in %s '%s' allows privilege escalation — set allowPrivilegeEscalation: false", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	container.securityContext.allowPrivilegeEscalation != false
	not _on(object.get(container, ["securityContext", "privileged"], null))
}

violations contains sprintf("Security: Container '%s' in %s '%s' does not set readOnlyRootFilesystem: true — use ephemeral volumes for writes", [_name(container), resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	some container in all_containers
	container.securityContext.readOnlyRootFilesystem != true
	not annotation_true("admission.kubernetes.io/skip-readonly-check")
}

violations contains sprintf("Security: Container '%s' in %s '%s' runs as root (runAsNonRoot not set or false)", [_name(container), resource_kind, resource_name]) if {
	resource_kind in workload_kinds
	some container in all_containers
	not object.get(pod_spec, ["securityContext", "runAsNonRoot"], null) == true
	not object.get(container, ["securityContext", "runAsNonRoot"], null) == true
}

violations contains sprintf("Security: Container '%s' drops no capabilities — add 'drop: [\"ALL\"]' to securityContext", [_name(container)]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	some container in all_containers
	not drops_all_capabilities(container)
}

drops_all_capabilities(container) if {
	some d in container.securityContext.capabilities.drop
	is_string(d)
	upper(d) == "ALL"
}

# =============================================================================
# SERVICE ACCOUNT HYGIENE
# =============================================================================

violations contains sprintf("ServiceAccount: %s '%s' uses default service account — create a dedicated service account with minimal RBAC", [resource_kind, resource_name]) if {
	resource_kind in long_running_kinds
	is_production_namespace(namespace)
	not _nonempty_string(object.get(pod_spec, "serviceAccountName", null))
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

violations contains sprintf("Probes: Container '%s' in Deployment '%s' has no readinessProbe — readiness probes required for zero-downtime deployments", [_name(container), resource_name]) if {
	resource_kind == "Deployment"
	some container in _container_list("containers")
	not is_object(object.get(container, "readinessProbe", null))
}

violations contains sprintf("Probes: Container '%s' in Deployment '%s' has no livenessProbe — liveness probes required for self-healing", [_name(container), resource_name]) if {
	resource_kind == "Deployment"
	is_production_namespace(namespace)
	some container in _container_list("containers")
	not is_object(object.get(container, "livenessProbe", null))
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
	not _selector_set
	not annotation_true("admission.kubernetes.io/headless-service")
}

# a selector is a non-empty object of labels (null, "" and {} select nothing)
_selector_set if {
	sel := resource_object.spec.selector
	is_object(sel)
	count(sel) > 0
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
has_tls if {
	tls := resource_object.spec.tls
	is_array(tls)
	count(tls) > 0
}

violations contains sprintf("Ingress: Ingress '%s' does not specify ingressClassName — use explicit class to prevent routing conflicts", [resource_name]) if {
	resource_kind == "Ingress"
	not _nonempty_string(object.get(resource_object, ["spec", "ingressClassName"], null))
	not _nonempty_string(object.get(resource_object, ["metadata", "annotations", "kubernetes.io/ingress.class"], null))
}

# =============================================================================
# COMPLIANCE REPORT
# =============================================================================

violations_by_category := {
	"resources": [v | some v in violations; contains(v, "Resources:")],
	"registry": [v | some v in violations; contains(v, "Registry:")],
	"image_tags": [v | some v in violations; contains(v, "ImageTag:")],
	"labels": [v | some v in violations; contains(v, "Labels:")],
	"security": [v | some v in violations; contains(v, "Security:")],
	"service_account": [v | some v in violations; contains(v, "ServiceAccount:")],
	"probes": [v | some v in violations; contains(v, "Probes:")],
	"services": [v | some v in violations; contains(v, "Service:")],
	"ingress": [v | some v in violations; contains(v, "Ingress:")],
}

compliance_report := {
	"framework": "Kubernetes Admission Control",
	"standard": "kubernetes.admission",
	"compliant": compliant,
	"allow": allow,
	"resource_kind": resource_kind,
	"resource_name": resource_name,
	"namespace": namespace,
	"is_production": is_production_namespace(namespace),
	"violation_count": count(violations),
	"violations": [v | some v in violations],
	"violations_by_category": violations_by_category,
}
