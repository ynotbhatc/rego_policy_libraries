package kubernetes.admission_test

import rego.v1

import data.kubernetes.admission as adm

container(extra) := object.union(
	{
		"name": "app",
		"image": "quay.io/org/app:1.0",
		"resources": {"limits": {"cpu": "1", "memory": "1Gi"}, "requests": {"cpu": "1", "memory": "1Gi"}},
		"securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "capabilities": {"drop": ["ALL"]}},
	},
	extra,
)

review(kind, spec_wrapper) := {"request": {"operation": "CREATE", "namespace": "prod", "kind": {"kind": kind}, "object": spec_wrapper}}

template(spec) := {
	"metadata": {"name": "w", "labels": {"app": "a", "version": "1", "team": "t"}},
	"spec": {"template": {"metadata": {"labels": {"app": "a", "version": "1", "team": "t"}}, "spec": object.union({"serviceAccountName": "sa", "automountServiceAccountToken": false}, spec)}},
}

has_violation(i, needle) if {
	some v in adm.violations with input as i
	contains(v, needle)
}

test_clean_deployment_allowed if {
	i := review("Deployment", template({"containers": [container({"readinessProbe": {}, "livenessProbe": {}})]}))
	adm.allow with input as i
}

test_empty_request_denied if {
	not adm.allow with input as {}
	has_violation({}, "request cannot be evaluated")
}

test_delete_request_allowed if {
	adm.allow with input as {"request": {"operation": "DELETE", "kind": {"kind": "Pod"}, "namespace": "prod"}}
}

test_replicaset_privileged_container_denied if {
	i := review("ReplicaSet", template({"containers": [container({"securityContext": {"privileged": true}})]}))
	has_violation(i, "is privileged")
}

test_init_container_privileged_denied if {
	i := review("Deployment", template({"containers": [container({"readinessProbe": {}, "livenessProbe": {}})], "initContainers": [container({"name": "init", "securityContext": {"privileged": true}})]}))
	has_violation(i, "Container 'init'")
}

test_init_container_unapproved_registry_denied if {
	i := review("Deployment", template({"containers": [container({"readinessProbe": {}, "livenessProbe": {}})], "initContainers": [container({"name": "init", "image": "evil.example/x:1"})]}))
	has_violation(i, "Registry:")
}

test_empty_tls_list_denied if {
	i := {"request": {"operation": "CREATE", "namespace": "prod", "kind": {"kind": "Ingress"}, "object": {"metadata": {"name": "i"}, "spec": {"tls": [], "ingressClassName": "nginx"}}}}
	has_violation(i, "no TLS configuration")
}

test_nonempty_tls_list_allowed if {
	i := {"request": {"operation": "CREATE", "namespace": "prod", "kind": {"kind": "Ingress"}, "object": {"metadata": {"name": "i"}, "spec": {"tls": [{"hosts": ["a"]}], "ingressClassName": "nginx"}}}}
	adm.allow with input as i
}

test_partial_drop_list_denied if {
	i := review("Deployment", template({"containers": [container({"readinessProbe": {}, "livenessProbe": {}, "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "capabilities": {"drop": ["NET_RAW"]}}})]}))
	has_violation(i, "drops no capabilities")
}

test_annotation_false_does_not_opt_out if {
	w := object.union(template({"containers": [container({"readinessProbe": {}, "livenessProbe": {}, "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": false, "runAsNonRoot": true, "capabilities": {"drop": ["ALL"]}}})]}), {"metadata": {"annotations": {"admission.kubernetes.io/skip-readonly-check": "false"}}})
	has_violation(review("Deployment", w), "readOnlyRootFilesystem")
}

test_annotation_true_opts_out if {
	w := object.union(template({"containers": [container({"readinessProbe": {}, "livenessProbe": {}, "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": false, "runAsNonRoot": true, "capabilities": {"drop": ["ALL"]}}})]}), {"metadata": {"annotations": {"admission.kubernetes.io/skip-readonly-check": "true"}}})
	not has_violation(review("Deployment", w), "readOnlyRootFilesystem")
}

# ── Audit 2026-11-24: the report is defined and failing on no input and on malformed reviews ────────

_report_fails(r) if {
	is_object(r)
	r.compliant == false
	r.allow == false
	r.violation_count >= 1
	some v in r.violations
	contains(v, "request cannot be evaluated")
}

test_report_defined_and_failing_on_non_object_input if {
	every bad in [null, "true", 1, true, [], {}] {
		_report_fails(data.kubernetes.admission.compliance_report) with input as bad
	}
}

test_report_defined_and_failing_on_malformed_request if {
	every bad in [null, "true", 1, [], {}] {
		_report_fails(data.kubernetes.admission.compliance_report) with input as {"request": bad}
		_report_fails(data.kubernetes.admission.compliance_report) with input as {"request": {"kind": {"kind": "Pod"}, "object": bad}}
		_report_fails(data.kubernetes.admission.compliance_report) with input as {"request": {"kind": bad, "object": {"metadata": {"name": "x"}}}}
	}
}

# Audit 2026-11-24 round 2: a blank kind matches no rule, so the review was admitted with nothing judged.
test_blank_kind_is_not_evaluable if {
	every kind in ["", "   "] {
		r := data.kubernetes.admission.compliance_report with input as {"request": {"kind": {"kind": kind}, "object": {"metadata": {"name": "x"}}}}
		r.compliant == false
		r.allow == false
		r.violation_count == 1
	}
}

# A kind this policy has no rule for (ConfigMap here) is admitted: the policy judges workloads, Services and
# Ingresses, and the API server has already type-checked the object against its schema.
test_kind_without_rules_is_admitted if {
	r := data.kubernetes.admission.compliance_report with input as {"request": {"kind": {"kind": "ConfigMap"}, "namespace": "dev-a", "object": {"metadata": {"name": "x"}, "data": {"k": "v"}}}}
	r.compliant == true
	r.allow == true
	r.is_production == false
}

# The report was undefined for every request in a dev-, test-, sandbox- or staging namespace: the
# is_production field called a function that is undefined (not false) for those namespaces.
test_report_defined_in_non_production_namespaces if {
	every ns in ["dev-a", "test-a", "sandbox-a", "staging"] {
		r := data.kubernetes.admission.compliance_report with input as {"request": {"kind": {"kind": "Pod"}, "namespace": ns, "object": {"metadata": {"name": "x"}, "spec": {"containers": [{"name": "c", "image": "registry.access.redhat.com/ubi9/ubi:9.4", "securityContext": {"privileged": true}}]}}}}
		r.is_production == false
		r.compliant == false
		r.violation_count > 0
	}
	r := data.kubernetes.admission.compliance_report with input as {"request": {"kind": {"kind": "ConfigMap"}, "namespace": "payments", "object": {"metadata": {"name": "x"}}}}
	r.is_production == true
}
