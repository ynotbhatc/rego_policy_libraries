# 2026-11-24: Gate exception (b) of 2026-10-19 is withdrawn. A manifest whose kind is missing, empty, not a string
# or not a kind the gate judges is denied with a SENTINEL-K8S-000 finding, never passed with nothing judged.
package sentinel.kubernetes_kind_test

import rego.v1

import data.sentinel.kubernetes as gate
import data.sentinel.kubernetes_malformed_test as m

_msgs(inp) := {msg | some msg in gate.all_violations with input as inp; startswith(msg, "SENTINEL-K8S-000")}

test_missing_kind_is_denied_and_named if {
	inp := json.remove(m.good_deployment, ["kind"])
	m._denied(inp)
	some msg in _msgs(inp)
	contains(msg, "input.kind is missing")
}

test_empty_or_blank_kind_is_denied_and_named if {
	every k in ["", "   "] {
		inp := json.patch(m.good_deployment, [{"op": "replace", "path": "/kind", "value": k}])
		m._denied(inp)
		some msg in _msgs(inp)
		contains(msg, "input.kind is empty")
	}
}

test_kind_of_another_type_is_denied_and_names_the_type if {
	every bad in [null, 1, true, ["Deployment"], {}] {
		inp := json.patch(m.good_deployment, [{"op": "replace", "path": "/kind", "value": bad}])
		m._denied(inp)
		some msg in _msgs(inp)
		contains(msg, "input.kind must be a string")
	}
}

test_unrecognised_kind_is_denied_even_when_the_pod_spec_is_bad if {
	every k in ["Deploymnt", "deployment", "false", "Foo"] {
		inp := json.patch(m.good_deployment, [
			{"op": "replace", "path": "/kind", "value": k},
			{"op": "replace", "path": "/manifest/spec/template/spec/containers/0/securityContext/privileged", "value": true},
		])
		m._denied(inp)
		some msg in _msgs(inp)
		contains(msg, "is not a standard built-in Kubernetes kind")
	}
}

test_recognised_kinds_are_still_judged if {
	m._allowed(m.good_deployment)
	every k in ["Namespace", "ConfigMap", "Service"] {
		inp := {"kind": k, "manifest": {"metadata": {"name": "x", "namespace": "shop", "labels": {"app": "a", "version": "1", "team": "t"}}}}
		count(_msgs(inp)) == 0
	}
}

# 2026-11-24: standard built-in kinds the gate does not judge are recognised, so ordinary deployments are not blocked.
test_builtin_non_workload_kind_passes_with_nothing_judged if {
	every k in ["HorizontalPodAutoscaler", "PodDisruptionBudget", "StorageClass", "Lease", "EndpointSlice", "CustomResourceDefinition", "ValidatingWebhookConfiguration", "PriorityClass", "ResourceQuota", "Node"] {
		inp := {"kind": k, "manifest": {"metadata": {"name": "x"}}}
		m._allowed(inp)
		count(gate.all_violations) == 0 with input as inp
	}
}

test_custom_resource_is_denied_with_the_way_to_allow_it if {
	inp := {"kind": "Certificate", "manifest": {"metadata": {"name": "x"}}}
	m._denied(inp)
	some msg in _msgs(inp)
	contains(msg, "\"Certificate\"")
	contains(msg, "input.policy.additional_kinds")
}

test_custom_resource_listed_in_additional_kinds_passes if {
	inp := {"kind": "Certificate", "manifest": {"metadata": {"name": "x"}}, "policy": {"additional_kinds": ["Certificate", "Issuer"]}}
	m._allowed(inp)
	count(_msgs(inp)) == 0
}

test_additional_kinds_does_not_admit_other_kinds_or_a_bad_kind if {
	inp := {"kind": "Issuer", "manifest": {"metadata": {"name": "x"}}, "policy": {"additional_kinds": ["Certificate"]}}
	m._denied(inp)
	inp2 := {"kind": "", "manifest": {"metadata": {"name": "x"}}, "policy": {"additional_kinds": [""]}}
	m._denied(inp2)
}

test_additional_kinds_of_the_wrong_type_is_an_evidence_finding_and_denies if {
	every bad in ["Certificate", {"Certificate": true}, 1, true, null, ["Certificate", 1], ["Certificate", ""], ["Certificate", null]] {
		inp := {"kind": "Certificate", "manifest": {"metadata": {"name": "x"}}, "policy": {"additional_kinds": bad}}
		m._denied(inp)
		some msg in _msgs(inp)
		contains(msg, "input.policy.additional_kinds must be a list of non-empty strings")
	}
}

test_wrong_type_additional_kinds_denies_even_for_a_judged_kind if {
	inp := json.patch(m.good_deployment, [{"op": "add", "path": "/policy", "value": {"additional_kinds": "Certificate"}}])
	m._denied(inp)
}

test_additional_kinds_does_not_relax_a_judged_workload if {
	inp := json.patch(m.good_deployment, [
		{"op": "add", "path": "/policy", "value": {"additional_kinds": ["Deployment"]}},
		{"op": "replace", "path": "/manifest/spec/template/spec/containers/0/securityContext/privileged", "value": true},
	])
	m._denied(inp)
}

# 2026-11-24: ReplicaSet and ReplicationController are judged like a Deployment (owner decision), as
# kubernetes.admission already does. The same pod template gets the same findings under either kind.
test_replicaset_and_replicationcontroller_are_judged_like_a_deployment if {
	m._allowed(m.good_deployment)
	every k in ["ReplicaSet", "ReplicationController"] {
		m._allowed(object.union(m.good_deployment, {"kind": k}))
	}
	bad := json.patch(m.good_deployment, [{"op": "add", "path": "/manifest/spec/template/spec/hostNetwork", "value": true}])
	as_deployment := gate.all_violations with input as bad
	count(as_deployment) > 0
	every k in ["ReplicaSet", "ReplicationController"] {
		v := gate.all_violations with input as object.union(bad, {"kind": k})
		count(v) == count(as_deployment)
	}
}
