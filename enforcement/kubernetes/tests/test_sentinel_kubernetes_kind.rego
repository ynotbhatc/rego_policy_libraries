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
		contains(msg, "is not a kind this gate judges")
	}
}

test_recognised_kinds_are_still_judged if {
	m._allowed(m.good_deployment)
	every k in ["Namespace", "ConfigMap", "Service"] {
		inp := {"kind": k, "manifest": {"metadata": {"name": "x", "namespace": "shop", "labels": {"app": "a", "version": "1", "team": "t"}}}}
		count(_msgs(inp)) == 0
	}
}
