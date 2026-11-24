# A malformed manifest is denied (SENTINEL-K8S-000 and the type checks in the workload rules): the gate
# never allows input it could not read as a manifest.

package sentinel.kubernetes_malformed_test

import rego.v1

import data.sentinel.kubernetes as gate
import data.sentinel_kubernetes.main

good_deployment := {
	"kind": "Deployment",
	"namespace": "shop",
	"existing_policies": [{"name": "default-deny", "namespace": "shop"}],
	"manifest": {
		"metadata": {"name": "web", "namespace": "shop", "labels": {"app": "web", "version": "1.4.2", "team": "shop"}},
		"spec": {"template": {"spec": {
			"automountServiceAccountToken": false,
			"hostNetwork": false,
			"containers": [{
				"name": "web",
				"image": "registry.example.com/shop/web:1.4.2",
				"securityContext": {
					"privileged": false,
					"runAsNonRoot": true,
					"runAsUser": 10001,
					"readOnlyRootFilesystem": true,
					"allowPrivilegeEscalation": false,
				},
				"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}},
				"livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080}},
				"readinessProbe": {"httpGet": {"path": "/ready", "port": 8080}},
			}],
		}}},
	},
}

_allowed(inp) if {
	gate.compliant with input as inp
	main.compliance_report.compliant == true with input as inp
}

_denied(inp) if {
	not gate.compliant with input as inp
	main.compliance_report.compliant == false with input as inp
}

_k8s000(inp) if {
	some msg in gate.all_violations with input as inp
	startswith(msg, "SENTINEL-K8S-000: Malformed")
}

_c := "/manifest/spec/template/spec/containers/0"

test_good_deployment_is_allowed if _allowed(good_deployment)

test_empty_input_is_denied if _denied({})

test_input_that_is_not_a_manifest_is_denied if {
	every inp in [{"foo": "bar"}, {"kind": "Deployment"}, {"manifest": null, "kind": null}, {"manifest": "true", "kind": "true"}, {"manifest": [], "kind": "Pod"}, {"image": "nginx:1.27", "securityContext": {"privileged": false}}] {
		_denied(inp)
		_k8s000(inp)
	}
}

test_kind_of_the_wrong_type_is_denied if {
	every bad in [1, true, ["Deployment"]] {
		inp := json.patch(good_deployment, [{"op": "replace", "path": "/kind", "value": bad}])
		_denied(inp)
		_k8s000(inp)
	}
}

test_workload_without_readable_containers_is_denied if {
	every path in ["/manifest/spec", "/manifest/spec/template", "/manifest/spec/template/spec", "/manifest/spec/template/spec/containers", _c] {
		every bad in [null, "true", 1] {
			inp := json.patch(good_deployment, [{"op": "replace", "path": path, "value": bad}])
			_denied(inp)
			_k8s000(inp)
		}
	}
	_denied(json.patch(good_deployment, [{"op": "replace", "path": "/manifest/spec/template/spec/containers", "value": []}]))
	_denied(json.patch(good_deployment, [{"op": "remove", "path": "/manifest/spec/template/spec/containers"}]))
}

# Decision 2026-10-19 stands: a readable manifest of a kind the workload rules do not cover is not judged on them.
test_readable_non_workload_manifest_is_still_allowed if {
	_allowed({
		"kind": "ConfigMap",
		"existing_policies": [{"name": "default-deny", "namespace": "shop"}],
		"manifest": {"metadata": {"name": "settings", "namespace": "shop", "labels": {"app": "web", "version": "1", "team": "shop"}}, "data": {"k": "v"}},
	})
}

# Every boolean and number in the allowed manifest, sent as a string or as null, is denied; so is removing
# it, except hostNetwork and privileged (unset is off), runAsNonRoot and runAsUser (either one meets
# SENTINEL-K8S-002) and the probe ports (not judged).
_leaves := [[p, v] |
	walk(good_deployment, [p, v])
	not is_object(v)
	not is_array(v)
	not is_string(v)
	p[count(p) - 1] != "port"
]

test_leaf_of_the_wrong_type_is_denied if {
	count(_leaves) == 7
	every leaf in _leaves {
		[p, v] := leaf
		every bad in [sprintf("%v", [v]), "x", [v]] {
			_denied(json.patch(good_deployment, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_leaf_null_or_removed_is_denied_unless_unset_means_off if {
	every leaf in [l | some l in _leaves; not l[0][count(l[0]) - 1] in {"hostNetwork", "privileged", "runAsUser", "runAsNonRoot"}] {
		[p, _] := leaf
		_denied(json.patch(good_deployment, [{"op": "replace", "path": p, "value": null}]))
		_denied(json.patch(good_deployment, [{"op": "remove", "path": p}]))
	}
}

test_off_switch_as_a_string_is_denied if {
	every path in ["/manifest/spec/template/spec/hostNetwork", "/manifest/spec/template/spec/hostPID", "/manifest/spec/template/spec/hostIPC", concat("", [_c, "/securityContext/privileged"])] {
		every bad in [true, "true", "false", 1] {
			_denied(json.patch(good_deployment, [{"op": "add", "path": path, "value": bad}]))
		}
	}
}

test_missing_or_non_string_image_is_denied if {
	path := concat("", [_c, "/image"])
	_denied(json.patch(good_deployment, [{"op": "remove", "path": path}]))
	every bad in [null, 1, true, ""] {
		_denied(json.patch(good_deployment, [{"op": "replace", "path": path, "value": bad}]))
	}
}

# A container without a name is still judged: the finding names it "<unnamed>".
test_unnamed_container_is_still_judged if {
	inp := json.patch(good_deployment, [
		{"op": "remove", "path": concat("", [_c, "/name"])},
		{"op": "replace", "path": concat("", [_c, "/securityContext/privileged"]), "value": true},
	])
	_denied(inp)
	some msg in gate.all_violations with input as inp
	startswith(msg, "SENTINEL-K8S-001: Container '<unnamed>'")
}

test_string_run_as_user_is_denied if {
	inp := json.patch(good_deployment, [{"op": "replace", "path": concat("", [_c, "/securityContext/runAsUser"]), "value": "10001"}])
	_denied(inp)
	some msg in gate.all_violations with input as inp
	startswith(msg, "SENTINEL-K8S-002: Container 'web' sets runAsUser to a string")
}
