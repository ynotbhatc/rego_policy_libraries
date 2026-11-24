# A review this policy cannot read is denied, and a value of the wrong type never clears a finding:
# only the boolean false (or unset) is "off", a null label / limit / service account is not set, and a
# container without a name is still judged.

package kubernetes.admission_malformed_test

import rego.v1

import data.kubernetes.admission as adm

# a Deployment the policy admits, carrying only what the policy requires
good_review := {"request": {
	"operation": "CREATE",
	"namespace": "prod",
	"kind": {"kind": "Deployment"},
	"object": {
		"metadata": {"name": "web", "labels": {"app": "web", "version": "1.4.2", "team": "shop"}},
		"spec": {"template": {
			"metadata": {"labels": {"app": "web", "version": "1.4.2", "team": "shop"}},
			"spec": {
				"serviceAccountName": "web",
				"automountServiceAccountToken": false,
				"containers": [{
					"name": "web",
					"image": "quay.io/shop/web:1.4.2",
					"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}},
					"securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true, "capabilities": {"drop": ["ALL"]}},
					"livenessProbe": {"httpGet": {"path": "/healthz"}},
					"readinessProbe": {"httpGet": {"path": "/ready"}},
				}],
			},
		}},
	},
}}

_o := "/request/object"

_s := "/request/object/spec/template/spec"

_c := "/request/object/spec/template/spec/containers/0"

_allowed(inp) if {
	adm.allow with input as inp
	adm.compliance_report.compliant == true with input as inp
}

_denied(inp) if {
	not adm.allow with input as inp
	adm.compliance_report.compliant == false with input as inp
	adm.compliance_report.violation_count > 0 with input as inp
}

_denied_with(inp, needle) if {
	_denied(inp)
	some v in adm.violations with input as inp
	contains(v, needle)
}

_set(path, value) := json.patch(good_review, [{"op": "add", "path": path, "value": value}])

test_good_review_is_allowed if _allowed(good_review)

test_workload_without_readable_containers_is_denied if {
	every path in ["/request/object/spec", "/request/object/spec/template", _s, concat("", [_s, "/containers"]), _c] {
		every bad in [null, "true", 1, false] {
			_denied_with(_set(path, bad), "request cannot be evaluated")
		}
	}
	_denied_with(_set(concat("", [_s, "/containers"]), []), "request cannot be evaluated")
	_denied_with(json.patch(good_review, [{"op": "remove", "path": concat("", [_s, "/containers"])}]), "request cannot be evaluated")
	every field in ["initContainers", "ephemeralContainers"] {
		every bad in ["true", 1, ["x"], {"a": 1}] {
			_denied_with(_set(concat("/", [_s, field]), bad), "request cannot be evaluated")
		}
	}
}

test_unset_or_null_optional_container_lists_are_allowed if {
	every field in ["initContainers", "ephemeralContainers"] {
		every ok in [null, []] {
			_allowed(_set(concat("/", [_s, field]), ok))
		}
	}
}

# the switches that must stay off: off only as false, null or unset
test_off_switch_of_another_type_is_denied if {
	every path in [concat("", [_s, "/hostNetwork"]), concat("", [_s, "/hostPID"]), concat("", [_s, "/hostIPC"]), concat("", [_c, "/securityContext/privileged"])] {
		every bad in [true, "true", "false", "no", 1, 0] {
			_denied_with(_set(path, bad), "Security:")
		}
		every ok in [false, null] {
			_allowed(_set(path, ok))
		}
	}
}

# the settings that must be stated: any other type, null and removal are each denied
_required := {
	concat("", [_c, "/securityContext/allowPrivilegeEscalation"]): "allows privilege escalation",
	concat("", [_c, "/securityContext/readOnlyRootFilesystem"]): "readOnlyRootFilesystem",
	concat("", [_c, "/securityContext/runAsNonRoot"]): "runs as root",
	concat("", [_s, "/automountServiceAccountToken"]): "auto-mounts service account token",
}

test_required_setting_of_another_type_is_denied if {
	every path, needle in _required {
		every bad in ["true", "false", "no", null, 0, 1] {
			_denied_with(_set(path, bad), needle)
		}
	}
}

test_run_as_non_root_removed_is_denied if {
	_denied_with(json.patch(good_review, [{"op": "remove", "path": concat("", [_c, "/securityContext/runAsNonRoot"])}]), "runs as root")
}

test_null_or_empty_label_is_a_missing_label if {
	every base in [concat("", [_o, "/metadata/labels"]), concat("", [_o, "/spec/template/metadata/labels"])] {
		every label in adm.required_workload_labels {
			every bad in [null, false, "", 1] {
				_denied_with(_set(concat("/", [base, label]), bad), "Labels:")
			}
			_denied_with(json.patch(good_review, [{"op": "remove", "path": concat("/", [base, label])}]), "Labels:")
		}
	}
}

test_null_or_empty_quantity_is_no_limit if {
	every path in ["/resources/limits/cpu", "/resources/limits/memory", "/resources/requests/cpu", "/resources/requests/memory"] {
		every bad in [null, false, "", true] {
			_denied_with(_set(concat("", [_c, path]), bad), "Resources:")
		}
		_denied_with(json.patch(good_review, [{"op": "remove", "path": concat("", [_c, path])}]), "Resources:")
	}
	_allowed(_set(concat("", [_c, "/resources/limits/cpu"]), 2))
}

test_missing_or_non_string_image_is_denied if {
	path := concat("", [_c, "/image"])
	_denied_with(json.patch(good_review, [{"op": "remove", "path": path}]), "Registry:")
	every bad in [null, 1, true, ""] {
		_denied_with(_set(path, bad), "Registry:")
		_denied_with(_set(path, bad), "ImageTag:")
	}
}

test_service_account_null_or_empty_is_the_default_account if {
	every bad in [null, "", false, 1] {
		_denied_with(_set(concat("", [_s, "/serviceAccountName"]), bad), "ServiceAccount:")
	}
}

test_probe_that_is_not_an_object_is_no_probe if {
	every probe in ["livenessProbe", "readinessProbe"] {
		every bad in [null, "true", true, 1] {
			_denied_with(_set(concat("/", [_c, probe]), bad), "Probes:")
		}
	}
}

# A container without a name is still judged: the finding names it "<unnamed>" (the name was a sprintf
# argument, so every finding on an unnamed container used to vanish).
test_unnamed_container_is_still_judged if {
	inp := json.patch(good_review, [
		{"op": "remove", "path": concat("", [_c, "/name"])},
		{"op": "add", "path": concat("", [_c, "/securityContext/privileged"]), "value": true},
		{"op": "remove", "path": concat("", [_c, "/resources"])},
	])
	_denied_with(inp, "Security: Container '<unnamed>' in Deployment 'web' is privileged")
	_denied_with(inp, "Resources: Container '<unnamed>'")
}

test_unreadable_registry_policy_approves_nothing if {
	every bad in [null, "quay.io", 1, [null], ["quay.io", 1]] {
		inp := object.union(good_review, {"policy": {"approved_registries": bad}})
		_denied_with(inp, "policy.approved_registries must be a list")
		_denied_with(inp, "Registry: Container 'web'")
	}
	_allowed(object.union(good_review, {"policy": {"approved_registries": ["quay.io"]}}))
	_denied_with(object.union(good_review, {"policy": {"approved_registries": ["ghcr.io"]}}), "Registry: Container 'web'")
}

test_service_selector_and_ingress_class_null_are_not_set if {
	svc := {"request": {"operation": "CREATE", "namespace": "prod", "kind": {"kind": "Service"}, "object": {"metadata": {"name": "s"}, "spec": {"type": "ClusterIP", "selector": {"app": "web"}}}}}
	_allowed(svc)
	every bad in [null, {}, "", "app=web"] {
		_denied_with(json.patch(svc, [{"op": "replace", "path": "/request/object/spec/selector", "value": bad}]), "has no selector")
	}
	ing := {"request": {"operation": "CREATE", "namespace": "prod", "kind": {"kind": "Ingress"}, "object": {"metadata": {"name": "i"}, "spec": {"tls": [{"hosts": ["a"]}], "ingressClassName": "nginx"}}}}
	_allowed(ing)
	every bad in [null, "", false] {
		_denied_with(json.patch(ing, [{"op": "replace", "path": "/request/object/spec/ingressClassName", "value": bad}]), "ingressClassName")
	}
	every bad in [null, "true", 1, {}] {
		_denied_with(json.patch(ing, [{"op": "replace", "path": "/request/object/spec/tls", "value": bad}]), "no TLS configuration")
	}
}
