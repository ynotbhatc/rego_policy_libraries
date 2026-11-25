# A malformed manifest never passes: a switch that must stay off is off only as the boolean false (or
# unset), a required true is only the boolean true, runAsUser is a number, and containers must be readable.

package k8s_pss.bad_manifest_test

import rego.v1

import data.k8s_pss.main
import data.k8s_pss.main_test.restricted_pod

_passes(inp) if main.compliance_report.compliant == true with input as inp

_baseline_passes(inp) if main.compliance_report.baseline_compliant == true with input as inp

# switches that must stay off: [path under /pod, ...]
_off_switches := [
	"/pod/spec/hostNetwork",
	"/pod/spec/hostPID",
	"/pod/spec/hostIPC",
	"/pod/spec/containers/0/securityContext/privileged",
]

_not_off := [true, "true", "false", "no", 1, 0]

test_fixture_passes if _passes(restricted_pod)

test_empty_and_null_input_fail if {
	not _passes({})
	not _passes({"pod": null})
	not _passes({"pod": {"spec": null}})
}

test_switch_that_is_not_the_boolean_false_fails_baseline if {
	every path in _off_switches {
		every bad in _not_off {
			inp := json.patch(restricted_pod, [{"op": "add", "path": path, "value": bad}])
			not _baseline_passes(inp)
			not _passes(inp)
		}
	}
}

test_switch_explicitly_false_or_null_is_off if {
	every path in _off_switches {
		_passes(json.patch(restricted_pod, [{"op": "add", "path": path, "value": false}]))
		_passes(json.patch(restricted_pod, [{"op": "add", "path": path, "value": null}]))
	}
}

test_host_process_string_fails if {
	every bad in ["true", "false", 1] {
		not _baseline_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/spec/securityContext/windowsOptions", "value": {"hostProcess": bad}}]))
	}
}

# Every boolean and number in the restricted fixture, sent as a string, null or not at all.
_leaves := [[p, v] |
	walk(restricted_pod, [p, v])
	not is_object(v)
	not is_array(v)
	not is_string(v)
	p[count(p) - 1] != "containerPort" # not a PSS field: only hostPort is restricted
]

test_fixture_leaf_of_the_wrong_type_fails if {
	count(_leaves) > 0
	every leaf in _leaves {
		[p, v] := leaf
		every bad in [sprintf("%v", [v]), "x", null] {
			not _passes(json.patch(restricted_pod, [{"op": "replace", "path": p, "value": bad}]))
		}
		not _passes(json.patch(restricted_pod, [{"op": "remove", "path": p}]))
	}
}

test_run_as_user_string_zero_is_not_nonroot if {
	inp := json.patch(restricted_pod, [{"op": "add", "path": "/pod/spec/securityContext/runAsUser", "value": "0"}])
	not _passes(inp)
}

# The Pod Security Standards restrict the AppArmor annotations when they are set; they do not require a
# pod to carry metadata. Absent or null metadata / annotations is the allowed "undefined". Metadata or
# annotations of another type cannot be read, so the Baseline AppArmor control is not cleared.
test_metadata_or_annotations_absent_is_allowed if {
	_passes(json.patch(restricted_pod, [{"op": "remove", "path": "/pod/metadata"}]))
	_passes(json.patch(restricted_pod, [{"op": "replace", "path": "/pod/metadata", "value": null}]))
	_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": null}]))
	_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {}}]))
}

test_unreadable_metadata_or_annotations_fails_baseline_apparmor if {
	every bad in ["web", 1, true, ["a"]] {
		every path in ["/pod/metadata", "/pod/metadata/annotations"] {
			inp := json.patch(restricted_pod, [{"op": "add", "path": path, "value": bad}])
			not _baseline_passes(inp)
			not _passes(inp)
			"PSS baseline (apparmor): input.pod.metadata or its annotations is not an object — the AppArmor annotations cannot be evaluated" in main.baseline_violations with input as inp
		}
	}
}

# A manifest whose containers cannot be read is not cleared on the per-container controls.
test_unreadable_containers_fail if {
	every bad in [null, "true", 1, [], ["app"], [null], {"name": "app"}] {
		inp := json.patch(restricted_pod, [{"op": "replace", "path": "/pod/spec/containers", "value": bad}])
		not _baseline_passes(inp)
		not _passes(inp)
	}
	not _passes(json.patch(restricted_pod, [{"op": "remove", "path": "/pod/spec/containers"}]))
	every field in ["initContainers", "ephemeralContainers"] {
		every bad in ["true", 1, ["app"], {"name": "app"}] {
			not _baseline_passes(json.patch(restricted_pod, [{"op": "add", "path": concat("/", ["/pod/spec", field]), "value": bad}]))
		}
		every ok in [null, []] {
			_passes(json.patch(restricted_pod, [{"op": "add", "path": concat("/", ["/pod/spec", field]), "value": ok}]))
		}
	}
}

# The annotation form belongs to the Baseline profile: it fails a pod judged at baseline too.
test_apparmor_annotation_is_a_baseline_control if {
	key := "container.apparmor.security.beta.kubernetes.io/app"
	inp := object.union(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "unconfined"}}]), {"pss_profile": "baseline"})
	main.compliance_report.compliant == false with input as inp
	main.compliance_report.total_controls == 18 with input as inp
	some v in main.compliance_report.violations with input as inp
	startswith(v, "PSS baseline (apparmor): annotation")
}

test_apparmor_annotation_unconfined_fails_baseline if {
	key := "container.apparmor.security.beta.kubernetes.io/app"
	not _baseline_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "unconfined"}}]))
	_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "runtime/default"}}]))
	_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "localhost/profile-a"}}]))
}

# A securityContext that is not an object cannot be read: at baseline it used to pass, because every rule
# that reads it went undefined.
test_unreadable_security_context_fails_baseline if {
	every path in ["/pod/spec/securityContext", "/pod/spec/containers/0/securityContext"] {
		every bad in ["restricted", 1, true, ["a"]] {
			inp := object.union(json.patch(restricted_pod, [{"op": "replace", "path": path, "value": bad}]), {"pss_profile": "baseline"})
			main.compliance_report.compliant == false with input as inp
			not _baseline_passes(inp)
		}
	}
}
