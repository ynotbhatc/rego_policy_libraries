# A malformed manifest never passes: a switch that must stay off is off only as the boolean false (or
# unset), a required true is only the boolean true, runAsUser is a number, and metadata must be present.

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

test_metadata_missing_or_null_fails if {
	not _passes(json.patch(restricted_pod, [{"op": "remove", "path": "/pod/metadata"}]))
	not _passes(json.patch(restricted_pod, [{"op": "replace", "path": "/pod/metadata", "value": null}]))
	not _passes(json.patch(restricted_pod, [{"op": "replace", "path": "/pod/metadata", "value": "web"}]))
}

test_apparmor_annotation_unconfined_fails_baseline if {
	key := "container.apparmor.security.beta.kubernetes.io/app"
	not _baseline_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "unconfined"}}]))
	_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "runtime/default"}}]))
	_passes(json.patch(restricted_pod, [{"op": "add", "path": "/pod/metadata/annotations", "value": {key: "localhost/profile-a"}}]))
}
