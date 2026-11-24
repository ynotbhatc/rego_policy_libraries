# Bad evidence never passes (CIS OpenShift v2.0.0): every boolean and number in the all-pass fixture is sent as a
# string, as null and not at all, and the report must not come back compliant. The two tables below are the
# only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package cis_openshift.bad_evidence_test

import rego.v1

_green := data.cis_openshift_4_test.green

_report := data.cis_openshift.main.compliance_report

# leaves the module does not read (path pattern: reason): no value of theirs can change the result
_unread := {
	"kubelet/nodes/[0-9]+/config/authentication/webhook/enabled": "no recommendation reads it (4.2.2 reads authentication.anonymous.enabled)",
	"kubelet/nodes/[0-9]+/config/kubeAPIQPS": "4.2.8 is a manual review, decided by attest.kubelet_kube_api_qps_reviewed",
	"openshift/kube_(controller_manager|scheduler)_pod/spec/containers/0/(liveness|readiness)Probe/httpGet/port": "only the probe path is read (1.3.x, 1.4.x)",
}

# leaves that may be left out or null (the module then takes the stricter reading, or the check does not
# depend on them); a value of the wrong type is still a finding. Path pattern: reason.
_optional := {
	"openshift/kube_apiserver_endpoint_ports/[0-9]+": "removing one of several endpoint ports leaves a valid list",
	"scc/items/[0-9]+/allow[A-Za-z]+": "5.2.x need one SCC that refuses; the others may omit the field",
}

_key(p) := concat("/", [sprintf("%v", [x]) | some x in p])

_listed(key, patterns) if {
	some pattern, _ in patterns
	regex.match(sprintf("^%s$", [pattern]), key)
}

_booleans := [p | walk(_green, [p, v]); is_boolean(v); not _listed(_key(p), _unread)]

_numbers := [p | walk(_green, [p, v]); is_number(v); not _listed(_key(p), _unread)]

_passes(inp) if _report.compliant == true with input as inp

test_fixture_passes_and_has_leaves if {
	_passes(_green)
	count(_booleans) + count(_numbers) > 0
}

test_empty_and_null_input_fail if {
	not _passes({})
	not _passes(null)
}

test_boolean_of_the_wrong_type_never_passes if {
	every p in _booleans {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_null_or_removed_never_passes if {
	every p in [q | some q in _booleans; not _listed(_key(q), _optional)] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

test_number_as_string_never_passes if {
	every p in _numbers {
		v := json.patch(_green, [{"op": "replace", "path": p, "value": "x"}])
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": sprintf("%v", [object.get(_green, p, 0)])}]))
		not _passes(v)
	}
}

test_number_null_or_removed_never_passes if {
	every p in [q | some q in _numbers; not _listed(_key(q), _optional)] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

# The exception lists stay honest: a listed pattern must match a leaf of the fixture.
test_exception_lists_name_real_leaves if {
	keys := {_key(p) | walk(_green, [p, v]); not is_object(v); not is_array(v)}
	every pattern, _ in object.union(_unread, _optional) {
		some k in keys
		regex.match(sprintf("^%s$", [pattern]), k)
	}
}

test_scc_string_boolean_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/scc/items/0/allowHostPID", "value": "false"}])
	r := _report with input as inp
	"5.2.2: evidence invalid — SCC privileged: allowHostPID must be true or false, got string" in r.violations
}

test_string_port_is_not_a_port if {
	inp := json.patch(_green, [{"op": "replace", "path": "/openshift/kube_apiserver_endpoint_ports/0", "value": "6443"}])
	r := _report with input as inp
	some msg in r.violations
	startswith(msg, "1.2.14: ")
}
