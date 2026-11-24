# Bad evidence never passes (DISA STIG OpenShift 4): every boolean and number in the all-pass fixture is sent as a
# string, as null and not at all, and the report must not come back compliant. The two tables below are the
# only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package stig.openshift_4.bad_evidence_test

import rego.v1

_green := data.stig.openshift_4.core_rules_test.green_fixture

_report := data.stig.openshift_4.main.compliance_report

# leaves the module does not read (path pattern: reason): no value of theirs can change the result
_unread := {}

# leaves that may be left out or null (the module then takes the stricter reading, or the check does not
# depend on them); a value of the wrong type is still a finding. Path pattern: reason.
_optional := {
	"openshift/image_config/spec/allowedRegistriesForImport/[0-9]+/insecure": "the API omits insecure when it is false",
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

# CNTR-OS-000660: the six allow* fields are required fields of the SCC API object. An SCC collected without
# one of them (or with null) is not cleared, whatever its other fields say.
test_scc_without_a_required_allow_field_never_passes if {
	every i in [0, 1] {
		every field in ["allowHostDirVolumePlugin", "allowHostIPC", "allowHostNetwork", "allowHostPID", "allowHostPorts", "allowPrivilegedContainer"] {
			path := sprintf("/scc/items/%d/%s", [i, field])
			not _passes(json.patch(_green, [{"op": "remove", "path": path}]))
			not _passes(json.patch(_green, [{"op": "replace", "path": path, "value": null}]))
		}
	}
}

# CNTR-OS-001010 reads what `systemctl is-enabled` / `is-active` print. A word systemctl never prints is not
# an answer: "false", "no", "true" and "" used to pass as "not enabled".
test_sshd_state_that_systemctl_never_prints_never_passes if {
	every field in ["sshd_enabled", "sshd_active"] {
		every bad in ["false", "true", "no", "", "0", null, false, 0] {
			not _passes(json.patch(_green, [{"op": "replace", "path": sprintf("/rhcos/nodes/0/%s", [field]), "value": bad}]))
		}
	}
	every ok in ["disabled", "masked", "static", "Disabled"] {
		_passes(json.patch(_green, [{"op": "replace", "path": "/rhcos/nodes/0/sshd_enabled", "value": ok}]))
	}
	every ok in ["inactive", "failed"] {
		_passes(json.patch(_green, [{"op": "replace", "path": "/rhcos/nodes/0/sshd_active", "value": ok}]))
	}
}
