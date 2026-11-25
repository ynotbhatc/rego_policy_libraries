# Bad evidence never passes (CIS GCP Foundations): every boolean and number in the all-pass fixture is sent as a
# string, as null and not at all, and the report must not come back compliant. The two tables below are the
# only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package cis_gcp.bad_evidence_test

import rego.v1

_green := data.cis_gcp_foundations_test.good

_report := data.cis_gcp.main.compliance_report

# leaves the module does not read (path pattern: reason): no value of theirs can change the result
_unread := {
	"backend_services/[0-9]+/logConfig/sampleRate": "2.17 reads logConfig.enable only",
	"compute_instances/[0-9]+/shieldedInstanceConfig/enableSecureBoot": "4.8 reads enableVtpm and enableIntegrityMonitoring",
	"sql_instances/[0-9]+/settings/ipConfiguration/ipv4Enabled": "the SQL recommendations read authorizedNetworks, requireSsl and the instance addresses",
}

# leaves that may be left out or null (the module then takes the stricter reading, or the check does not
# depend on them); a value of the wrong type is still a finding. Path pattern: reason.
_optional := {
	"compute_instances/[0-9]+/canIpForward": "the API omits canIpForward when it is off",
	"subnetworks/[0-9]+/(enableFlowLogs|logConfig/enable)": "flow logs are on when either flag is true",
}

_key(p) := concat("/", [sprintf("%v", [x]) | some x in p])

_listed(key, patterns) if {
	some pattern, _ in patterns
	regex.match(sprintf("^%s$", [pattern]), key)
}

_booleans := [p | walk(_green, [p, v]); is_boolean(v); not _listed(_key(p), _unread)]

_numbers := [p | walk(_green, [p, v]); is_number(v); not _listed(_key(p), _unread)]

_passes(inp) if _report.compliant == true with input as inp

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_booleans_5 if {
	sum([count(_slice(_booleans, i, 5)) | some i in numbers.range(0, 4)]) == count(_booleans)
	every i in numbers.range(0, 4) {
		every k, x in _slice(_booleans, i, 5) {
			x == _booleans[i + (k * 5)]
		}
	}
}

test_the_slices_cover_booleans_for_null_or_removed_2 if {
	sum([count(_slice(_booleans, i, 2)) | some i in numbers.range(0, 1)]) == count(_booleans)
	every i in numbers.range(0, 1) {
		every k, x in _slice(_booleans, i, 2) {
			x == _booleans[i + (k * 2)]
		}
	}
}

test_fixture_passes_and_has_leaves if {
	_passes(_green)
	count(_booleans) + count(_numbers) > 0
}

test_empty_and_null_input_fail if {
	not _passes({})
	not _passes(null)
}

test_boolean_of_the_wrong_type_never_passes_slice_0 if {
	every p in _slice(_booleans, 0, 5) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_1 if {
	every p in _slice(_booleans, 1, 5) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_2 if {
	every p in _slice(_booleans, 2, 5) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_3 if {
	every p in _slice(_booleans, 3, 5) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_4 if {
	every p in _slice(_booleans, 4, 5) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_null_or_removed_never_passes_slice_0 if {
	every p in [q | some q in _slice(_booleans, 0, 2); not _listed(_key(q), _optional)] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

test_boolean_null_or_removed_never_passes_slice_1 if {
	every p in [q | some q in _slice(_booleans, 1, 2); not _listed(_key(q), _optional)] {
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

test_string_ip_forwarding_is_not_off if {
	every bad in ["false", "true", 1] {
		inp := json.patch(_green, [{"op": "replace", "path": "/compute_instances/0/canIpForward", "value": bad}])
		r := _report with input as inp
		some msg in r.violations
		contains(msg, "4.6")
	}
}

test_string_flow_sampling_is_not_full_sampling if {
	not _passes(json.patch(_green, [{"op": "replace", "path": "/subnetworks/0/logConfig/flowSampling", "value": "1"}]))
}
