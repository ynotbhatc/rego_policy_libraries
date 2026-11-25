# Bad evidence never passes (CIS Amazon EKS v2.0.0): every boolean and number in the all-pass fixture is sent as a
# string, as null and not at all, and the report must not come back compliant. The two tables below are the
# only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package cis_eks.bad_evidence_test

import rego.v1

_green := data.cis_eks.main_test.compliant_input

_report := data.cis_eks.main.compliance_report

# leaves the module does not read (path pattern: reason): no value of theirs can change the result
_unread := {}

# leaves that may be left out or null (the module then takes the stricter reading, or the check does not
# depend on them); a value of the wrong type is still a finding. Path pattern: reason.
_optional := {
	"cis_eks/ecr/repository_scanning_configurations/[0-9]+/scanOnPush": "5.1.1 is also met by scanFrequency or by the third-party scanning attestation",
	"cis_eks/nodes/[0-9]+/(kubeconfig_file|kubelet_config_file)/exists": "a file entry without exists is a present file and its mode and owner are checked",
	"cis_eks/nodes/[0-9]+/configz/kubeletconfig/readOnlyPort": "the kubelet default is 0",
	"cis_eks/service_accounts/[0-9]+/automountServiceAccountToken": "Kubernetes omits the field when unset; the token then mounts and 4.1.6 decides on the allow list",
	"cis_eks/workloads/.*/(automountServiceAccountToken|allowPrivilegeEscalation|privileged|hostNetwork)": "Kubernetes omits unset pod fields; each control applies the Kubernetes default",
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
	every j, x in _booleans {
		x in _slice(_booleans, j % 5, 5)
	}
}

test_the_slices_cover_booleans_for_null_or_removed_2 if {
	sum([count(_slice(_booleans, i, 2)) | some i in numbers.range(0, 1)]) == count(_booleans)
	every j, x in _booleans {
		x in _slice(_booleans, j % 2, 2)
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

test_string_privileged_is_invalid_evidence_for_4_2_1 if {
	inp := json.patch(_green, [{"op": "replace", "path": "/cis_eks/workloads/3/spec/containers/0/securityContext/privileged", "value": "true"}])
	r := _report with input as inp
	"CIS EKS 4.2.1: evidence invalid — workloads[3].spec.containers[0].securityContext.privileged is not a boolean (got string)" in r.violations
}

# One message per control: invalid evidence replaces the finding, it does not add to it.
test_invalid_evidence_is_one_message_per_control if {
	inp := json.patch(_green, [{"op": "replace", "path": "/cis_eks/workloads/3/spec/hostNetwork", "value": "false"}])
	r := _report with input as inp
	count([v | some v in r.violations; startswith(v, "CIS EKS 4.2.4:")]) == 1
	count(r.violations) == 1
}

test_empty_input_still_yields_one_message_per_control if {
	r := _report with input as {}
	r.failed_controls == 47
	every id, _ in data.cis_eks.main.requires {
		count([v | some v in r.violations; startswith(v, sprintf("CIS EKS %s:", [id]))]) == 1
	}
}
