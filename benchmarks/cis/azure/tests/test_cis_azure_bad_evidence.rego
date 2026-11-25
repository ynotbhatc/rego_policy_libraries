# Bad evidence never passes (CIS Azure Foundations v7.0.0): every boolean and number in the all-pass fixture is sent as a
# string, as null and not at all, and the report must not come back compliant. The two sets below are the
# only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package cis_azure.bad_evidence_test

import rego.v1

_green := data.cis_azure.v7_controls_test.green

_report := data.cis_azure.main.compliance_report

# leaves the module does not read: no value of theirs can change the result
_unread := {
	# only retentionPolicy.days is read (7.6, 7.12)
	"flow_logs/0/retentionPolicy/enabled",
	# only retentionPolicy.days is read (7.6, 7.12)
	"flow_logs/1/retentionPolicy/enabled",
}

# leaves that may be left out or null (the module then takes the stricter reading, or the check does not
# depend on them); a value of the wrong type is still a finding
_optional := {
	# 7.6 checks the retention of a virtual network flow log whether or not it is enabled
	"flow_logs/0/enabled",
	# an item without attributes.enabled is treated as enabled and stays in scope
	"key_vaults/0/keys/0/attributes/enabled",
	# an item without attributes.enabled is treated as enabled and stays in scope
	"key_vaults/0/secrets/0/attributes/enabled",
}

_key(p) := concat("/", [sprintf("%v", [x]) | some x in p])

_booleans := [p | walk(_green, [p, v]); is_boolean(v); not _key(p) in _unread]

_numbers := [p | walk(_green, [p, v]); is_number(v); not _key(p) in _unread]

_passes(inp) if _report.compliant == true with input as inp

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_booleans_7 if {
	sum([count(_slice(_booleans, i, 7)) | some i in numbers.range(0, 6)]) == count(_booleans)
	every i in numbers.range(0, 6) {
		every k, x in _slice(_booleans, i, 7) {
			x == _booleans[i + (k * 7)]
		}
	}
}

test_the_slices_cover_booleans_for_null_or_removed_4 if {
	sum([count(_slice(_booleans, i, 4)) | some i in numbers.range(0, 3)]) == count(_booleans)
	every i in numbers.range(0, 3) {
		every k, x in _slice(_booleans, i, 4) {
			x == _booleans[i + (k * 4)]
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
	every p in _slice(_booleans, 0, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_1 if {
	every p in _slice(_booleans, 1, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_2 if {
	every p in _slice(_booleans, 2, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_3 if {
	every p in _slice(_booleans, 3, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_4 if {
	every p in _slice(_booleans, 4, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_5 if {
	every p in _slice(_booleans, 5, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_6 if {
	every p in _slice(_booleans, 6, 7) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_null_or_removed_never_passes_slice_0 if {
	every p in [q | some q in _slice(_booleans, 0, 4); not _key(q) in _optional] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

test_boolean_null_or_removed_never_passes_slice_1 if {
	every p in [q | some q in _slice(_booleans, 1, 4); not _key(q) in _optional] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

test_boolean_null_or_removed_never_passes_slice_2 if {
	every p in [q | some q in _slice(_booleans, 2, 4); not _key(q) in _optional] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

test_boolean_null_or_removed_never_passes_slice_3 if {
	every p in [q | some q in _slice(_booleans, 3, 4); not _key(q) in _optional] {
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
	every p in [q | some q in _numbers; not _key(q) in _optional] {
		not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": null}]))
		not _passes(json.patch(_green, [{"op": "remove", "path": p}]))
	}
}

# The exception lists stay honest: a listed leaf must exist in the fixture.
test_exception_lists_name_real_leaves if {
	keys := {_key(p) | walk(_green, [p, v]); not is_object(v); not is_array(v)}
	every k in _unread | _optional {
		k in keys
	}
}

# The finding names the property and the type that was sent.
test_string_boolean_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/application_gateways/0/enableHttp2", "value": "true"}])
	r := _report with input as inp
	some msg in r.violations
	startswith(msg, "7.2.1: ")
	contains(msg, "evidence invalid — enableHttp2 must be true or false, got string")
	r.evidence_invalid_count == 1
}

test_string_false_does_not_turn_a_setting_off if {
	inp := json.patch(_green, [{"op": "replace", "path": "/storage_accounts/0/allowBlobPublicAccess", "value": "false"}])
	r := _report with input as inp
	some msg in r.violations
	startswith(msg, "9.2.5: ")
}

test_string_priority_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/network_security_groups/0/securityRules/0/priority", "value": "100"}])
	r := _report with input as inp
	some msg in r.violations
	startswith(msg, "7.8: ")
	contains(msg, "has no numeric priority")
}

# Defender plan extensions are strings in the Azure API ("True" / "False"): they stay accepted.
test_api_string_settings_still_pass if {
	some x in _green.defender_pricings
	some e in x.extensions
	e.isEnabled == "True"
	_passes(_green)
}

# input.cis_profile.level is the number 1 or 2. A string (the strings "1" and "level1" included), null or another
# number never selects a profile: the report is scoped at Level 2 and every Level 2 recommendation says so.
test_level_of_another_type_is_invalid_evidence if {
	every bad in ["1", "2", "level1", "Level 1", null, 3, true] {
		r := _report with input as object.union(_green, {"cis_profile": {"level": bad}})
		full := _report with input as object.union(_green, {"cis_profile": {"level": 2}})
		r.compliant == false
		r.total_controls == full.total_controls
		every id in {i | some i, rec in data.cis_azure.recommendations; rec.level == 2} {
			some v in r.violations
			startswith(v, sprintf("%s: ", [id]))
			endswith(v, sprintf("evidence invalid — input.cis_profile.level must be the number 1 or 2, got %s, so this Level 2 recommendation could not be scoped", [json.marshal(bad)]))
		}
	}
	every bad in ["1", null, []] {
		r := _report with input as object.union(_green, {"cis_profile": bad})
		r.compliant == false
	}
}

test_level_number_selects_the_profile if {
	l1 := _report with input as object.union(_green, {"cis_profile": {"level": 1}})
	l2 := _report with input as object.union(_green, {"cis_profile": {"level": 2}})
	none := _report with input as object.remove(_green, ["cis_profile"])
	l1.compliant == true
	l2.compliant == true
	none.compliant == true
	l1.total_controls < l2.total_controls
	none.total_controls == l2.total_controls
}

# A boolean read inside a searched list item (an activity log alert, the WDATP Defender setting, the default
# security contact) that arrives as another type fails its recommendation, and the finding names the fact and
# the type that was sent, like every other boolean read.
test_nested_boolean_of_the_wrong_type_is_named if {
	cases := [
		["/activity_log_alerts/0/enabled", "evidence invalid — activity log alert alert-0: enabled must be true or false, got %s"],
		[sprintf("/activity_log_alerts/%d/enabled", [count(_green.activity_log_alerts) - 1]), "evidence invalid — activity log alert alert-service-health: enabled must be true or false, got %s"],
		["/defender_settings/0/enabled", "evidence invalid — Defender setting WDATP: enabled must be true or false, got %s"],
		["/security_contacts/0/isEnabled", "evidence invalid — the default security contact's isEnabled must be true or false, got %s"],
	]
	every c in cases {
		every bad in ["true", "false", 1] {
			r := _report with input as json.patch(_green, [{"op": "replace", "path": c[0], "value": bad}])
			r.compliant == false
			want := sprintf(c[1], [type_name(bad)])
			named := [v | some v in r.violations; endswith(v, want)]
			count(named) == 1
			r.evidence_invalid_count >= 1
		}
	}
}

# One alert with a bad `enabled` fails the recommendation that alert serves, not the other sixteen.
test_bad_alert_fails_only_its_own_recommendation if {
	r := _report with input as json.patch(_green, [{"op": "replace", "path": "/activity_log_alerts/0/enabled", "value": "true"}])
	count({split(v, ":")[0] | some v in r.violations}) == 1
}
