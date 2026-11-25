# Bad evidence never passes (CIS AWS Foundations v7.0.0): every boolean and number in the all-pass fixture is sent as a
# string, as null and not at all, and the report must not come back compliant. The two sets below are the
# only exceptions, each with its reason; a new leaf in the fixture is covered without editing this file.

package cis_aws.bad_evidence_test

import rego.v1

_green := data.cis_aws.v7_controls_test.green

_report := data.cis_aws.main.compliance_report

# leaves the module does not read: no value of theirs can change the result
_unread := set()

# leaves that may be left out or null (the module then takes the stricter reading, or the check does not
# depend on them); a value of the wrong type is still a finding
_optional := {
	# 2.5 is met by AccountMFAEnabled == 1 alone
	"account_summary/AccountPasswordPresent",
	# a modality that is not in use need not be logged (7.4.2)
	"bedrock_invocation_logging/0/loggingConfig/embeddingDataDeliveryEnabled",
	# a modality that is not in use need not be logged (7.4.2)
	"bedrock_invocation_logging/0/loggingConfig/imageDataDeliveryEnabled",
	# a modality that is not in use need not be logged (7.4.2)
	"bedrock_invocation_logging/0/loggingConfig/videoDataDeliveryEnabled",
	# a policy without an AttachmentCount is treated as attached and is checked (2.14)
	"iam_policies/0/AttachmentCount",
	# EC2 omits Main on an explicit subnet association
	"route_tables/0/Associations/0/Main",
}

_key(p) := concat("/", [sprintf("%v", [x]) | some x in p])

_booleans := [p | walk(_green, [p, v]); is_boolean(v); not _key(p) in _unread]

_numbers := [p | walk(_green, [p, v]); is_number(v); not _key(p) in _unread]

_passes(inp) if _report.compliant == true with input as inp

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_booleans_4 if {
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
	every p in _slice(_booleans, 0, 4) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_1 if {
	every p in _slice(_booleans, 1, 4) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_2 if {
	every p in _slice(_booleans, 2, 4) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_of_the_wrong_type_never_passes_slice_3 if {
	every p in _slice(_booleans, 3, 4) {
		every bad in ["true", "false", "no", "yes", 0, 1] {
			not _passes(json.patch(_green, [{"op": "replace", "path": p, "value": bad}]))
		}
	}
}

test_boolean_null_or_removed_never_passes if {
	every p in [q | some q in _booleans; not _key(q) in _optional] {
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

# The finding names the fact and the type that was sent.
test_string_boolean_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/rds_instances/0/StorageEncrypted", "value": "true"}])
	r := _report with input as inp
	some msg in r.violations
	startswith(msg, "3.2.1: ")
	contains(msg, "evidence invalid — input.rds_instances[0].StorageEncrypted must be a boolean, got string")
	r.evidence_invalid_count == 1
}

test_string_number_is_named if {
	inp := json.patch(_green, [{"op": "replace", "path": "/password_policy/MinimumPasswordLength", "value": "14"}])
	r := _report with input as inp
	some msg in r.violations
	startswith(msg, "2.8: ")
	contains(msg, "evidence invalid — input.password_policy.MinimumPasswordLength must be a number, got string")
}

# The credential report is CSV: its "true" / "false" strings are the API's own type and stay accepted.
test_credential_report_strings_still_pass if {
	inp := json.patch(_green, [{"op": "replace", "path": "/credential_report/0/mfa_active", "value": "true"}])
	_passes(inp)
}

# input.cis_profile.level is the number 1 or 2. A string (the strings "1" and "level1" included), null or another
# number never selects a profile: the report is scoped at Level 2 and every Level 2 recommendation says so.
test_level_of_another_type_is_invalid_evidence if {
	every bad in ["1", "2", "level1", "Level 1", null, 3, true] {
		r := _report with input as object.union(_green, {"cis_profile": {"level": bad}})
		full := _report with input as object.union(_green, {"cis_profile": {"level": 2}})
		r.compliant == false
		r.total_controls == full.total_controls
		every id in {i | some i, rec in data.cis_aws.recommendations; rec.level == 2} {
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

# 7.1.6: a key status is Active, Inactive or Expired. Another word ("false", "true", "no") is not read as "not
# active": it used to take the key out of the rotation check.
test_unknown_api_key_status_fails_7_1_6 if {
	every bad in ["false", "true", "no", "enabled"] {
		inp := json.patch(_green, [{"op": "add", "path": "/bedrock_api_keys/0/Status", "value": bad}])
		r := _report with input as inp
		r.compliant == false
		some v in r.violations
		startswith(v, "7.1.6: ")
		contains(v, "is not Active, Inactive or Expired")
	}
	every ok in ["Inactive", "Expired"] {
		_passes(json.patch(_green, [{"op": "add", "path": "/bedrock_api_keys/0/Status", "value": ok}]))
	}
}

# 2.14: only AttachmentCount == 0 takes a policy out of scope. A null count used to (null > 0 is false in Rego),
# so an administrative policy collected without its count was cleared.
test_admin_policy_without_a_numeric_attachment_count_fails_2_14 if {
	admin := {"op": "add", "path": "/iam_policies/0/DefaultVersionDocument/Statement/-", "value": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
	every count_patch in [{"op": "add", "path": "/iam_policies/0/AttachmentCount", "value": null}, {"op": "add", "path": "/iam_policies/0/AttachmentCount", "value": "0"}, {"op": "add", "path": "/iam_policies/0/AttachmentCount", "value": 3}] {
		r := _report with input as json.patch(_green, [admin, count_patch])
		some v in r.violations
		startswith(v, "2.14: ")
		contains(v, "has an Allow statement with Action * on Resource *")
	}
	unattached := _report with input as json.patch(_green, [admin, {"op": "add", "path": "/iam_policies/0/AttachmentCount", "value": 0}])
	count([v | some v in unattached.violations; startswith(v, "2.14: ")]) == 0
}
