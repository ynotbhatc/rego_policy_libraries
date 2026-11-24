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
