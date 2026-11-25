# Bad evidence never passes: every boolean and number in the all-pass tenancy, sent as a string, null or
# not at all, and every list sent as null or not at all, leaves the tenancy non-compliant with a finding
# that names the fact.

package cis_oci.bad_evidence_test

import rego.v1

import data.cis_oci.main
import data.cis_oci.main_test.green

_bool_paths := [p | walk(green, [p, v]); is_boolean(v)]

_num_paths := [p | walk(green, [p, v]); is_number(v)]

_list_paths := [p | walk(green, [p, v]); is_array(v); count(p) in {2, 3}; p[0] == "oci"]

_dotted(p) := concat(".", [sprintf("%v", [x]) | some x in p])

test_fixture_has_the_leaves_this_test_walks if {
	count(_bool_paths) == 19
	count(_num_paths) == 10
	count(_list_paths) == 20
}

test_boolean_as_string_or_null_fails_and_is_named if {
	every p in _bool_paths {
		every bad in ["true", "false", "no", 0, 1, null] {
			r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": p, "value": bad}])
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_boolean_as_string_is_reported_with_its_type if {
	# cloud_guard is an object, not a list item: 4.14 fails without a type line
	every p in [q | some q in _bool_paths; q[1] != "cloud_guard"] {
		r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": p, "value": "true"}])
		some msg in r.violations
		contains(msg, sprintf("%v is not a boolean (got string)", [p[count(p) - 1]]))
	}
}

test_boolean_removed_fails if {
	every p in _bool_paths {
		r := main.compliance_report with input as json.patch(green, [{"op": "remove", "path": p}])
		r.compliant == false
	}
}

test_number_as_string_or_null_fails if {
	every p in _num_paths {
		every bad in ["1", "0", "365", "not-a-number", true] {
			r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": p, "value": bad}])
			r.compliant == false
		}
	}
}

# A port bound may be left out (the rule then covers every port); every other number is required.
test_number_null_or_removed_fails if {
	every p in [q | some q in _num_paths; not q[count(q) - 1] in {"port_min", "port_max"}] {
		r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": p, "value": null}])
		r.compliant == false
		s := main.compliance_report with input as json.patch(green, [{"op": "remove", "path": p}])
		s.compliant == false
	}
}

test_list_null_or_removed_is_missing_evidence if {
	every p in _list_paths {
		name := _dotted(p)
		r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": p, "value": null}])
		r.compliant == false
		some msg in r.violations
		contains(msg, sprintf("evidence missing: %s not collected", [name]))
		s := main.compliance_report with input as json.patch(green, [{"op": "remove", "path": p}])
		s.compliant == false
		some msg2 in s.violations
		contains(msg2, sprintf("evidence missing: %s not collected", [name]))
	}
}

test_list_of_the_wrong_type_is_named if {
	every p in _list_paths {
		r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": p, "value": "none"}])
		r.compliant == false
		some msg in r.violations
		contains(msg, sprintf("%s is not a list (got string)", [_dotted(p)]))
	}
}

test_section_null_or_removed_fails if {
	every section, _ in green.oci {
		r := main.compliance_report with input as json.patch(green, [{"op": "replace", "path": ["oci", section], "value": null}])
		r.compliant == false
		s := main.compliance_report with input as json.patch(green, [{"op": "remove", "path": ["oci", section]}])
		s.compliant == false
	}
}

# An empty list is a statement that there are none, and stays a pass where the benchmark allows it.
test_empty_lists_are_not_missing_evidence if {
	inp := json.patch(green, [
		{"op": "replace", "path": "/oci/compute/instances", "value": []},
		{"op": "replace", "path": "/oci/integration_instances", "value": []},
		{"op": "replace", "path": "/oci/kms/keys", "value": []},
	])
	r := main.compliance_report with input as inp
	r.compliant == true
}

test_string_port_on_an_internet_rule_is_read_as_open if {
	inp := json.patch(green, [
		{"op": "replace", "path": "/oci/network/security_lists/1/ingress/0/source", "value": "0.0.0.0/0"},
		{"op": "replace", "path": "/oci/network/security_lists/1/ingress/0/port_min", "value": "23"},
	])
	v := main.violations with input as inp
	"2.1: checked condition — no security lists allow ingress from 0.0.0.0/0 to port 22" in v
	"2.1: oci.network.security_lists[1].ingress[0].port_min is not a number (got string)" in v
}

test_null_credential_age_is_not_rotated if {
	inp := json.patch(green, [{"op": "replace", "path": "/oci/iam/users/0/api_keys/0/age_days", "value": null}])
	"1.8: checked condition — user API keys rotate within 90 days (alice)" in main.violations with input as inp
}

test_empty_input_reports_no_per_fact_noise if {
	main.violations with input as {} == ({
		"CIS OCI: FAIL-CLOSED - facts 'input.oci' were not supplied; the tenancy was not evaluated",
		"1.1: service level admins must be created to manage resources of particular service",
		"1.4: checked condition — IAM password policy requires minimum length of 14 or greater",
		"1.5: checked condition — IAM password policy expires passwords within 365 days",
		"1.6: checked condition — IAM password policy prevents password reuse",
	} | {m | some m in main.violations with input as {}; regex.match(`^4\.`, m)})
}
