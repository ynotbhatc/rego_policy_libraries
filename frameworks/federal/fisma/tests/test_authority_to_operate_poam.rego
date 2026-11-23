package fisma.ato_poam_test

import rego.v1

# Weekly audit 2026-11-23: "an empty POA&M counts as adequate".
# NIST SP 800-53 Rev 5 CA-5: the POA&M documents planned remediation of assessed weaknesses and known
# vulnerabilities, so an empty one is adequate only when there is nothing to track, and a missing one is
# missing evidence.

ato := data.fisma.ato

_item := {
	"weakness_id": "W-1",
	"description": "TLS 1.0 enabled on the load balancer",
	"resources_required": "2 engineer days",
	"completion_date": "2027-01-15",
	"risk_rating": "moderate",
	"status": "ongoing",
}

_inp(poam) := {"ato": {"authorization_package": {"poam": poam}}}

_adequate(poam) if ato.plan_of_action_milestones_adequate with input as _inp(poam)

test_empty_poam_without_declared_zero_is_not_adequate if {
	not _adequate({"action_items": [], "risk_tolerance_acceptable": true})
	f := ato.poam_evidence_findings with input as _inp({"action_items": [], "risk_tolerance_acceptable": true})
	some msg in f
	contains(msg, "open_weaknesses_count")
}

test_empty_poam_with_zero_open_weaknesses_is_adequate if {
	_adequate({"action_items": [], "open_weaknesses_count": 0, "risk_tolerance_acceptable": true})
}

test_empty_poam_with_open_weaknesses_is_not_adequate if {
	not _adequate({"action_items": [], "open_weaknesses_count": 3, "risk_tolerance_acceptable": true})
}

test_zero_as_string_or_boolean_is_not_a_declaration if {
	not _adequate({"action_items": [], "open_weaknesses_count": "0", "risk_tolerance_acceptable": true})
	not _adequate({"action_items": [], "open_weaknesses_count": false, "risk_tolerance_acceptable": true})
	not _adequate({"action_items": [], "open_weaknesses_count": null, "risk_tolerance_acceptable": true})
}

test_empty_poam_contradicted_by_known_vulnerabilities if {
	inp := {"ato": {
		"authorization_package": {"poam": {"action_items": [], "open_weaknesses_count": 0, "risk_tolerance_acceptable": true}},
		"risk_assessment": {"vulnerabilities": {"identified_vulnerabilities": ["CVE-2026-0001"]}},
	}}
	not ato.plan_of_action_milestones_adequate with input as inp
	f := ato.poam_evidence_findings with input as inp
	some msg in f
	contains(msg, "identified_vulnerabilities lists 1")
}

test_missing_null_and_wrong_typed_poam_is_evidence_missing if {
	every poam in [
		{"risk_tolerance_acceptable": true},
		{"action_items": null, "risk_tolerance_acceptable": true},
		{"action_items": "none", "risk_tolerance_acceptable": true},
		{"action_items": {}, "open_weaknesses_count": 0, "risk_tolerance_acceptable": true},
		{"action_items": 0, "risk_tolerance_acceptable": true},
	] {
		not _adequate(poam)
	}
}

test_evidence_missing_is_reported_for_each_bad_shape if {
	every poam in [
		{},
		{"action_items": null},
		{"action_items": "none"},
		{"action_items": {}, "open_weaknesses_count": 0},
	] {
		f := ato.poam_evidence_findings with input as _inp(poam)
		some msg in f
		contains(msg, "evidence missing")
	}
	f0 := ato.poam_evidence_findings with input as {}
	some msg0 in f0
	contains(msg0, "evidence missing")
}

test_complete_items_are_adequate if {
	_adequate({"action_items": [_item], "risk_tolerance_acceptable": true})
	count(ato.poam_evidence_findings) == 0 with input as _inp({"action_items": [_item]})
}

test_risk_tolerance_still_required if {
	not _adequate({"action_items": [_item]})
	not _adequate({"action_items": [_item], "risk_tolerance_acceptable": "true"})
}

test_wrong_typed_or_blank_item_fields_are_incomplete if {
	every bad in [
		object.union(_item, {"weakness_id": 7}),
		object.union(_item, {"description": true}),
		object.union(_item, {"completion_date": "  "}),
		object.remove(_item, ["resources_required"]),
		object.union(_item, {"status": "closed-ish"}),
		"W-1",
	] {
		not _adequate({"action_items": [_item, bad], "risk_tolerance_acceptable": true})
		f := ato.poam_evidence_findings with input as _inp({"action_items": [_item, bad]})
		some msg in f
		contains(msg, "POA&M item 1 is incomplete")
	}
}

test_report_carries_the_findings if {
	a := ato.ato_assessment with input as _inp({"action_items": []})
	count(a.poam_evidence_findings) == 1
	a.ato_ready == false
}
