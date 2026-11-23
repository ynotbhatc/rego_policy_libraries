package fisma.main_empty_lists_test

import rego.v1

# Weekly audit 2026-11-23 follow-up: `count(x) >= 0` is true for every collection, so an empty list (and an object)
# passed. A list is evidence only as an array, and an empty one passes only with an explicit "there are none" fact.

fm := data.fisma.main

_poa := {
	"finding_id": "F-1",
	"remediation_strategy": "Disable TLS 1.0",
	"target_completion_date": "2027-01-15",
	"responsible_party": "Platform team",
	"risk_level": "moderate",
}

_remediation(r) := {"fisma": {"assess": {"remediation": r}}}

_poam_ok(r) if fm.remediation_plans_developed with input as _remediation(r)

# NIST SP 800-53 Rev 5 CA-5: the POA&M tracks weaknesses and known vulnerabilities.
test_empty_poam_needs_zero_open_weaknesses if {
	not _poam_ok({"plan_of_actions": []})
	not _poam_ok({"plan_of_actions": [], "open_weaknesses_count": 2})
	not _poam_ok({"plan_of_actions": [], "open_weaknesses_count": "0"})
	not _poam_ok({"plan_of_actions": [], "open_weaknesses_count": null})
	_poam_ok({"plan_of_actions": [], "open_weaknesses_count": 0})
}

test_missing_or_wrong_typed_poam_is_not_developed if {
	every r in [{}, {"plan_of_actions": null}, {"plan_of_actions": {}, "open_weaknesses_count": 0}, {"plan_of_actions": "none"}] {
		not _poam_ok(r)
	}
	not fm.remediation_plans_developed with input as {}
}

test_poam_items_must_be_complete if {
	_poam_ok({"plan_of_actions": [_poa]})
	every bad in [
		object.union(_poa, {"finding_id": 7}),
		object.union(_poa, {"remediation_strategy": true}),
		object.union(_poa, {"target_completion_date": " "}),
		object.remove(_poa, ["responsible_party"]),
		object.union(_poa, {"risk_level": "critical"}),
	] {
		not _poam_ok({"plan_of_actions": [_poa, bad]})
	}
}

_tailored := {"control_id": "AC-2", "tailoring_action": "modify", "rationale": "Parameter set by agency policy", "approval_documented": true}

_tailoring_ok(t) if fm.control_tailoring_completed with input as {"fisma": {"select": {"tailoring": t}}}

# NIST SP 800-53 Rev 5 PL-11 (tailor the selected baseline) and PL-2a (rationale for any tailoring decisions).
test_empty_tailoring_needs_explicit_statement if {
	not _tailoring_ok({"tailored_controls": []})
	not _tailoring_ok({"tailored_controls": [], "tailoring_applied": true})
	not _tailoring_ok({"tailored_controls": [], "tailoring_applied": "false"})
	not _tailoring_ok({"tailored_controls": [], "tailoring_applied": null})
	_tailoring_ok({"tailored_controls": [], "tailoring_applied": false})
}

test_tailoring_list_must_be_an_array_and_consistent if {
	_tailoring_ok({"tailored_controls": [_tailored]})
	_tailoring_ok({"tailored_controls": [_tailored], "tailoring_applied": true})
	not _tailoring_ok({"tailored_controls": [_tailored], "tailoring_applied": false})
	not _tailoring_ok({"tailoring_applied": false})
	not _tailoring_ok({"tailored_controls": null, "tailoring_applied": false})
	not _tailoring_ok({"tailored_controls": {}, "tailoring_applied": false})
	not _tailoring_ok({"tailored_controls": [object.union(_tailored, {"rationale": 5})]})
	not _tailoring_ok({"tailored_controls": [object.union(_tailored, {"approval_documented": "true"})]})
}

_comp := {"baseline_control_id": "IA-2(1)", "compensating_control_id": "AC-3", "rationale": "Legacy console", "risk_acceptance_documented": true}

_comp_ok(s) if fm.compensating_controls_identified with input as {"fisma": {"select": s}}

# PL-11 discussion: tailoring includes "selecting compensating controls".
test_empty_compensating_controls_need_explicit_statement if {
	not _comp_ok({"compensating_controls": []})
	not _comp_ok({"compensating_controls": [], "compensating_controls_used": true})
	not _comp_ok({"compensating_controls": [], "compensating_controls_used": 0})
	_comp_ok({"compensating_controls": [], "compensating_controls_used": false})
}

test_compensating_controls_must_be_an_array_and_consistent if {
	_comp_ok({"compensating_controls": [_comp]})
	not _comp_ok({"compensating_controls": [_comp], "compensating_controls_used": false})
	not _comp_ok({"compensating_controls_used": false})
	not _comp_ok({"compensating_controls": {}, "compensating_controls_used": false})
	not _comp_ok({"compensating_controls": null})
	not _comp_ok({"compensating_controls": [object.union(_comp, {"compensating_control_id": ""})]})
}
