# Tests for apra_cps234.main — APRA CPS 234 Information Security.
package apra_cps234.main_test

import rego.v1

import data.apra_cps234.main

_all := {id: true | some id, _ in main.controls}

_no_tp := {id: true | some id, c in main.controls; not c.tp}

test_table_has_24_paragraphs_13_to_36 if {
	count(main.controls) == 24
	{id | some id, _ in main.controls} == {sprintf("%d", [n]) | some n in numbers.range(13, 36)}
}

test_four_third_party_paragraphs if {
	{id | some id, c in main.controls; c.tp} == {"16", "22", "28", "34"}
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.third_party_managed_assets == "undeclared"

	# 1 flag + 20 non-third-party paragraphs
	r.violation_count == 21
}

test_entity_without_third_parties_is_compliant_with_20 if {
	inp := {"apra_cps234": {"third_party_managed_assets": false, "controls": _no_tp}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.controls_evaluated == 20
}

test_entity_with_third_parties_needs_all_24 if {
	inp := {"apra_cps234": {"third_party_managed_assets": true, "controls": _no_tp}}
	r := main.compliance_report with input as inp
	r.violation_count == 4
	r.sections.capability.gaps == ["16"]
	main.compliant with input as {"apra_cps234": {"third_party_managed_assets": true, "controls": _all}}
}

test_string_true_is_not_an_attestation if {
	inp := {"apra_cps234": {"third_party_managed_assets": true, "controls": object.union(_all, {"35": "true"})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "72 hours")
}

test_unknown_paragraph_flagged if {
	inp := {"apra_cps234": {"third_party_managed_assets": true, "controls": object.union(_all, {"37": true})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown paragraph 37")
}

test_section_report_lists_gaps if {
	inp := {"apra_cps234": {"third_party_managed_assets": false, "controls": object.remove(_no_tp, {"35", "36"})}}
	r := main.compliance_report with input as inp
	r.sections.notification.gaps == ["35", "36"]
	r.violation_count == 2
}

# ── Evidence rule (data-driven, audit 2026-11-24) ────────────────────────────────────────────────────
# Only the boolean true passes a yes/no fact, and a scope flag must be a declared boolean. Every boolean in
# the widest all-pass fixture is replaced in turn by a wrong-typed value, by null, and removed: none passes.
# The report is also defined and non-compliant when there is no input or the module's container is not an object.

_evidence_full := {"apra_cps234": {"third_party_managed_assets": true, "controls": _all}}

_evidence_bool_paths := [p | walk(_evidence_full, [p, v]); is_boolean(v)]

test_evidence_fixture_passes if {
	r := main.compliance_report with input as _evidence_full
	r.compliant == true
	r.violation_count == 0
	count(_evidence_bool_paths) > 10
}

test_evidence_wrong_type_or_null_never_passes if {
	every p in _evidence_bool_paths {
		every bad in ["false", "true", "no", 0, 1, null] {
			r := main.compliance_report with input as json.patch(_evidence_full, [{"op": "replace", "path": p, "value": bad}])
			r.compliant == false
			r.violation_count >= 1
		}
	}
}

test_evidence_removed_never_passes if {
	every p in _evidence_bool_paths {
		r := main.compliance_report with input as json.remove(_evidence_full, [concat("/", p)])
		r.compliant == false
		r.violation_count >= 1
	}
}

test_evidence_report_defined_on_no_or_non_object_facts if {
	some key, _ in _evidence_full
	every bad in [null, "true", "1", 1, true, []] {
		r := main.compliance_report with input as {key: bad}
		r.compliant == false
		r.violation_count >= 1
		top := main.compliance_report with input as bad
		top.compliant == false
	}
	empty := main.compliance_report with input as {}
	empty.compliant == false
}

test_evidence_problem_is_named if {
	some id, _ in _all
	r1 := main.compliance_report with input as json.patch(_evidence_full, [{"op": "replace", "path": ["apra_cps234", "controls", id], "value": "true"}])
	r1.violation_count == 1
	some v1 in r1.violations
	contains(v1, "[evidence invalid — attestation is not a boolean (got string)]")
	r2 := main.compliance_report with input as json.remove(_evidence_full, [concat("/", ["apra_cps234", "controls", id])])
	r2.violation_count == 1
	some v2 in r2.violations
	contains(v2, "[evidence missing — attestation not collected]")
	r3 := main.compliance_report with input as json.patch(_evidence_full, [{"op": "replace", "path": ["apra_cps234", "controls", id], "value": false}])
	r3.violation_count == 1
	some v3 in r3.violations
	not contains(v3, "[evidence")
}
