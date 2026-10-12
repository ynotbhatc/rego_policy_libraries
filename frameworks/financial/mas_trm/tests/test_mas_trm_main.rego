# Tests for mas_trm.main — MAS Technology Risk Management Guidelines (January 2021).
package mas_trm.main_test

import rego.v1

import data.mas_trm.main

_all := {id: true | some id, _ in main.controls}

_all_but_ch14 := {id: true | some id, c in main.controls; c.ch != "14"}

# ── Table integrity ─────────────────────────────────────────────────────────

test_table_has_237_controls if {
	count(main.controls) == 237
}

test_every_control_has_a_known_chapter if {
	count({id | some id, c in main.controls; not main.chapters[c.ch]}) == 0
}

test_ids_are_paragraph_numbers_of_their_chapter if {
	count({id | some id, c in main.controls; not startswith(id, concat("", [c.ch, "."]))}) == 0
}

test_parts_do_not_overlap if {
	count(main.controls_a) + count(main.controls_b) == count(main.controls)
}

test_chapter_14_has_23_controls if {
	count({id | some id, c in main.controls; c.ch == "14"}) == 23
}

# ── Fail-closed ─────────────────────────────────────────────────────────────

test_empty_input_is_all_violations if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.controls_evaluated == 237
	r.violation_count == 237
	r.online_financial_services_in_scope == true
}

test_string_true_is_not_an_attestation if {
	inp := {"mas_trm": {"controls": object.union(_all, {"9.1.5": "true"})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "MAS TRM 9.1.5")
}

test_unknown_id_is_flagged if {
	inp := {"mas_trm": {"controls": object.union(_all, {"16.1.1": true})}}
	v := main.violations with input as inp
	count(v) == 1
	some msg in v
	contains(msg, "unknown paragraph id 16.1.1")
}

test_non_object_controls_flagged if {
	v := main.violations with input as {"mas_trm": {"controls": ["9.1.5"]}}
	some msg in v
	contains(msg, "must be an object")
}

# ── Scope ───────────────────────────────────────────────────────────────────

test_full_attestation_is_compliant if {
	main.compliant with input as {"mas_trm": {"controls": _all}}
}

test_no_online_financial_services_excludes_chapter_14_only if {
	inp := {"mas_trm": {"online_financial_services": false, "controls": _all_but_ch14}}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.controls_evaluated == 214
	r.chapters["14"].applicable == false
	r.chapters["14"].controls == 0
}

test_chapter_14_attestations_still_type_checked_when_out_of_scope if {
	inp := {"mas_trm": {"online_financial_services": false, "controls": object.union(_all_but_ch14, {"14.2.1": true})}}
	main.compliant with input as inp
}

test_declaring_ofs_false_does_not_excuse_other_chapters if {
	inp := {"mas_trm": {"online_financial_services": false, "controls": {}}}
	r := main.compliance_report with input as inp
	r.violation_count == 214
}

# ── Chapter report ──────────────────────────────────────────────────────────

test_chapter_report_counts_gaps if {
	inp := {"mas_trm": {"controls": object.remove(_all, {"9.1.5", "9.2.1"})}}
	r := main.compliance_report with input as inp
	r.chapters["9"].controls == 12
	r.chapters["9"].attested == 10
	r.chapters["9"].gaps == ["9.1.5", "9.2.1"]
	r.chapters["10"].gaps == []
	r.violation_count == 2
}
