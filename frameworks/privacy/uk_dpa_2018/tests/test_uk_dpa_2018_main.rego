# Tests for uk_dpa_2018.main — Data Protection Act 2018 duties beyond the UK GDPR (revised to 2026-09-30).
package uk_dpa_2018.main_test

import rego.v1

import data.uk_dpa_2018.main

_all := {id: true | some id, _ in main.duties}

_all_on := {k: true | some k, _ in main._gates}

_all_off := {k: false | some k, _ in main._gates}

_flags_off_but(k) := object.union(_all_off, {k: true})

_in(scope, duties) := {"uk_dpa_2018": {"scope": scope, "duties": duties}}

test_table_counts_per_chapter if {
	count(main.duties_table) == 151
	count(main.duties) == 151
	count({id | some id, r in main.duties; r.gate == ""}) == 3
	count({id | some id, r in main.duties; r.gate == "competent_authority"}) == 130
	counts := {c: n | some c, _ in main.chapters; n := count({id | some id, r in main.duties; r.group == c})}
	counts == {
		"P2C2": 4, "P2C2-S1": 4, "P2C2-S2": 4, "P2C2-S3": 3, "P2C3": 3,
		"P3C2": 24, "P3C3": 35, "P3C4": 52, "P3C5": 14, "P3C6": 5, "P6": 3,
	}
	main.compliance_report.total_controls == count(main.duties)
}

test_every_row_has_known_gate_chapter_and_text if {
	count({id | some id, r in main.duties; r.gate != ""; not main._gates[r.gate]}) == 0
	count({id | some id, r in main.duties; not main.chapters[r.group]}) == 0
	count({id | some id, r in main.duties; count(r.text) < 20}) == 0
	count({id | some id, r in main.duties; not regex.match(`^(s\.[0-9]+[A-Z]*(\([0-9]+[A-Z]*\))?|Sch\.[0-9] para [0-9]+[A-Z]?(\([0-9]+\))?)$`, id)}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.scope_flags.competent_authority == "undeclared"

	# FAIL-CLOSED container + 11 undeclared flags + 3 ungated s.164A rows
	r.violation_count == 15
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_missing_duties_container_fails_closed if {
	v := main.violations with input as {"uk_dpa_2018": {"scope": _all_off}}
	some m in v
	contains(m, "FAIL-CLOSED — input.uk_dpa_2018.duties")
}

test_all_flags_true_all_attested_is_compliant if {
	inp := _in(_all_on, _all)
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.duties_evaluated == 151
	r.duties_attested == 151
	r.parts["3"].applicable == 130
	r.parts["2"].applicable == 18
	r.parts["6"].applicable == 3
}

test_one_false_is_named if {
	inp := _in(_all_on, object.union(_all, {"s.62(1)": false}))
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "DPA s.62(1) (Logging):")
	r := main.compliance_report with input as inp
	r.chapters.P3C4.gaps == ["s.62(1)"]
	r.parts["3"].gaps == 1
}

test_unknown_id_is_a_violation if {
	# s.9 (child's consent) is omitted in this version of the Act, so s.9(1) is not a row
	inp := _in(_all_on, object.union(_all, {"s.9(1)": true}))
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "unknown id s.9(1)")
}

test_competent_authority_false_excludes_part_3 if {
	inp := _in(_all_off, {"s.164A(2)": true, "s.164A(3)": true, "s.164A(4)": true})
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.duties_evaluated == 3
	r.parts["3"].duties == 130
	r.parts["3"].applicable == 0
	r.chapters.P3C4.applicable == 0
}

test_competent_authority_true_opens_130_part_3_rows if {
	inp := _in(_flags_off_but("competent_authority"), {"s.164A(2)": true, "s.164A(3)": true, "s.164A(4)": true})
	r := main.compliance_report with input as inp
	r.duties_evaluated == 133
	r.violation_count == 130
	r.parts["3"].gaps == 130
}

test_part_2_gates_open_their_rows if {
	r1 := main.compliance_report with input as _in(_flags_off_but("schedule_1_policy_document"), {})
	r1.chapters["P2C2-S1"].gaps == ["Sch.1 para 39", "Sch.1 para 40(1)", "Sch.1 para 41", "Sch.1 para 5(1)"]
	r2 := main.compliance_report with input as _in(_flags_off_but("special_category_or_criminal_data"), {})
	r2.chapters.P2C2.gaps == ["s.10(2)", "s.10(3)", "s.10(5)"]
	r3 := main.compliance_report with input as _in(_flags_off_but("national_security_defence_exemption"), {})
	r3.chapters.P2C3.gaps == ["s.28(3)", "s.28(4)"]
}

test_string_true_and_non_boolean_flag_rejected if {
	inp := _in(object.union(_all_off, {"competent_authority": "no"}), {"s.164A(2)": "true", "s.164A(3)": true, "s.164A(4)": true})
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	startswith(m1, "DPA s.164A(2)")
	some m2 in v
	contains(m2, "scope flag competent_authority undeclared")
}
