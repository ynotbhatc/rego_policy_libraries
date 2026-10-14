# Tests for nispom.main — 32 CFR Part 117 (NISPOM) contractor obligations.
package nispom.main_test

import rego.v1

import data.nispom.main

_all := {r.id: true | some r in main._rows}

_ungated := {r.id: true | some r in main._rows; r.gate == ""}

_flags_off := {k: false | some k, _ in main._gates}

_flags_on := {k: true | some k, _ in main._gates}

_off(obl) := {"nispom": object.union(_flags_off, {"obligations": obl})}

test_row_counts_pinned if {
	count(main._rows) == 599
	count(main.obligations) == 599
	count(_ungated) == 285
	count(main._gates) == 18
	count([r | some r in main._rows; r.s == "117.8"]) == 45
	count([r | some r in main._rows; r.s == "117.15"]) == 88
	count([r | some r in main._rows; r.s == "117.19"]) == 146
	count([r | some r in main._rows; r.s == "117.22"]) == 1
}

test_every_row_has_known_section_gate_and_prefix if {
	count([r | some r in main._rows; not main.sections[r.s]]) == 0
	count([r | some r in main._rows; r.gate != ""; not main._gates[r.gate]]) == 0
	count([r | some r in main._rows; not startswith(r.id, concat("", [r.s, "("]))]) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# 285 ungated rows + 18 undeclared gates + 1 FAIL-CLOSED
	r.violation_count == 304
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"nispom": object.union(_flags_off, {"obligations": ["117.7(a)"]})}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_ungated_all_true_with_flags_false_is_compliant if {
	inp := _off(_ungated)
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.evaluated == 285
	r.sections["117.19"].applicable == 0
}

test_all_true_all_flags_true_is_compliant if {
	inp := {"nispom": object.union(_flags_on, {"obligations": _all})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.evaluated == 599
	r.attested == 599
}

test_one_false_is_named if {
	inp := _off(object.union(_ungated, {"117.8(c)(1)": false}))
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "NISPOM 32 CFR 117 117.8(c)(1) (§117.8 Reporting requirements): not attested")
	r := main.compliance_report with input as inp
	r.sections["117.8"].gaps == ["117.8(c)(1)"]
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := _off(object.union(_ungated, {"117.7(a)": "true", "117.99(z)": true}))
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "117.7(a) (§117.7 Procedures): not attested")
	some m2 in v
	contains(m2, "unknown id 117.99(z)")
}

test_undeclared_gate_is_a_violation if {
	inp := {"nispom": object.union(object.remove(_flags_off, ["has_foci"]), {"obligations": _ungated})}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "gate nispom.has_foci undeclared")
}

test_foci_gate_opens_foci_rows if {
	inp := {"nispom": object.union(_flags_off, {"has_foci": true, "obligations": _ungated})}
	r := main.compliance_report with input as inp
	r.violation_count == 22
	r.sections["117.11"].applicable == 26
}

test_restricted_data_gate_covers_117_14_q if {
	inp := {"nispom": object.union(_flags_off, {"handles_restricted_data": true, "obligations": _ungated})}
	r := main.compliance_report with input as inp
	r.sections["117.14"].gaps == ["117.14(q)"]
}

test_declared_total_matches_rows if {
	r := main.compliance_report with input as {}
	r.total_controls == count(main._rows)
}
