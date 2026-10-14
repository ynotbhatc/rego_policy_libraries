# Tests for nrc_73_54.main — 10 CFR 73.54 cyber security rule for nuclear power reactors.
package nrc_73_54.main_test

import rego.v1

import data.nrc_73_54.main

_all := {r.id: true | some r in main._rows}

test_row_counts_pinned if {
	count(main._rows) == 34
	count(main.paragraphs) == 34
	count([r | some r in main._rows; r.s == "a"]) == 10
	count([r | some r in main._rows; r.s == "e"]) == 7
	count([r | some r in main._rows; r.stem != ""]) == 22
}

test_every_row_has_known_section if {
	count([r | some r in main._rows; not main.sections[r.s]]) == 0
	count([r | some r in main._rows; not startswith(r.id, concat("", ["73.54(", r.s, ")"]))]) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")
	r.violation_count == 35
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"nrc_73_54": {"paragraphs": true}}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_all_true_is_compliant if {
	main.compliant with input as {"nrc_73_54": {"paragraphs": _all}}
	r := main.compliance_report with input as {"nrc_73_54": {"paragraphs": _all}}
	r.attested == 34
	r.standard_total == 34
}

test_one_false_is_named if {
	inp := {"nrc_73_54": {"paragraphs": object.union(_all, {"73.54(e)(2)(iii)": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "10 CFR 73.54 73.54(e)(2)(iii) (§73.54(e)): not attested — Correct exploited vulnerabilities; and")
	r := main.compliance_report with input as inp
	r.sections.e.gaps == ["73.54(e)(2)(iii)"]
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"nrc_73_54": {"paragraphs": object.union(_all, {"73.54(h)": "true", "73.54(i)": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "73.54(h) (§73.54(h)): not attested")
	some m2 in v
	contains(m2, "unknown id 73.54(i)")
}

test_dated_obligation_carried if {
	r := main.compliance_report with input as {}
	r.dated_obligations.cyber_security_plan_submission_by_existing_part_50_licensees == "2009-11-23"
}

test_declared_total_matches_rows if {
	r := main.compliance_report with input as {}
	r.total_controls == count(main._rows)
}
