# Tests for maritime_33cfr101f.main — 33 CFR Part 101 Subpart F (USCG maritime cybersecurity).
package maritime_33cfr101f.main_test

import rego.v1

import data.maritime_33cfr101f.main

_all := {r.id: true | some r in main._rows}

test_row_counts_pinned if {
	count(main._rows) == 105
	count(main.obligations) == 105
	count([r | some r in main._rows; r.s == "101.650"]) == 51
	count([r | some r in main._rows; r.s == "101.625"]) == 17
	count([r | some r in main._rows; r.s == "101.630"]) == 15
	count(main.obligations["101.630(c)"].items) == 14
	count(main.obligations["101.625(e)"].items) == 12
}

test_every_row_has_known_section if {
	count([r | some r in main._rows; not main.sections[r.s]]) == 0
	count([r | some r in main._rows; not startswith(r.id, r.s)]) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")
	r.violation_count == 106
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"maritime_33cfr101f": "yes"}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_all_true_is_compliant if {
	main.compliant with input as {"maritime_33cfr101f": {"obligations": _all}}
}

test_one_false_is_named if {
	inp := {"maritime_33cfr101f": {"obligations": object.union(_all, {"101.650(a)(4)": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "33 CFR 101 Subpart F 101.650(a)(4) (§101.650 Cybersecurity measures): not attested — Multifactor authentication")
	r := main.compliance_report with input as inp
	r.sections["101.650"].gaps == ["101.650(a)(4)"]
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"maritime_33cfr101f": {"obligations": object.union(_all, {"101.655": "true", "101.615": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "101.655 (§101.655 Cybersecurity compliance dates): not attested")
	some m2 in v
	contains(m2, "unknown id 101.615")
}

test_dates_carried_as_data if {
	r := main.compliance_report with input as {}
	r.dated_obligations["101.655_cybersecurity_plans_submitted_no_later_than"] == "2027-07-16"
	r.dated_obligations.subpart_f_effective == "2025-07-16"
	r.notification_clocks["101.630(e)(4)_hours_to_notify_and_amend_after_cyso_change"] == 96
}

test_declared_total_matches_rows if {
	r := main.compliance_report with input as {}
	r.total_controls == count(main._rows)
}
