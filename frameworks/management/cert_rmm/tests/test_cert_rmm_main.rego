# Tests for cert_rmm.main — CERT Resilience Management Model v1.2 specific practices.
package cert_rmm.main_test

import rego.v1

import data.cert_rmm.main

_all := {r.id: true | some r in main.practice_rows}

test_row_counts_pinned if {
	count(main.practice_rows) == 248
	count(main.practice_by_id) == 248
	count(main.process_areas) == 26
	count(main.goals) == 93
	count(main.generic_goals) == 3
	count(main.generic_practices) == 13
	count({r.id | some r in main.practice_rows; r.process_area == "SC"}) == 20
	count({r.id | some r in main.practice_rows; r.process_area == "AM"}) == 4
}

test_every_row_has_known_area_and_goal if {
	count({r.id | some r in main.practice_rows; not main.process_areas[r.process_area]}) == 0
	count({r.id | some r in main.practice_rows; not main.goals[r.goal]}) == 0
	count({r.id | some r in main.practice_rows; not startswith(r.id, concat("", [r.goal, ".SP"]))}) == 0
	count({g | some g, _ in main.goals; count({r | some r in main.practice_rows; r.goal == g}) == 0}) == 0
}

test_wrapped_titles_joined if {
	main.practice_by_id["RRM:SG1.SP5"].title == "Identify Inconsistencies Between Resilience Requirements and Activities Performed to Meet the Requirements"
	main.practice_by_id["RTSE:SG2.SP2"].title == "Integrate Selected Guidelines with a Defined Software and System Development Process"
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED notice + 248 unattested practices
	r.violation_count == 249
	r.specific_goals_achieved == 0
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"cert_rmm": {"practices": "all"}}
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_full_attestation_is_compliant if {
	main.compliant with input as {"cert_rmm": {"practices": _all}}
	r := main.compliance_report with input as {"cert_rmm": {"practices": _all}}
	r.specific_goals_achieved == 93
	r.process_areas.ADM.gg1_achieve_specific_goals == true
}

test_one_false_is_named_and_breaks_its_goal if {
	inp := {"cert_rmm": {"practices": object.union(_all, {"AM:SG1.SP3": false})}}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	startswith(m, "CERT-RMM AM:SG1.SP3 (AM Access Management)")
	r := main.compliance_report with input as inp
	r.process_areas.AM.not_attested == ["AM:SG1.SP3"]
	r.process_areas.AM.specific_goals_achieved == []
	r.process_areas.AM.gg1_achieve_specific_goals == false
	r.specific_goals_achieved == 92
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"cert_rmm": {"practices": object.union(_all, {"VAR:SG4.SP1": "true", "AM:SG2.SP3": true})}}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "CERT-RMM VAR:SG4.SP1 ")
	some m2 in v
	contains(m2, "unknown practice id AM:SG2.SP3")
}
