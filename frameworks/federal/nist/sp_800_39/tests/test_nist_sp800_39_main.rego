# Tests for nist.sp800_39.main — NIST SP 800-39 Chapter 3 tasks (sha256 cf680760d171fc590396c1d98eef184af96efa971ef9880830cd2912ea1a54a8).
package nist.sp800_39.main_test

import rego.v1

import data.nist.sp800_39.main

_all := {id: true | some id, _ in main.tasks}

_comp_count(c) := count({id | some id, t in main.tasks; t.component == c})

test_row_counts_per_component if {
	count(main.tasks) == 12
	count(main.sections) == 4
	_comp_count("frame") == 4
	_comp_count("assess") == 2
	_comp_count("respond") == 4
	_comp_count("monitor") == 2
	count({id | some id, t in main.tasks; t.label != concat("", ["TASK ", id])}) == 0
	count({id | some id, t in main.tasks; count(t.tiers) != 3}) == 0
}

test_task_text_verbatim if {
	main.tasks["1-1"].text == "Identify assumptions that affect how risk is assessed, responded to, and monitored within the organization."
	main.tasks["1-3"].text == "Identify the level of risk tolerance for the organization."
	main.tasks["4-2"].text == "Monitor organizational information systems and environments of operation on an ongoing basis to verify compliance, determine effectiveness of risk response measures, and identify changes."
	main.tasks["3-2"].title == "EVALUATION OF ALTERNATIVES"
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.tasks_satisfied == 0
	r.violation_count == 13
}

test_non_object_tasks_fail_closed if {
	r := main.compliance_report with input as {"nist_sp_800_39": {"tasks": "all"}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_all_true_is_compliant if {
	r := main.compliance_report with input as {"nist_sp_800_39": {"tasks": _all}}
	r.compliant == true
	r.violation_count == 0
	r.tasks_satisfied == 12
	r.components.respond.tasks_satisfied == 4
}

test_one_false_task_is_named if {
	r := main.compliance_report with input as {"nist_sp_800_39": {"tasks": object.union(_all, {"2-2": false})}}
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "TASK 2-2")
	r.components.assess.tasks_not_satisfied == ["2-2"]
}

test_unknown_task_id_is_a_violation if {
	r := main.compliance_report with input as {"nist_sp_800_39": {"tasks": object.union(_all, {"TASK 1-1": true})}}
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "unknown task id TASK 1-1")
}
