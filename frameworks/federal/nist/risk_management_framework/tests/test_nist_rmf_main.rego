# Tests for nist.rmf.main — NIST SP 800-37 Rev 2 Chapter 3 tasks (sha256 4f75e1136bb905a654f1bcd9eefefb4108f47597276ee5eec0688f6d96f6a01d).
package nist.rmf.main_test

import rego.v1

import data.nist.rmf.main

_all := {id: true | some id, _ in main.tasks}

_gates := {"uses_tailored_baselines_or_profiles": true, "prioritizes_systems_within_impact_level": true}

_green := {"nist_rmf": object.union(_gates, {"tasks": _all})}

_facts := {
	"confidentiality": {"impact_level": "moderate", "rationale": "r", "loss_scenario_documented": true},
	"integrity": {"impact_level": "high", "rationale": "r", "loss_scenario_documented": true},
	"availability": {"impact_level": "low", "rationale": "r", "loss_scenario_documented": true},
	"overall_impact_level": "high",
	"high_water_mark_applied": true,
	"rationale_documented": true,
	"information_types": [{"confidentiality_impact": "moderate", "integrity_impact": "high", "availability_impact": "low"}],
	"system_boundary": {"clearly_defined": true, "documented": true, "components_identified": true},
	"documentation": {"categorization_results_documented": true, "rationale_provided": true, "stakeholder_approval": true, "review_date": "2026-01-01"},
	"system_owner": {"identified": true, "categorization_approved": true, "responsibilities_documented": true},
	"saiso_review": {"completed": true, "approval_documented": true, "date": "2026-01-02"},
	"provisional_authorization": {"not_applicable": true},
	"external_dependencies": [],
}

_step_count(s) := count({id | some id, t in main.tasks; t.step == s})

test_row_counts_per_step if {
	count(main.tasks) == 47
	count(main.sections) == 8
	_step_count("prepare-organization") == 7
	_step_count("prepare-system") == 11
	_step_count("categorize") == 3
	_step_count("select") == 6
	_step_count("implement") == 2
	_step_count("assess") == 6
	_step_count("authorize") == 5
	_step_count("monitor") == 7
	count(main.legacy) == 12
	count({id | some _, id in main.legacy; not main.tasks[id]}) == 0
}

test_task_text_verbatim if {
	main.tasks["P-1"].text == "Identify and assign individuals to specific roles associated with security and privacy risk management."
	main.tasks["C-2"].text == "Categorize the system and document the security categorization results."
	main.tasks["M-7"].text == "Implement a system disposal strategy and execute required actions when a system is removed from operation."
	main.tasks["R-4"].primary_responsibility == ["Authorizing Official"]
	main.tasks["P-13"].csf == ["ID.AM-3", "ID.AM-4"]
	main.tasks["P-4"].gate == "uses_tailored_baselines_or_profiles"
	main.tasks["P-6"].gate == "prioritizes_systems_within_impact_level"
	count({id | some id, t in main.tasks; t.gate != ""}) == 2
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.tasks_satisfied == 0

	# FAIL-CLOSED + 47 tasks + 2 undeclared gates
	r.violation_count == 50
}

test_non_object_tasks_fail_closed if {
	r := main.compliance_report with input as {"nist_rmf": {"tasks": ["P-1"]}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_all_true_with_gates_declared_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.tasks_satisfied == 47
	r.steps.categorize.tasks_satisfied == 3
	r.steps["prepare-system"].tasks_satisfied == 11
}

test_undeclared_gate_is_a_violation if {
	r := main.compliance_report with input as {"nist_rmf": {"tasks": _all}}
	r.compliant == false
	r.violation_count == 2
	some v in r.violations
	contains(v, "uses_tailored_baselines_or_profiles")
}

test_gate_false_makes_optional_task_not_applicable if {
	tasks := object.remove(_all, ["P-4", "P-6"])
	r := main.compliance_report with input as {"nist_rmf": {"tasks": tasks, "uses_tailored_baselines_or_profiles": false, "prioritizes_systems_within_impact_level": false}}
	r.compliant == true
	r.tasks_not_applicable == 2
	r.steps["prepare-organization"].tasks_not_applicable == ["P-4", "P-6"]
}

test_one_false_task_is_named if {
	r := main.compliance_report with input as {"nist_rmf": object.union(_gates, {"tasks": object.union(_all, {"A-4": false})})}
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "A-4")
	r.steps.assess.tasks_not_satisfied == ["A-4"]
}

test_unknown_task_id_is_a_violation if {
	r := main.compliance_report with input as {"nist_rmf": object.union(_gates, {"tasks": object.union(_all, {"P-19": true})})}
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "unknown task id P-19")
}

test_categorization_facts_that_hold_keep_compliance if {
	r := main.compliance_report with input as object.union(_green, {"system_categorization": _facts})
	r.categorization_facts_supplied == true
	r.compliant == true
}

test_failing_legacy_fact_names_the_task_even_when_attested if {
	bad := object.union(_facts, {"overall_impact_level": "moderate"})
	r := main.compliance_report with input as object.union(_green, {"system_categorization": bad})
	r.compliant == false
	some v in r.violations
	contains(v, "C-2")
	contains(v, "high_water_mark_properly_applied")
	r.steps.categorize.tasks_not_satisfied == ["C-2"]
}

test_legacy_categorize_package_still_answers if {
	data.nist.rmf.categorize.high_water_mark_properly_applied with input as {"system_categorization": _facts}
	data.nist.rmf.categorize.rmf_categorization_compliant with input as {"system_categorization": _facts}
	r := data.nist.rmf.categorize.rmf_categorization_compliance with input as {"system_categorization": _facts}
	r.overall_compliant == true
	r.saiso_review_completed == true
}
