# Tests for nist.ai_rmf.main — NIST AI 100-1 (AI RMF 1.0) Core, 72 subcategories, sha256 7576edb531d9848825814ee88e28b1795d3a84b435b4b797d3670eafdc4a89f1.
package nist.ai_rmf.main_test

import rego.v1

import data.nist.ai_rmf.main

_facts := {
	"govern": {
		"ai_governance_roles_defined": true,
		"ai_risk_tolerance_defined": true,
		"team_diversity_considered": true,
		"organizational_training_on_ai_risk": true,
	},
	"map": {"intended_use_documented": true},
	"measure": {
		"ai_risk_metrics_defined": true,
		"bias_testing_conducted": true,
		"performance_monitored_post_deployment": true,
		"privacy_risk_assessed": true,
		"explainability_assessed": true,
		"regular_risk_assessments": true,
	},
	"manage": {
		"risk_treatment_plans_documented": true,
		"human_override_available": true,
		"retire_plan_documented": true,
	},
	"ai_system": {"name": "ResumeRanker", "fairness_assessed": true},
	"assessment_date": "2026-10-14",
}

_attested := {sid: true | some sid, s in main.subcategories; s.basis == "attestation"}

_green := object.union(_facts, {
	"nist_ai_rmf": {"subcategories": _attested},
	"nist_ai_600_1": {"scope": {"generative_ai": false}},
})

test_core_counts_match_ai_100_1 if {
	count(main.subcategories) == 72
	count(main.categories) == 19
	count(main.function_names) == 4
	count([s | some s in main.subcategories; s.function == "GOVERN"]) == 19
	count([s | some s in main.subcategories; s.function == "MAP"]) == 18
	count([s | some s in main.subcategories; s.function == "MEASURE"]) == 22
	count([s | some s in main.subcategories; s.function == "MANAGE"]) == 13
	count([c | some c in main.categories; c.function == "GOVERN"]) == 6
	count([c | some c in main.categories; c.function == "MAP"]) == 5
	count([c | some c in main.categories; c.function == "MEASURE"]) == 4
	count([c | some c in main.categories; c.function == "MANAGE"]) == 4
	count([s | some s in main.subcategories; s.basis == "facts"]) == 14
	count([s | some s in main.subcategories; s.basis == "attestation"]) == 58
	count(data.nist.ai_rmf.violation) == 15 with input as {}
	count(data.nist.ai_rmf.legacy) == 22
}

test_every_subcategory_belongs_to_its_category_and_function if {
	count({sid | some sid, s in main.subcategories; not main.categories[s.category]}) == 0
	count({sid | some sid, s in main.subcategories; main.categories[s.category].function != s.function}) == 0
	count({sid | some sid, s in main.subcategories; not startswith(sid, concat("", [s.category, "."]))}) == 0
}

test_verbatim_rows if {
	main.subcategories["GOVERN 1.1"].text == "Legal and regulatory requirements involving AI are understood, managed, and documented."
	main.subcategories["MANAGE 4.3"].text == "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented."
	main.categories["MAP 1"].text == "Context is established and understood."
}

test_every_facts_subcategory_has_facts if {
	count({sid | some sid, s in main.subcategories; s.basis == "facts"; not data.nist.ai_rmf.facts_for[sid]}) == 0
	count({sid | some sid, _ in data.nist.ai_rmf.facts_for; main.subcategories[sid].basis != "facts"}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "NIST AI RMF: FAIL-CLOSED")
	some w in r.violations
	contains(w, "NIST AI 600-1: FAIL-CLOSED")
	r.subcategories_satisfied == 0
	r.total_controls == 72
	r.framework == "NIST AI Risk Management Framework (AI RMF)"
	r.version == "1.0"
	is_array(r.violations)
	r.ai_system == "unknown"
}

test_non_object_subcategories_fail_closed if {
	r := main.compliance_report with input as object.union(_green, {"nist_ai_rmf": {"subcategories": ["GOVERN 1.1"]}})
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_full_green_input_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.subcategories_satisfied == 72
	r.ai_system == "ResumeRanker"
	r.assessed_at == "2026-10-14"
	r.generative_ai_profile.scope == "not_applicable"
	r.total_controls == 72
	r.generative_ai_profile.compliant == true
	not r.generative_ai_profile.violations
	r.function_summary.GOVERN.compliant == true
	r.function_summary.MANAGE.subcategories_total == 13
}

test_one_attestation_false_is_named if {
	r := main.compliance_report with input as object.union(_green, {"nist_ai_rmf": {"subcategories": object.union(_attested, {"MEASURE 2.12": false})}})
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	startswith(v, "NIST AI RMF MEASURE 2.12 (MEASURE 2): not attested satisfied")
	r.functions.MEASURE.not_satisfied == ["MEASURE 2.12"]
}

test_non_true_attestation_is_a_violation if {
	r := main.compliance_report with input as object.union(_green, {"nist_ai_rmf": {"subcategories": object.union(_attested, {"GOVERN 1.1": "true"})}})
	r.compliant == false
	some v in r.violations
	startswith(v, "NIST AI RMF GOVERN 1.1 ")
}

test_one_fact_false_is_named_and_not_fail_open if {
	r := main.compliance_report with input as object.union(_green, {"manage": {"human_override_available": "false"}})
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	startswith(v, "NIST AI RMF MANAGE 2.4 (MANAGE 2): facts not satisfied")
	r.subcategories["MANAGE 2.4"].satisfied == false
}

test_attesting_a_facts_subcategory_is_ignored if {
	no_facts := object.remove(_green, ["govern"])
	r := main.compliance_report with input as object.union(no_facts, {"nist_ai_rmf": {"subcategories": object.union(_attested, {"GOVERN 2.1": true})}})
	r.compliant == false
	r.subcategories["GOVERN 2.1"].satisfied == false
}

test_unknown_id_is_a_violation if {
	r := main.compliance_report with input as object.union(_green, {"nist_ai_rmf": {"subcategories": object.union(_attested, {"GOVERN 9.9": true})}})
	r.compliant == false
	some v in r.violations
	contains(v, "unknown subcategory id GOVERN 9.9")
}

test_profile_violations_are_counted_once if {
	r := main.compliance_report with input as object.union(_green, {"nist_ai_600_1": {"scope": {"generative_ai": true}, "actions": {}}})
	p := data.nist.ai_600_1.main.compliance_report with input as object.union(_green, {"nist_ai_600_1": {"scope": {"generative_ai": true}, "actions": {}}})
	r.compliant == false
	p.violation_count == 212
	r.violation_count == 212
	r.total_controls == 284
	r.core_controls == 72
	r.profile_controls == 212
	r.standard_total == 72
	r.generative_ai_profile.total_controls == 212
	not r.generative_ai_profile.violations
}

test_profile_in_scope_and_attested_is_compliant if {
	acts := {aid: true | some aid, _ in data.nist.ai_600_1.main.actions}
	r := main.compliance_report with input as object.union(_green, {"nist_ai_600_1": {"scope": {"generative_ai": true}, "actions": acts}})
	r.compliant == true
	r.generative_ai_profile.actions_satisfied == 212
}

test_legacy_fact_checks_reported if {
	r := main.compliance_report with input as {}
	count(r.legacy_fact_checks) == 22
	r.legacy_fact_checks["govern.ai_risk_policy_documented"].status == "unmapped"
}
