# Tests for nist.sp800_160v2.main — NIST SP 800-160 Vol. 2 Rev. 1 implementation approaches (sha256 d3e9830faadfd1e7a43392194320c5203935c3d7f30f78896b55a8a53e0f0b15).
package nist.sp800_160v2.main_test

import rego.v1

import data.nist.sp800_160v2.main

_all := {id: true | some id, _ in main.approaches}

_green := {"nist_sp_800_160v2": {"approaches": _all}}

test_table_counts_match_source if {
	count(main.approaches) == 50
	count(main.techniques) == 14
	count(main.objectives) == 8
	count(main.goals) == 4
	count(main.strategic_design_principles) == 5
	count(main.structural_design_principles) == 14
	count([1 | some _, a in main.approaches; some _ in a.sp800_53]) == 418
	count({c | some _, a in main.approaches; some c in a.sp800_53}) == 265
}

test_approaches_per_technique if {
	count(main._by_technique["adaptive-response"]) == 3
	count(main._by_technique["analytic-monitoring"]) == 3
	count(main._by_technique["contextual-awareness"]) == 3
	count(main._by_technique["coordinated-protection"]) == 4
	count(main._by_technique.deception) == 4
	count(main._by_technique.diversity) == 6
	count(main._by_technique["dynamic-positioning"]) == 5
	count(main._by_technique["non-persistence"]) == 3
	count(main._by_technique["privilege-restriction"]) == 3
	count(main._by_technique.realignment) == 6
	count(main._by_technique.redundancy) == 3
	count(main._by_technique.segmentation) == 2
	count(main._by_technique["substantiated-integrity"]) == 3
	count(main._by_technique.unpredictability) == 2
}

test_approaches_per_objective if {
	count(main._by_objective["prevent-or-avoid"]) == 26
	count(main._by_objective.prepare) == 16
	count(main._by_objective.continue) == 20
	count(main._by_objective.constrain) == 18
	count(main._by_objective.reconstitute) == 19
	count(main._by_objective.understand) == 17
	count(main._by_objective.transform) == 11
	count(main._by_objective["re-architect"]) == 18
}

test_every_row_is_well_formed if {
	count({id | some id, a in main.approaches; not main.techniques[a.technique]}) == 0
	count({id | some id, a in main.approaches; not startswith(id, concat("", [a.technique, "."]))}) == 0
	count({id | some id, a in main.approaches; some o in a.objectives; not main.objectives[o]}) == 0
	count({id | some id, a in main.approaches; count(a.objectives) == 0}) == 0
	count({id | some id, a in main.approaches; count(a.sp800_53) == 0}) == 0
	count({o | some o, gs in main.objective_goals; some g in gs; not main.goals[g]}) == 0
}

# Table D-13: each technique row equals the union of its approaches' rows
test_technique_objectives_equal_union_of_approaches if {
	every t, objs in main.technique_objectives {
		{o | some o in objs} == {o | some id in main._by_technique[t]; some o in main.approaches[id].objectives}
	}
}

test_one_approach_per_technique_verbatim if {
	main.approaches["adaptive-response.dynamic-reconfiguration"].technique == "adaptive-response"
	main.approaches["adaptive-response.dynamic-reconfiguration"].text == "Make changes to individual systems, system elements, components, or sets of resources to change functionality or behavior without interrupting service."
	main.approaches["analytic-monitoring.monitoring-and-damage-assessment"].technique == "analytic-monitoring"
	main.approaches["analytic-monitoring.monitoring-and-damage-assessment"].text == "Monitor and analyze behavior and characteristics of components and resources to look for indicators of adversary activity or precursor conditions or indications of other threat events and to detect and assess damage from adversity."
	main.approaches["contextual-awareness.dynamic-resource-awareness"].technique == "contextual-awareness"
	main.approaches["contextual-awareness.dynamic-resource-awareness"].text == "Maintain current information about resources, the status of resources, and resource connectivity."
	main.approaches["coordinated-protection.calibrated-defense-in-depth"].technique == "coordinated-protection"
	main.approaches["coordinated-protection.calibrated-defense-in-depth"].text == "Provide complementary protective mechanisms at different architectural layers or in different locations, calibrating the strength and number of mechanisms to resource value."
	main.approaches["deception.obfuscation"].technique == "deception"
	main.approaches["deception.obfuscation"].text == "Hide, transform, or otherwise obscure the contents, properties, or presence of information or other assets from the adversary."
	main.approaches["diversity.architectural-diversity"].technique == "diversity"
	main.approaches["diversity.architectural-diversity"].text == "Use multiple sets of technical standards, different technologies, and different architectural patterns."
	main.approaches["dynamic-positioning.functional-relocation-of-sensors"].technique == "dynamic-positioning"
	main.approaches["dynamic-positioning.functional-relocation-of-sensors"].text == "Relocate sensors or reallocate responsibility for specific sensing tasks to look for indicators of adverse events."
	main.approaches["non-persistence.non-persistent-information"].technique == "non-persistence"
	main.approaches["non-persistence.non-persistent-information"].text == "Refresh information periodically, or generate information on demand and delete it when no longer needed."
	main.approaches["privilege-restriction.trust-based-privilege-management"].technique == "privilege-restriction"
	main.approaches["privilege-restriction.trust-based-privilege-management"].text == "Define, assign, and maintain privileges based on established trust criteria consistent with the principles of least privilege."
	main.approaches["realignment.purposing"].technique == "realignment"
	main.approaches["realignment.purposing"].text == "Ensure that cyber resources are used consistently with mission or business function purposes and approved uses, thereby avoiding unnecessary sharing and complexity."
	main.approaches["redundancy.protected-backup-and-restore"].technique == "redundancy"
	main.approaches["redundancy.protected-backup-and-restore"].text == "Back up information and software (including configuration data and virtualized resources) in a way that protects its confidentiality, integrity, and authenticity. Enable safe and secure restoration in case of disruption or corruption."
	main.approaches["segmentation.predefined-segmentation"].technique == "segmentation"
	main.approaches["segmentation.predefined-segmentation"].text == "Define enclaves, segments, micro-segments, or other restricted types of resource sets based on criticality and trustworthiness so that they can be protected separately and, if necessary, isolated."
	main.approaches["substantiated-integrity.integrity-checks"].technique == "substantiated-integrity"
	main.approaches["substantiated-integrity.integrity-checks"].text == "Apply and validate checks of the integrity or quality of information, components, or services to guard against surreptitious modification."
	main.approaches["unpredictability.temporal-unpredictability"].technique == "unpredictability"
	main.approaches["unpredictability.temporal-unpredictability"].text == "Change behavior or state at times that are determined randomly or by complex functions."
}

test_mappings_pinned if {
	main.approaches["adaptive-response.dynamic-reconfiguration"].sp800_53 == ["AC-2(6)", "AC-2(8)", "AC-4(3)", "CP-2(5)", "IR-4(2)", "IR-4(3)", "IR-4(9)", "IR-4(11)", "SC-7(20)"]
	main.approaches["adaptive-response.dynamic-reconfiguration"].objectives == ["prevent-or-avoid", "continue", "constrain", "reconstitute", "understand"]
	"CM-5(6)" in main.approaches["privilege-restriction.trust-based-privilege-management"].sp800_53
	not "SC-7(15)" in main.approaches["privilege-restriction.trust-based-privilege-management"].sp800_53
	not "SR-7" in main.approaches["coordinated-protection.self-challenge"].sp800_53
	"SR-7" in main.approaches["deception.disinformation"].sp800_53
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
	r.approaches_in_scope == 50
	r.approaches_attested == 0
	r.violation_count == 51
	r.gate_applied == false
}

test_non_object_approaches_fail_closed if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": true}}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_non_object_root_fails_closed if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": "yes"}
	r.compliant == false
	some v in r.violations
	contains(v, "FAIL-CLOSED")
}

test_full_green_without_gate_is_compliant if {
	r := main.compliance_report with input as _green
	r.compliant == true
	r.violation_count == 0
	r.approaches_in_scope == 50
	r.approaches_attested == 50
	count(r.techniques_selected) == 14
	every _, t in r.techniques { t.status == "satisfied" }
	every _, o in r.objectives { o.status == "satisfied" }
}

test_full_green_with_full_gate_is_compliant if {
	sel := [t | some t, _ in main.techniques]
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": _all, "scope": {"techniques_selected": sel}}}
	r.compliant == true
	r.gate_applied == true
	r.approaches_in_scope == 50
}

test_one_false_is_named if {
	inp := {"nist_sp_800_160v2": {"approaches": object.union(_all, {"redundancy.replication": false})}}
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "redundancy.replication")
	contains(v, "Duplicate hardware, information, backups, or functionality in multiple locations, and keep them synchronized.")
	r.techniques.redundancy.status == "not_satisfied"
	r.techniques.redundancy.not_attested == ["redundancy.replication"]
	r.objectives.prepare.not_attested == ["redundancy.replication"]
	r.techniques.segmentation.status == "satisfied"
}

test_missing_and_non_true_values_are_violations if {
	inp := {"nist_sp_800_160v2": {"approaches": object.union(object.remove(_all, ["deception.tainting"]), {"diversity.path-diversity": "true"})}}
	r := main.compliance_report with input as inp
	r.violation_count == 2
}

test_unknown_approach_id_is_violation if {
	inp := {"nist_sp_800_160v2": {"approaches": object.union(_all, {"adaptive-response.teleportation": true})}}
	r := main.compliance_report with input as inp
	r.compliant == false
	some v in r.violations
	contains(v, "unknown approach id adaptive-response.teleportation")
}

test_gate_subset_evaluates_only_selected if {
	inp := {"nist_sp_800_160v2": {
		"approaches": {
			"redundancy.protected-backup-and-restore": true,
			"redundancy.surplus-capacity": true,
			"redundancy.replication": true,
			"segmentation.predefined-segmentation": true,
			"segmentation.dynamic-segmentation-and-isolation": true,
			"deception.tainting": false,
		},
		"scope": {"techniques_selected": ["redundancy", "segmentation"]},
	}}
	r := main.compliance_report with input as inp
	r.compliant == true
	r.gate_applied == true
	r.approaches_in_scope == 5
	r.approaches_attested == 5
	r.techniques_selected == ["redundancy", "segmentation"]
	r.techniques.redundancy.status == "satisfied"
	r.techniques.deception.status == "not_selected"
	r.objectives.understand.status == "not_selected"
	r.objectives.constrain.status == "satisfied"
}

test_gate_subset_still_reports_unattested_selected if {
	inp := {"nist_sp_800_160v2": {"approaches": {"unpredictability.temporal-unpredictability": true}, "scope": {"techniques_selected": ["unpredictability"]}}}
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "unpredictability.contextual-unpredictability")
}

test_gate_subset_still_rejects_unknown_ids if {
	inp := {"nist_sp_800_160v2": {"approaches": {"redundancy.protected-backup-and-restore": true, "redundancy.surplus-capacity": true, "redundancy.replication": true, "nope": true}, "scope": {"techniques_selected": ["redundancy"]}}}
	r := main.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 1
}

test_empty_gate_is_violation_and_ignored if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": _all, "scope": {"techniques_selected": []}}}
	r.compliant == false
	r.gate_applied == false
	r.approaches_in_scope == 50
	some v in r.violations
	contains(v, "non-empty list")
}

test_non_list_gate_is_violation if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": _all, "scope": {"techniques_selected": "redundancy"}}}
	r.compliant == false
	r.violation_count == 1
}

test_unknown_technique_in_gate_is_violation if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": _all, "scope": {"techniques_selected": ["redundancy", "teleportation"]}}}
	r.compliant == false
	r.gate_applied == false
	r.violation_count == 2
	some v in r.violations
	contains(v, "unknown technique id teleportation")
}

test_undeclared_gate_flag_is_violation if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": _all, "scope": {"include_examples": true}}}
	r.compliant == false
	r.violation_count == 1
	some v in r.violations
	contains(v, "undeclared gate flag scope.include_examples")
}

test_non_object_scope_is_violation if {
	r := main.compliance_report with input as {"nist_sp_800_160v2": {"approaches": _all, "scope": ["redundancy"]}}
	r.compliant == false
	r.violation_count == 1
}
