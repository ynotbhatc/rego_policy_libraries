package nist.sp800_53.contingency_planning_logic_test

# CP family: one finding per base control and Moderate-baseline enhancement, fail closed, organization-defined
# frequencies and periods, attestations for CP-11 and CP-13.

import data.nist.sp800_53.contingency_planning as cp
import rego.v1

# The ids that have a finding in a report ("NIST CP-9: ..." -> "CP-9").
_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

_freq(days, odp) := {"days_since_last": days, "odp": {"frequency_days": odp}}

_att := {"attested": true, "by": "ISSO J. Doe", "date": "2026-11-01"}

_pass := {"cp_controls": {
	"policy_procedures": {
		"policy_documented": true,
		"procedures_documented": true,
		"official_designated": true,
		"policy_review": _freq(200, 365),
		"procedures_review": _freq(100, 365),
	},
	"contingency_plan": {
		"plan_documented": true,
		"approved": true,
		"distributed_to_key_personnel": true,
		"coordinated_with_incident_handling": true,
		"updated_for_changes": true,
		"changes_communicated": true,
		"lessons_learned_incorporated": true,
		"protected_from_unauthorized_disclosure_and_modification": true,
		"review": _freq(200, 365),
		"coordination": {"related_plans": [{"name": "COOP", "coordinated": true}, {"name": "IRP", "coordinated": true}]},
		"resumption": {"covers_all_in_scope_functions": true, "planned_hours": 24, "odp": {"function_scope": "essential", "resumption_hours": 48}},
		"critical_assets": {"critical_asset_count": 12, "all_in_scope_functions_mapped": true, "odp": {"function_scope": "essential"}},
		"capacity_planning": {"processing_capacity_planned": true, "telecommunications_capacity_planned": true, "environmental_support_planned": true},
		"continuity": {"covers_all_in_scope_functions": true, "sustained_until_full_restoration": true, "odp": {"function_scope": "essential"}},
	},
	"contingency_training": {
		"training_on_system_changes": true,
		"max_days_to_initial_training": 10,
		"odp": {"initial_training_days": 30},
		"refresher": _freq(300, 365),
		"content_update": _freq(100, 365),
		"simulated_events": {"included_in_last_training": true},
	},
	"plan_testing": object.union(
		{
			"defined_tests_used": true, "results_reviewed": true, "corrective_actions_initiated": true,
			"coordination": {"related_plans": [{"name": "COOP", "coordinated": true}]},
			"alternate_processing_site": {"tested_at_site": true, "personnel_familiarized": true, "capabilities_evaluated": true},
		},
		_freq(200, 365),
	),
	"alternate_storage_site": {
		"established": true,
		"agreements_in_place": true,
		"equivalent_controls": true,
		"separation": {"threats_assessed": true, "sufficiently_separated": true},
		"accessibility": {"problems_identified": true, "mitigation_actions_outlined": true},
		"recovery_objectives": {
			"replication_lag_minutes": 10, "retrieval_hours": 4,
			"odp": {"recovery_point_objective_minutes": 15, "recovery_time_objective_hours": 12},
		},
	},
	"alternate_processing_site": {
		"established": true,
		"agreements_in_place": true,
		"equipment_and_supplies_available_or_contracted": true,
		"equivalent_controls": true,
		"resumption_hours": 8,
		"odp": {"resumption_hours": 12},
		"separation": {"threats_assessed": true, "sufficiently_separated": true},
		"accessibility": {"problems_identified": true, "mitigation_actions_outlined": true},
		"priority_of_service": {"provisions_in_agreements": true, "restoration_hours": 4, "odp": {"recovery_time_objective_hours": 12}},
		"preparation": {"configured_for_operations": true, "failover_verified": true},
	},
	"telecommunications": {
		"alternate_services_established": true,
		"agreements_in_place": true,
		"resumption_hours": 4,
		"odp": {"resumption_hours": 12},
		"priority_of_service": {
			"primary_agreement_provisions": true,
			"alternate_agreement_provisions": true,
			"restoration_hours": 2,
			"odp": {"recovery_time_objective_hours": 12},
			"common_carrier_for_nsep": true,
			"tsp_requested": true,
		},
		"single_point_of_failure": {"diversity_assessed": true, "shared_points_of_failure": []},
		"provider_separation": {"primary_providers": ["CarrierA"], "alternate_providers": ["CarrierB"], "shared_threats_assessed": true},
		"provider_contingency_plans": {
			"all_providers_have_plans": true, "plans_reviewed_against_requirements": true,
			"testing_evidence": _freq(100, 365),
		},
	},
	"backup": {
		"confidentiality_protected": true,
		"integrity_protected": true,
		"availability_protected": true,
		"user_level": _freq(1, 1),
		"system_level": _freq(3, 7),
		"documentation": _freq(10, 30),
		"testing": object.union({"last_test_verified": true}, _freq(20, 30)),
		"cryptographic_protection": {"unencrypted_backup_sets": 0, "sets_without_cryptographic_integrity": 0},
		"sampled_restoration": {"used_in_last_plan_test": true, "functions_restored": 3},
		"separate_storage": {"critical_sets_collocated": 0},
		"transfer_to_alternate_site": {"hours_since_last_transfer": 6, "transfer_rate_mbps": 500, "odp": {"max_hours": 24, "min_transfer_rate_mbps": 100}},
	},
	"recovery": {
		"recovers_to_known_state": true,
		"recovery_hours": 6,
		"odp": {"recovery_hours": 24},
		"transaction_recovery": {"transaction_based": true, "implemented": true},
		"component_restoration": {"restore_hours": 2, "from_integrity_protected_baseline": true, "odp": {"restoration_hours": 4}},
	},
	"alternate_communications_protocols": {"attestation": _att},
	"safe_mode": {"enters_on_defined_conditions": true, "defined_restrictions_applied": true},
	"alternative_security_mechanisms": {"attestation": _att},
}}

test_all_pass_fixture_is_compliant if {
	fx := _pass
	r := cp.compliance_report with input as fx
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_the_catalog if {
	cp.evaluated_controls == {
		"CP-1", "CP-2", "CP-2(1)", "CP-2(2)", "CP-2(3)", "CP-2(5)", "CP-2(8)", "CP-3", "CP-3(1)", "CP-4", "CP-4(1)",
		"CP-4(2)", "CP-6", "CP-6(1)", "CP-6(2)", "CP-6(3)", "CP-7", "CP-7(1)", "CP-7(2)", "CP-7(3)", "CP-7(4)", "CP-8",
		"CP-8(1)", "CP-8(2)", "CP-8(3)", "CP-8(4)", "CP-9", "CP-9(1)", "CP-9(2)", "CP-9(3)", "CP-9(5)", "CP-9(8)",
		"CP-10", "CP-10(2)", "CP-10(4)", "CP-11", "CP-12", "CP-13",
	}
	count(cp.evaluated_controls) == 38
}

test_empty_input_one_finding_per_control if {
	r := cp.compliance_report with input as {}
	r.compliant == false
	count(r.violations) == count(cp.evaluated_controls)
	_ids(r) == cp.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# --- each control: one failing case flips exactly that id -------------------------------------------------------

test_cp1_no_official_flips_only_cp1 if {
	fx := object.union(_pass, {"cp_controls": {"policy_procedures": {"official_designated": false}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-1"}
}

test_cp2_plan_review_overdue_flips_only_cp2 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"review": {"days_since_last": 400}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2"}
	contains(concat("", r.violations), "contingency plan last reviewed 400 days ago")
}

test_cp3_late_initial_training_flips_only_cp3 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_training": {"max_days_to_initial_training": 45}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-3"}
	contains(concat("", r.violations), "up to 45 days after a role was assumed")
}

test_cp4_results_not_reviewed_flips_only_cp4 if {
	fx := object.union(_pass, {"cp_controls": {"plan_testing": {"results_reviewed": false}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-4"}
}

test_cp6_no_equivalent_controls_flips_only_cp6 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_storage_site": {"equivalent_controls": false}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-6"}
}

test_cp7_slow_resumption_flips_only_cp7 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_processing_site": {"resumption_hours": 48}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7"}
	contains(concat("", r.violations), "48 hours; the organization-defined period is 12 hours")
}

test_cp8_no_agreements_flips_only_cp8 if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"agreements_in_place": false}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8"}
}

test_cp9_overdue_backups_share_one_finding if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"user_level": {"days_since_last": 2}, "documentation": {"days_since_last": 60}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9"}
	count(r.violations) == 1
	msg := concat("", r.violations)
	contains(msg, "backup of user-level information last taken 2 days ago")
	contains(msg, "backup of system documentation last taken 60 days ago")
}

test_cp10_slow_recovery_flips_only_cp10 if {
	fx := object.union(_pass, {"cp_controls": {"recovery": {"recovery_hours": 30}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-10"}
}

test_cp11_missing_attestation_flips_only_cp11 if {
	fx := json.remove(_pass, ["cp_controls/alternate_communications_protocols/attestation"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-11"}
	msg := concat("", r.violations)
	contains(msg, "evidence missing")
	contains(msg, "no machine-checkable evidence")
}

test_cp12_restrictions_not_applied_flips_only_cp12 if {
	fx := object.union(_pass, {"cp_controls": {"safe_mode": {"defined_restrictions_applied": false}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-12"}
}

test_cp13_unattested_flips_only_cp13 if {
	fx := object.union(_pass, {"cp_controls": {"alternative_security_mechanisms": {"attestation": {"attested": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-13"}
	contains(concat("", r.violations), "is not a complete attestation")
}

# --- attestation shape ------------------------------------------------------------------------------------------

test_attestation_with_empty_by_is_a_finding if {
	fx := object.union(_pass, {"cp_controls": {"alternate_communications_protocols": {"attestation": {"by": "  "}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-11"}
}

test_attestation_with_string_true_is_a_finding if {
	fx := object.union(_pass, {"cp_controls": {"alternative_security_mechanisms": {"attestation": {"attested": "true"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-13"}
}

test_attestation_missing_date_is_a_finding if {
	fx := json.remove(_pass, ["cp_controls/alternative_security_mechanisms/attestation/date"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-13"}
}

test_attestation_as_boolean_is_a_finding if {
	fx := object.union(_pass, {"cp_controls": {"alternate_communications_protocols": {"attestation": true}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-11"}
}

# --- type traps -------------------------------------------------------------------------------------------------

test_numeric_fact_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"recovery": {"recovery_hours": "1"}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-10"}
	msg := concat("", r.violations)
	contains(msg, "evidence missing")
	contains(msg, "recovery.recovery_hours")
}

test_numeric_fact_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"system_level": {"days_since_last": null}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.backup.system_level.days_since_last")
}

test_boolean_as_string_true_is_a_finding if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"integrity_protected": "true"}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9"}
	contains(concat("", r.violations), "integrity_protected is not true")
}

# --- enhancements: one failing case flips exactly that id, one evidence-missing case ---------------------------

test_cp2_1_uncoordinated_plan_flips_only_cp2_1 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"coordination": {"related_plans": [{"name": "COOP", "coordinated": true}, {"name": "IRP", "coordinated": false}]}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(1)"}
	contains(concat("", r.violations), "related plan IRP")
}

test_cp2_1_empty_register_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"coordination": {"related_plans": []}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp2_3_slow_resumption_flips_only_cp2_3 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"resumption": {"planned_hours": 72}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(3)"}
	contains(concat("", r.violations), "up to 72 hours after plan activation; the organization-defined period is 48 hours")
}

test_cp2_3_missing_odp_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/contingency_plan/resumption/odp/resumption_hours"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(3)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.contingency_plan.resumption.odp.resumption_hours")
}

test_cp2_3_unknown_scope_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"resumption": {"odp": {"function_scope": "some"}}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(3)"}
	contains(concat("", r.violations), "odp.function_scope")
}

test_cp2_8_no_critical_assets_flips_only_cp2_8 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"critical_assets": {"critical_asset_count": 0}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(8)"}
	contains(concat("", r.violations), "no critical system assets identified")
}

test_cp2_8_count_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"critical_assets": {"critical_asset_count": "1"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(8)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.contingency_plan.critical_assets.critical_asset_count")
}

test_cp4_1_uncoordinated_testing_flips_only_cp4_1 if {
	fx := object.union(_pass, {"cp_controls": {"plan_testing": {"coordination": {"related_plans": [{"name": "COOP"}]}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-4(1)"}
	contains(concat("", r.violations), "contingency plan testing not coordinated")
}

test_cp4_1_missing_register_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/plan_testing/coordination"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-4(1)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.plan_testing.coordination.related_plans")
}

test_cp6_1_not_separated_flips_only_cp6_1 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_storage_site": {"separation": {"sufficiently_separated": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-6(1)"}
}

test_cp6_1_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/alternate_storage_site/separation"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-6(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp6_3_no_mitigation_flips_only_cp6_3 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_storage_site": {"accessibility": {"mitigation_actions_outlined": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-6(3)"}
}

test_cp6_3_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/alternate_storage_site/accessibility/problems_identified"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-6(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp7_1_not_assessed_flips_only_cp7_1 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_processing_site": {"separation": {"threats_assessed": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(1)"}
}

test_cp7_1_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/alternate_processing_site/separation"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp7_2_problems_not_identified_flips_only_cp7_2 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_processing_site": {"accessibility": {"problems_identified": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(2)"}
}

test_cp7_2_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/alternate_processing_site/accessibility"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp7_3_restoration_beyond_rto_flips_only_cp7_3 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_processing_site": {"priority_of_service": {"restoration_hours": 24}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(3)"}
	contains(concat("", r.violations), "priority restoration in 24 hours; the organization-defined recovery time objective is 12 hours")
}

test_cp7_3_null_restoration_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"alternate_processing_site": {"priority_of_service": {"restoration_hours": null}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp8_1_tsp_not_requested_flips_only_cp8_1 if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"priority_of_service": {"tsp_requested": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(1)"}
	contains(concat("", r.violations), "Telecommunications Service Priority not requested")
}

test_cp8_1_no_common_carrier_needs_no_tsp if {
	fx := json.remove(
		object.union(_pass, {"cp_controls": {"telecommunications": {"priority_of_service": {"common_carrier_for_nsep": false}}}}),
		["cp_controls/telecommunications/priority_of_service/tsp_requested"],
	)
	r := cp.compliance_report with input as fx
	r.violation_count == 0
}

test_cp8_1_common_carrier_without_tsp_fact_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/telecommunications/priority_of_service/tsp_requested"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(1)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.telecommunications.priority_of_service.tsp_requested")
}

test_cp8_1_carrier_flag_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"priority_of_service": {"common_carrier_for_nsep": "true"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp8_2_shared_point_flips_only_cp8_2 if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"single_point_of_failure": {"shared_points_of_failure": ["central office CO-7"]}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(2)"}
	contains(concat("", r.violations), "central office CO-7")
}

test_cp8_2_list_not_an_array_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"single_point_of_failure": {"shared_points_of_failure": "none"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp9_1_overdue_backup_test_flips_only_cp9_1 if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"testing": {"days_since_last": 45}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(1)"}
	contains(concat("", r.violations), "backup information last tested 45 days ago")
}

test_cp9_1_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/backup/testing"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp9_8_unencrypted_sets_flip_only_cp9_8 if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"cryptographic_protection": {"unencrypted_backup_sets": 3}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(8)"}
	contains(concat("", r.violations), "3 backup sets not encrypted")
}

test_cp9_8_count_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"cryptographic_protection": {"sets_without_cryptographic_integrity": "0"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(8)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp10_2_not_implemented_flips_only_cp10_2 if {
	fx := object.union(_pass, {"cp_controls": {"recovery": {"transaction_recovery": {"implemented": "true"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-10(2)"}
	contains(concat("", r.violations), "implemented is not true")
}

test_cp10_2_not_transaction_based_passes if {
	fx := json.remove(
		object.union(_pass, {"cp_controls": {"recovery": {"transaction_recovery": {"transaction_based": false}}}}),
		["cp_controls/recovery/transaction_recovery/implemented"],
	)
	r := cp.compliance_report with input as fx
	r.violation_count == 0
}

test_cp10_2_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/recovery/transaction_recovery"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-10(2)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.recovery.transaction_recovery.transaction_based")
}

# A base control never fails for an enhancement: removing every enhancement fact leaves the base controls passing.
test_base_controls_ignore_enhancement_facts if {
	fx := json.remove(_pass, [
		"cp_controls/contingency_plan/coordination", "cp_controls/contingency_plan/resumption",
		"cp_controls/contingency_plan/critical_assets", "cp_controls/plan_testing/coordination",
		"cp_controls/alternate_storage_site/separation", "cp_controls/alternate_storage_site/accessibility",
		"cp_controls/alternate_processing_site/separation", "cp_controls/alternate_processing_site/accessibility",
		"cp_controls/alternate_processing_site/priority_of_service", "cp_controls/telecommunications/priority_of_service",
		"cp_controls/telecommunications/single_point_of_failure", "cp_controls/backup/testing",
		"cp_controls/backup/cryptographic_protection", "cp_controls/recovery/transaction_recovery",
		"cp_controls/contingency_plan/capacity_planning", "cp_controls/contingency_plan/continuity",
		"cp_controls/contingency_training/simulated_events", "cp_controls/plan_testing/alternate_processing_site",
		"cp_controls/alternate_storage_site/recovery_objectives", "cp_controls/alternate_processing_site/preparation",
		"cp_controls/telecommunications/provider_separation", "cp_controls/telecommunications/provider_contingency_plans",
		"cp_controls/backup/sampled_restoration", "cp_controls/backup/separate_storage",
		"cp_controls/backup/transfer_to_alternate_site", "cp_controls/recovery/component_restoration",
	])
	r := cp.compliance_report with input as fx
	_ids(r) == {id | some id in cp.evaluated_controls; contains(id, "(")}
}

# --- High-baseline enhancements: one failing case flips exactly that id, one evidence-missing case --------------

test_cp2_2_no_telecom_capacity_flips_only_cp2_2 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"capacity_planning": {"telecommunications_capacity_planned": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(2)"}
}

test_cp2_2_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/contingency_plan/capacity_planning"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp2_5_not_sustained_flips_only_cp2_5 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"continuity": {"sustained_until_full_restoration": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(5)"}
}

test_cp2_5_unknown_scope_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"contingency_plan": {"continuity": {"odp": {"function_scope": "most"}}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-2(5)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp3_1_no_simulation_flips_only_cp3_1 if {
	fx := object.union(_pass, {"cp_controls": {"contingency_training": {"simulated_events": {"included_in_last_training": false}}}})
	r := cp.compliance_report with input as fx
	r.violations == {"NIST CP-3(1): contingency training does not incorporate simulated events (input.cp_controls.contingency_training.simulated_events.included_in_last_training is not true)"}
}

test_cp3_1_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/contingency_training/simulated_events"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-3(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp4_2_not_tested_at_site_flips_only_cp4_2 if {
	fx := object.union(_pass, {"cp_controls": {"plan_testing": {"alternate_processing_site": {"tested_at_site": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-4(2)"}
}

test_cp4_2_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/plan_testing/alternate_processing_site/capabilities_evaluated"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-4(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp6_2_rpo_exceeded_flips_only_cp6_2 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_storage_site": {"recovery_objectives": {"replication_lag_minutes": 60}}}})
	r := cp.compliance_report with input as fx
	r.violations == {"NIST CP-6(2): data at the alternate storage site lags by up to 60 minutes; the recovery point objective is 15 minutes"}
}

test_cp6_2_lag_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"alternate_storage_site": {"recovery_objectives": {"replication_lag_minutes": "1"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-6(2)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.alternate_storage_site.recovery_objectives.replication_lag_minutes")
}

test_cp7_4_failover_not_verified_flips_only_cp7_4 if {
	fx := object.union(_pass, {"cp_controls": {"alternate_processing_site": {"preparation": {"failover_verified": false}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(4)"}
}

test_cp7_4_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/alternate_processing_site/preparation"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-7(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp8_3_same_provider_flips_only_cp8_3 if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"provider_separation": {"alternate_providers": ["CarrierA", "CarrierC"]}}}})
	r := cp.compliance_report with input as fx
	r.violations == {"NIST CP-8(3): alternate telecommunications obtained from a primary provider: CarrierA"}
}

test_cp8_3_empty_list_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"provider_separation": {"primary_providers": []}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp8_4_stale_provider_evidence_flips_only_cp8_4 if {
	fx := object.union(_pass, {"cp_controls": {"telecommunications": {"provider_contingency_plans": {"testing_evidence": {"days_since_last": 500}}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(4)"}
	contains(concat("", r.violations), "last obtained 500 days ago")
}

test_cp8_4_missing_odp_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/telecommunications/provider_contingency_plans/testing_evidence/odp"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-8(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp9_2_no_functions_restored_flips_only_cp9_2 if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"sampled_restoration": {"functions_restored": 0}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(2)"}
}

test_cp9_2_count_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"sampled_restoration": {"functions_restored": null}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(2)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp9_3_collocated_sets_flip_only_cp9_3 if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"separate_storage": {"critical_sets_collocated": 2}}}})
	r := cp.compliance_report with input as fx
	r.violations == {"NIST CP-9(3): 2 critical backup sets not stored separately from the operational system"}
}

test_cp9_3_count_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"separate_storage": {"critical_sets_collocated": "0"}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_cp9_5_slow_transfer_rate_flips_only_cp9_5 if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"transfer_to_alternate_site": {"transfer_rate_mbps": 50}}}})
	r := cp.compliance_report with input as fx
	r.violations == {"NIST CP-9(5): backup transfer to the alternate storage site ran at 50 Mbps; the organization-defined rate is 100 Mbps"}
}

test_cp9_5_overdue_transfer_flips_only_cp9_5 if {
	fx := object.union(_pass, {"cp_controls": {"backup": {"transfer_to_alternate_site": {"hours_since_last_transfer": 30}}}})
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(5)"}
}

test_cp9_5_missing_rate_odp_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/backup/transfer_to_alternate_site/odp/min_transfer_rate_mbps"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-9(5)"}
	contains(concat("", r.violations), "evidence missing — input.cp_controls.backup.transfer_to_alternate_site.odp.min_transfer_rate_mbps")
}

test_cp10_4_slow_restore_flips_only_cp10_4 if {
	fx := object.union(_pass, {"cp_controls": {"recovery": {"component_restoration": {"restore_hours": 8}}}})
	r := cp.compliance_report with input as fx
	r.violations == {"NIST CP-10(4): system components restored in up to 8 hours; the organization-defined restoration period is 4 hours"}
}

test_cp10_4_missing_is_evidence_missing if {
	fx := json.remove(_pass, ["cp_controls/recovery/component_restoration"])
	r := cp.compliance_report with input as fx
	_ids(r) == {"CP-10(4)"}
	contains(concat("", r.violations), "evidence missing")
}
