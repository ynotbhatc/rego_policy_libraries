# Count contract for the DORA reports (weekly audit 2026-11-23, "DORA miscounts"): totals come from the checks
# evaluated for the entity's scope, failed_controls is computed, and passed + failed == total on every input.

package dora.counts_test

import rego.v1

import data.dora.main
import data.dora.rts_ict_risk
import data.dora.rts_subcontracting
import data.dora.rts_tlpt

# ── fixtures ────────────────────────────────────────────────────────────────

_level1_pass := {
	"ict_risk_management": {
		"governance_framework": {"documented": true},
		"risk_appetite": {"defined": true},
		"asset_inventory": {"maintained": true},
		"threat_intelligence": {"process_exists": true},
		"recovery_objectives": {"rto_defined": true, "rpo_defined": true},
		"backup_policy": {"documented": true},
		"patch_management": {"process_exists": true},
		"encryption": {"in_transit": true, "at_rest": true},
		"mfa": {"enabled": true},
		"privileged_access": {"managed": true},
		"annual_review": {"completed": true},
	},
	"incident_reporting": {
		"classification_process": {"documented": true},
		"initial_notification": {"within_4_hours": true},
		"intermediate_report": {"within_72_hours": true},
		"final_report": {"within_1_month": true},
		"incident_register": {"maintained": true},
		"root_cause_analysis": {"performed": true},
	},
	"resilience_testing": {
		"basic_testing": {"annual": true},
		"tlpt": {"conducted": true},
		"test_results": {"remediated": true},
		"continuity_drills": {"conducted": true},
	},
	"third_party_risk": {
		"register": {"maintained": true},
		"contracts": {"exit_strategy": true, "audit_rights": true, "sla_defined": true},
		"concentration_risk": {"assessed": true},
		"critical_providers": {"identified": true},
		"due_diligence": {"performed": true},
	},
	"information_sharing": {"arrangements": {"in_place": true}},
}

_rows_all := {id: true | some id, _ in rts_ict_risk.obligations}

_roles(ccp, csd, venue, micro) := {
	"central_counterparty": ccp,
	"central_securities_depository": csd,
	"trading_venue": venue,
	"microenterprise": micro,
}

_rts(gate_and_roles, obligations) := {"dora": {"rts": object.union(gate_and_roles, {"obligations": obligations})}}

_title_ii_all_roles := object.union(_roles(true, true, true, false), {"simplified_framework": false})

_title_ii_no_roles := object.union(_roles(false, false, false, false), {"simplified_framework": false})

# Title II, every role flag set, nothing attested anywhere: the auditor's "fully failing Title II" input.
_fully_failing_title_ii := _rts(_title_ii_all_roles, {})

_fully_failing_title_iii := _rts({"simplified_framework": true}, {})

# Level-1 all true, Title II rows all true except three, the two small RTS modules untouched (all fail).
_mixed := object.union(
	_level1_pass,
	_rts(_title_ii_no_roles, object.union(_rows_all, {"Art.7(2)": false, "Art.3(1)(a)": "true", "Art.21(1)(f)": null})),
)

_inputs := {
	"empty": {},
	"fully_failing_title_ii": _fully_failing_title_ii,
	"fully_failing_title_iii": _fully_failing_title_iii,
	"mixed": _mixed,
	"level1_only_pass": _level1_pass,
	"wrong_types": {"ict_risk_management": {"mfa": {"enabled": null}, "encryption": {"at_rest": "false", "in_transit": 0}}},
	"unknown_ids": _rts(_title_ii_no_roles, object.union(_rows_all, {"Art.99(1)": true, "Art.98(1)": true, "Art.97(1)": true})),
}

_invariant(r) if {
	is_number(r.total_controls)
	r.passed_controls >= 0
	r.failed_controls >= 0
	r.passed_controls + r.failed_controls == r.total_controls
}

# ── the invariant, on every report and every input ──────────────────────────

test_main_passed_plus_failed_is_total_on_every_input if {
	every _, inp in _inputs {
		r := main.compliance_report with input as inp
		_invariant(r)
		r.violation_count == r.failed_controls + r.input_contract_violations
		r.violation_count == count(r.violations)
	}
}

test_module_reports_passed_plus_failed_is_total_on_every_input if {
	every _, inp in _inputs {
		_invariant(rts_subcontracting.compliance_report) with input as inp
		_invariant(rts_tlpt.compliance_report) with input as inp
		_invariant(rts_ict_risk.compliance_report) with input as inp
	}
}

test_main_total_is_the_sum_of_its_parts_on_every_input if {
	every _, inp in _inputs {
		r := main.compliance_report with input as inp
		parts := r.control_summary
		r.total_controls == sum([p.total_controls | some p in parts])
		r.failed_controls == sum([p.failed_controls | some p in parts])
		r.passed_controls == sum([p.passed_controls | some p in parts])
		l1 := parts.level_1_regulation_2022_2554
		l1.total_controls == sum([p.total_controls | some p in l1.pillars])
		l1.failed_controls == sum([p.failed_controls | some p in l1.pillars])
	}
}

# ── the audit finding: three scopes, three totals ───────────────────────────

test_empty_input_counts if {
	r := main.compliance_report with input as {}

	# 31 Level-1 + 30 + 31 + 208 Title II rows (no role declared, microenterprise not declared true)
	r.total_controls == 300
	r.failed_controls == 300
	r.passed_controls == 0
	r.compliance_score == 0
	r.input_contract_violations == 6
	r.violation_count == 306
	r.compliant == false
}

test_fully_failing_title_ii_fails_every_control if {
	r := main.compliance_report with input as _fully_failing_title_ii

	# before: total_controls 399 against 320 findings, so 79 controls read as passed with nothing attested
	r.total_controls == 320
	r.failed_controls == 320
	r.passed_controls == 0
	r.compliance_score == 0
	r.input_contract_violations == 0
	r.control_summary.rts_2024_1774_ict_risk_management.total_controls == 228
	r.control_summary.rts_2024_1774_ict_risk_management.title_evaluated == "II"
}

test_fully_failing_title_iii_fails_every_control if {
	r := main.compliance_report with input as _fully_failing_title_iii
	r.total_controls == 172 # 92 + the 80 Title III rows; Title II's 228 are not in scope
	r.failed_controls == 172
	r.passed_controls == 0
	r.control_summary.rts_2024_1774_ict_risk_management.total_controls == 80
	r.control_summary.rts_2024_1774_ict_risk_management.title_evaluated == "III"
}

test_mixed_input_counts if {
	r := main.compliance_report with input as _mixed
	r.total_controls == 300 # 31 + 30 + 31 + 208
	r.failed_controls == 64 # 0 Level-1, 30 + 31 RTS, 3 Title II rows (false, "true", null)
	r.passed_controls == 236
	r.compliance_score == 78 # floor(23600 / 300)
	r.control_summary.level_1_regulation_2022_2554.failed_controls == 0
	r.control_summary.rts_2024_1774_ict_risk_management.failed_controls == 3
	r.compliant == false
}

test_score_is_100_only_when_everything_evaluated_passes if {
	sub := {"third_party_risk": {"subcontracting": {
		"risk_assessment": {"covers_chain_complexity": true, "periodic_review_performed": true, "independent_of_provider": true},
		"group_consistency": {"ensured": true},
		"permissibility_decision": {"documented": true},
		"due_diligence": {
			"provider_vetting_capability_verified": true, "full_chain_identified": true,
			"regulatory_compliance_enabled": true, "access_rights_parity_verified": true,
			"provider_monitoring_capacity_verified": true, "entity_monitoring_capacity_verified": true,
			"failure_impact_assessed": true, "location_risk_assessed": true, "concentration_risk_assessed": true,
			"supervisory_access_obstacles_assessed": true,
		},
		"contract": {
			"eligible_services_specified": true, "provider_responsibility_clause": true,
			"monitoring_reporting_obligations": true, "data_location_specified": true, "flow_down_obligations": true,
			"chain_continuity_required": true, "security_standards_specified": true, "audit_rights_flow_down": true,
			"material_change_notification_clause": true, "termination_rights_clause": true,
			"remediation_timeline_documented": true,
		},
		"material_changes": {
			"notice_period_defined": true, "approval_before_implementation": true,
			"risk_tolerance_objection_process": true,
		},
		"termination": {"triggers_defined": true},
	}}}
	tlpt := {"resilience_testing": {"tlpt": {
		"scope_determination": {"performed": true},
		"organisation": {"control_team_lead_appointed": true, "secrecy_controls_established": true},
		"risk_management": {"live_system_risk_assessed": true, "pooled_joint_assessed": true},
		"providers": {
			"selection_evidence_collected": true, "ti_team_requirements_met": true, "red_team_requirements_met": true,
			"restoration_procedures_agreed": true, "prohibited_activities_defined": true, "compliance_documented": true,
		},
		"preparation": {
			"initiation_submitted_3_months": true, "control_team_established": true,
			"scope_spec_approved_by_board": true, "providers_contracted_before_testing": true,
		},
		"threat_intelligence": {
			"targeted_scenarios_produced": true, "min_three_scenarios_selected": true, "report_approved": true,
		},
		"red_team": {
			"test_plan_approved": true, "active_phase_min_12_weeks": true, "weekly_reporting": true,
			"legup_and_suspension_procedures": true,
		},
		"closure": {
			"red_team_report_4_weeks": true, "blue_team_report_10_weeks": true, "purple_teaming_conducted": true,
			"summary_report_8_weeks": true,
		},
		"remediation": {"plan_submitted_8_weeks": true},
		"attestation": {"obtained": true},
		"internal_testers": {"policy_established": true, "authority_approved_and_disclosed": true},
		"frequency": {"three_year_cycle_met": true},
	}}}
	all_pass := object.union(object.union(object.union(_level1_pass, sub), tlpt), _rts(_title_ii_no_roles, _rows_all))
	r := main.compliance_report with input as all_pass
	r.compliant == true
	r.total_controls == 300
	r.passed_controls == 300
	r.failed_controls == 0
	r.compliance_score == 100

	# one row short of everything: not 100
	one_short := object.union(all_pass, _rts(_title_ii_no_roles, object.union(_rows_all, {"Art.7(2)": false})))
	r2 := main.compliance_report with input as one_short
	r2.failed_controls == 1
	r2.compliance_score == 99
	r2.compliant == false
}

# Findings about the input are not controls: three unknown ids leave total and failed where they were.
test_input_contract_findings_are_not_controls if {
	r := main.compliance_report with input as _inputs.unknown_ids
	r.input_contract_violations == 3
	r.control_summary.rts_2024_1774_ict_risk_management.failed_controls == 0
	r.control_summary.rts_2024_1774_ict_risk_management.total_controls == 208
	r.compliant == false
}

# ── stated totals equal the rules implemented ───────────────────────────────

# Every check needs boolean true, so every rule fires on an empty input: the failing count there is the
# number of rules. A rule added, removed or moved to another article without the totals following fails here.
test_level1_totals_equal_the_rules_implemented if {
	pv := main.pillar_violations with input as {}
	every pillar, n in main.pillar_totals {
		count(pv[pillar]) == n
	}
	object.keys(main.pillar_totals) == object.keys(main.pillar_articles)
	l1 := main.level1_failed_checks with input as {}
	count(l1) == main.level1_total
	main.level1_total == 31
}

# Every Level-1 message sits in exactly one pillar (an article missing from pillar_articles would drop it).
test_every_level1_violation_is_in_exactly_one_pillar if {
	l1 := main.level1_failed_checks with input as {}
	pv := main.pillar_violations with input as {}
	every v in l1 {
		count([p | some p, vs in pv; v in vs]) == 1
	}
}

test_rts_module_totals_equal_the_rules_implemented if {
	count(rts_subcontracting.violation) == rts_subcontracting.total_controls with input as {}
	count(rts_tlpt.violation) == rts_tlpt.total_controls with input as {}
	rts_subcontracting.total_controls == 30
	rts_tlpt.total_controls == 31
}

test_rts_2024_1774_total_is_the_applicable_rows_not_the_rows_carried if {
	r2 := rts_ict_risk.compliance_report with input as _fully_failing_title_ii
	r2.total_controls == 228
	r2.rows_carried == 308
	r3 := rts_ict_risk.compliance_report with input as _fully_failing_title_iii
	r3.total_controls == 80
	r3.rows_carried == 308
	every _, inp in _inputs {
		r := rts_ict_risk.compliance_report with input as inp
		r.total_controls == r.controls_evaluated
		r.violation_count == r.failed_controls + r.input_contract_violations
	}
}

# ── evidence typing ─────────────────────────────────────────────────────────

# null, "false" and 0 used to pass the Level-1 checks (`not input.x` is false for any defined value but false).
test_level1_null_string_and_number_are_not_evidence if {
	v := main.violations with input as _inputs.wrong_types
	"DORA Art.9: Multi-factor authentication not enforced for ICT system access" in v
	"DORA Art.9: Data at rest not encrypted — encryption of sensitive data required" in v
	"DORA Art.9: Data in transit not encrypted — encryption of sensitive data required" in v
	r := main.compliance_report with input as _inputs.wrong_types
	r.control_summary.level_1_regulation_2022_2554.failed_controls == 31
}

test_level1_string_true_is_not_evidence if {
	inp := object.union(_level1_pass, {"information_sharing": {"arrangements": {"in_place": "true"}}})
	r := main.compliance_report with input as inp
	r.control_summary.level_1_regulation_2022_2554.failed_controls == 1
	count(r.pillar_summary.information_sharing) == 1
}

test_level1_all_true_passes_every_level1_check if {
	r := main.compliance_report with input as _level1_pass
	r.control_summary.level_1_regulation_2022_2554 == {
		"total_controls": 31,
		"failed_controls": 0,
		"passed_controls": 31,
		"pillars": {
			"ict_risk_management": {"total_controls": 14, "failed_controls": 0, "passed_controls": 14},
			"incident_reporting": {"total_controls": 6, "failed_controls": 0, "passed_controls": 6},
			"resilience_testing": {"total_controls": 3, "failed_controls": 0, "passed_controls": 3},
			"third_party_risk": {"total_controls": 7, "failed_controls": 0, "passed_controls": 7},
			"information_sharing": {"total_controls": 1, "failed_controls": 0, "passed_controls": 1},
		},
	}
}

# An undeclared microenterprise flag is not an exemption: the two "other than microenterprises" points stay open.
test_microenterprise_exemption_needs_explicit_true if {
	base := {"simplified_framework": false, "central_counterparty": false, "central_securities_depository": false, "trading_venue": false}
	undeclared := rts_ict_risk.compliance_report with input as _rts(base, {})
	undeclared.total_controls == 208
	as_string := rts_ict_risk.compliance_report with input as _rts(object.union(base, {"microenterprise": "true"}), {})
	as_string.total_controls == 208
	declared := rts_ict_risk.compliance_report with input as _rts(object.union(base, {"microenterprise": true}), {})
	declared.total_controls == 206
}

# ── citations corrected against Regulation (EU) 2022/2554 ───────────────────

test_citations_and_pillars_after_correction if {
	r := main.compliance_report with input as {}
	p1 := r.pillar_summary.ict_risk_management
	p3 := r.pillar_summary.resilience_testing

	# patches and updates: Art.9(4)(f), not Art.10 (detection)
	"DORA Art.9: Documented policies for patches and updates not established (Art.9(4)(f))" in p1

	# continuity and crisis-communication plan tests: Art.11(6), Chapter II, so pillar 1
	"DORA Art.11: ICT business continuity plan tests and crisis communication plan tests not conducted (Art.11(6))" in p1
	count(p1) == 14
	count(p3) == 3
	every v in r.violations {
		not startswith(v, "DORA Art.10:")
		not startswith(v, "DORA Art.25:")
	}
}
