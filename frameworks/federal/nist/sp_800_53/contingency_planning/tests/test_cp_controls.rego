package nist.sp800_53.contingency_planning_logic_test

# CP family: one finding per base control, fail closed, organization-defined frequencies and periods,
# attestations for CP-11 and CP-13.

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
	},
	"contingency_training": {
		"training_on_system_changes": true,
		"max_days_to_initial_training": 10,
		"odp": {"initial_training_days": 30},
		"refresher": _freq(300, 365),
		"content_update": _freq(100, 365),
	},
	"plan_testing": object.union(
		{"defined_tests_used": true, "results_reviewed": true, "corrective_actions_initiated": true},
		_freq(200, 365),
	),
	"alternate_storage_site": {"established": true, "agreements_in_place": true, "equivalent_controls": true},
	"alternate_processing_site": {
		"established": true,
		"agreements_in_place": true,
		"equipment_and_supplies_available_or_contracted": true,
		"equivalent_controls": true,
		"resumption_hours": 8,
		"odp": {"resumption_hours": 12},
	},
	"telecommunications": {
		"alternate_services_established": true,
		"agreements_in_place": true,
		"resumption_hours": 4,
		"odp": {"resumption_hours": 12},
	},
	"backup": {
		"confidentiality_protected": true,
		"integrity_protected": true,
		"availability_protected": true,
		"user_level": _freq(1, 1),
		"system_level": _freq(3, 7),
		"documentation": _freq(10, 30),
	},
	"recovery": {"recovers_to_known_state": true, "recovery_hours": 6, "odp": {"recovery_hours": 24}},
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
	cp.evaluated_controls == {"CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-7", "CP-8", "CP-9", "CP-10", "CP-11", "CP-12", "CP-13"}
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
