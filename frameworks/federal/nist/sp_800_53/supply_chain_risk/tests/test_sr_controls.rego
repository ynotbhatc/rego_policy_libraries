package nist.sp800_53.supply_chain_risk_logic_test

import rego.v1

# Logic tests for supply_chain_risk/sr_controls.rego. Every case states its input inline (no helper does
# `with input as`, which the wasm build rejects); each failing case changes one fact of the all-pass fixture
# and must flip exactly that control id.

_pass := {"sr_controls": {"policy": {"documented": true, "official_designated": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "procedures": {"documented": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "scrm_plan": {"documented": true, "protected": true, "days_since_last": 30, "odp": {"frequency_days": 365}, "team": {"established": true, "unfilled_roles": 0}}, "supply_chain_controls": {"weakness_process_established": true, "controls_employed": true, "documented": true}, "provenance": {"monitored": true, "components_without_provenance": 0}, "acquisition_strategies": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "supplier_assessments": {"days_since_last": 200, "odp": {"frequency_days": 365}}, "supply_chain_opsec": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "notification_agreements": {"entities_without_agreement": 0}, "tamper_protection": {"program_implemented": true, "sdlc": {"phases_without_anti_tamper": 0}}, "inspection": {"days_since_last": 20, "odp": {"frequency_days": 90}}, "anti_counterfeit": {"policy_procedures_implemented": true, "detection_prevention": true, "reporting_defined": true, "training": {"untrained_personnel": 0}, "service_repair": {"components_without_configuration_control": 0}}, "component_disposal": {"methods_defined": true, "disposals_without_approved_method": 0}}}

_flagged(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.supply_chain_risk.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.supply_chain_risk.compliance_report with input as {}
	count(r.violations) == count(data.nist.sp800_53.supply_chain_risk.evaluated_controls)
	every id in data.nist.sp800_53.supply_chain_risk.evaluated_controls {
		count(_flagged(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.supply_chain_risk.evaluated_controls == {"SR-1", "SR-2", "SR-2(1)", "SR-3", "SR-4", "SR-5", "SR-6", "SR-7", "SR-8", "SR-9", "SR-9(1)", "SR-10", "SR-11", "SR-11(1)", "SR-11(2)", "SR-12"}
}

test_sr1_policy_not_documented_fails if {
	inp := object.union(_pass, {"sr_controls": {"policy": {"documented": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-1")
	count(f) == 1
	contains(f[0], "policy not documented")
}

test_sr1_no_official_fails if {
	inp := object.union(_pass, {"sr_controls": {"policy": {"official_designated": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-1")
	count(f) == 1
	contains(f[0], "official")
}

test_sr1_procedures_review_overdue_fails if {
	inp := object.union(_pass, {"sr_controls": {"procedures": {"days_since_last": 400}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-1")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_sr1_policy_review_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"policy": {"odp": {"frequency_days": null}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr1_procedures_documented_string_fails if {
	inp := object.union(_pass, {"sr_controls": {"procedures": {"documented": "true"}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr2_plan_not_protected_fails if {
	inp := object.union(_pass, {"sr_controls": {"scrm_plan": {"protected": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-2")
	count(f) == 1
	contains(f[0], "unauthorized disclosure")
}

test_sr2_review_overdue_fails if {
	inp := object.union(_pass, {"sr_controls": {"scrm_plan": {"days_since_last": 366}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-2")
	count(f) == 1
	contains(f[0], "reviewed and updated last 366 days ago")
}

test_sr3_controls_not_employed_fails if {
	inp := object.union(_pass, {"sr_controls": {"supply_chain_controls": {"controls_employed": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-3")
	count(f) == 1
	contains(f[0], "supply chain controls")
}

test_sr4_components_without_provenance_fail if {
	inp := object.union(_pass, {"sr_controls": {"provenance": {"components_without_provenance": 7}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-4")
	count(f) == 1
	contains(f[0], "7 systems")
}

test_sr4_count_string_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"provenance": {"components_without_provenance": "1"}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-4")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr5_attestation_missing_fails if {
	inp := object.union(_pass, {"sr_controls": {"acquisition_strategies": {"attestation": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-5")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sr5_attested_string_true_fails if {
	inp := object.union(_pass, {"sr_controls": {"acquisition_strategies": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-5")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sr5_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sr_controls": {"acquisition_strategies": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-5")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sr6_assessment_overdue_fails if {
	inp := object.union(_pass, {"sr_controls": {"supplier_assessments": {"days_since_last": 400}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-6")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_sr6_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"supplier_assessments": {"days_since_last": "1"}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-6")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr6_days_null_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"supplier_assessments": {"days_since_last": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-6")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr7_attestation_missing_fails if {
	inp := object.union(_pass, {"sr_controls": {"supply_chain_opsec": {"attestation": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-7")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sr7_attested_string_true_fails if {
	inp := object.union(_pass, {"sr_controls": {"supply_chain_opsec": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-7")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sr7_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sr_controls": {"supply_chain_opsec": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-7")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sr8_entities_without_agreement_fail if {
	inp := object.union(_pass, {"sr_controls": {"notification_agreements": {"entities_without_agreement": 1}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-8")
	count(f) == 1
	contains(f[0], "1 supply chain entities")
}

test_sr8_count_null_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"notification_agreements": {"entities_without_agreement": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-8")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr9_no_tamper_program_fails if {
	inp := object.union(_pass, {"sr_controls": {"tamper_protection": {"program_implemented": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-9")
	count(f) == 1
	contains(f[0], "tamper protection program")
}

test_sr9_program_string_true_fails if {
	inp := object.union(_pass, {"sr_controls": {"tamper_protection": {"program_implemented": "true"}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-9")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr10_inspection_overdue_fails if {
	inp := object.union(_pass, {"sr_controls": {"inspection": {"days_since_last": 91}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-10")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 90")
}

test_sr10_odp_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"inspection": {"odp": {"frequency_days": "1"}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-10")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr11_no_detection_fails if {
	inp := object.union(_pass, {"sr_controls": {"anti_counterfeit": {"detection_prevention": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-11")
	count(f) == 1
	contains(f[0], "counterfeit")
}

test_sr12_unapproved_disposals_fail if {
	inp := object.union(_pass, {"sr_controls": {"component_disposal": {"disposals_without_approved_method": 2}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-12")
	count(f) == 1
	contains(f[0], "2 disposals")
}

test_sr12_methods_not_defined_fails if {
	inp := object.union(_pass, {"sr_controls": {"component_disposal": {"methods_defined": false}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-12")
	count(f) == 1
	contains(f[0], "disposal techniques")
}

# --- Moderate-baseline enhancements -------------------------------------------------------------

test_sr2_1_not_established_fails if {
	inp := object.union(_pass, {"sr_controls": {"scrm_plan": {"team": {"established": false}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-2(1)")
	count(f) == 1
	contains(f[0], "no supply chain risk management team")
}

test_sr2_1_unfilled_roles_fail if {
	inp := object.union(_pass, {"sr_controls": {"scrm_plan": {"team": {"unfilled_roles": 2}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-2(1)")
	count(f) == 1
	contains(f[0], "2 organization-defined SCRM team roles")
}

test_sr2_1_established_string_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"scrm_plan": {"team": {"established": "true"}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-2(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr11_1_untrained_fail if {
	inp := object.union(_pass, {"sr_controls": {"anti_counterfeit": {"training": {"untrained_personnel": 5}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-11(1)")
	count(f) == 1
	contains(f[0], "5 organization-defined personnel")
}

test_sr11_1_string_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"anti_counterfeit": {"training": {"untrained_personnel": "0"}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-11(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr11_1_null_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"anti_counterfeit": {"training": {"untrained_personnel": null}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-11(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sr11_2_uncontrolled_fail if {
	inp := object.union(_pass, {"sr_controls": {"anti_counterfeit": {"service_repair": {"components_without_configuration_control": 1}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-11(2)")
	count(f) == 1
	contains(f[0], "not under configuration control")
}

test_sr11_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"anti_counterfeit": {"service_repair": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-11(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_enhancement_missing_does_not_fail_base if {
	inp := object.union(_pass, {"sr_controls": {"scrm_plan": {"team": null}, "anti_counterfeit": {"training": null, "service_repair": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 3
	count(_flagged(v, "SR-2")) == 0
	count(_flagged(v, "SR-11")) == 0
}

test_sr9_1_phase_without_anti_tamper_flips_only_sr9_1 if {
	inp := object.union(_pass, {"sr_controls": {"tamper_protection": {"sdlc": {"phases_without_anti_tamper": 2}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-9(1)")
	count(f) == 1
	contains(f[0], "2 system development life cycle phases")
	not contains(f[0], "evidence missing")
}

test_sr9_1_missing_is_evidence_missing_and_base_unaffected if {
	inp := object.union(_pass, {"sr_controls": {"tamper_protection": {"sdlc": null}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SR-9(1)")
	count(f) == 1
	contains(f[0], "evidence missing — input.sr_controls.tamper_protection.sdlc.phases_without_anti_tamper")
}

test_sr9_1_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"sr_controls": {"tamper_protection": {"sdlc": {"phases_without_anti_tamper": "0"}}}})
	v := data.nist.sp800_53.supply_chain_risk.violation with input as inp
	count(v) == 1
	contains(_flagged(v, "SR-9(1)")[0], "evidence missing")
}
