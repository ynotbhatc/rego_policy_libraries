package nist.sp800_53.risk_assessment_logic_test

import rego.v1

# Logic tests for risk_assessment/ra_controls.rego. Every case states its input inline (no helper does
# `with input as`, which the wasm build rejects); each failing case changes one fact of the all-pass fixture
# and must flip exactly that control id.

_pass := {"ra_controls": {"policy": {"documented": true, "official_designated": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "procedures": {"documented": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "categorization": {"performed": true, "documented_in_security_plan": true, "approved_by_authorizing_official": true}, "risk_assessment": {"conducted": true, "results_documented": true, "results_disseminated": true, "review": {"days_since_last": 30, "odp": {"frequency_days": 365}}, "update": {"days_since_last": 30, "odp": {"frequency_days": 365}}, "supply_chain": {"performed": true, "unassessed_components": 0, "days_since_last": 100, "odp": {"frequency_days": 365}}}, "vulnerability_scanning": {"days_since_last": 7, "odp": {"frequency_days": 30}, "standards_based_tools": true, "reports_analyzed": true, "results_shared": true, "scanner_updatable": true, "overdue_remediations": 0, "vulnerability_updates": {"days_since_last": 1, "odp": {"frequency_days": 7}, "updated_before_last_scan": true}, "privileged_access": {"authorized": true, "targets_without_privileged_scan": 0}, "public_disclosure": {"channel_published": true}}, "tscm_survey": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "risk_response": {"per_risk_tolerance": true, "unaddressed_findings": 0}, "privacy_impact_assessment": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "criticality_analysis": {"performed": true, "critical_components_identified": true}, "threat_hunting": {"capability_established": true, "days_since_last": 10, "odp": {"frequency_days": 90}}}}

_flagged(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.risk_assessment.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.risk_assessment.compliance_report with input as {}
	count(r.violations) == count(data.nist.sp800_53.risk_assessment.evaluated_controls)
	every id in data.nist.sp800_53.risk_assessment.evaluated_controls {
		count(_flagged(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.risk_assessment.evaluated_controls == {"RA-1", "RA-2", "RA-3", "RA-3(1)", "RA-5", "RA-5(2)", "RA-5(5)", "RA-5(11)", "RA-6", "RA-7", "RA-8", "RA-9", "RA-10"}
}

test_ra1_policy_not_documented_fails if {
	inp := object.union(_pass, {"ra_controls": {"policy": {"documented": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-1")
	count(f) == 1
	contains(f[0], "policy not documented")
}

test_ra1_no_official_fails if {
	inp := object.union(_pass, {"ra_controls": {"policy": {"official_designated": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-1")
	count(f) == 1
	contains(f[0], "official")
}

test_ra1_procedures_review_overdue_fails if {
	inp := object.union(_pass, {"ra_controls": {"procedures": {"days_since_last": 400}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-1")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_ra1_policy_review_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"policy": {"odp": {"frequency_days": null}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra1_procedures_documented_string_fails if {
	inp := object.union(_pass, {"ra_controls": {"procedures": {"documented": "true"}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra2_not_ao_approved_fails if {
	inp := object.union(_pass, {"ra_controls": {"categorization": {"approved_by_authorizing_official": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-2")
	count(f) == 1
	contains(f[0], "authorizing official")
}

test_ra2_performed_string_true_fails if {
	inp := object.union(_pass, {"ra_controls": {"categorization": {"performed": "true"}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-2")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra3_review_overdue_fails if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"review": {"days_since_last": 366}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3")
	count(f) == 1
	contains(f[0], "reviewed last 366 days ago")
}

test_ra3_update_overdue_fails if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"update": {"days_since_last": 500}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3")
	count(f) == 1
	contains(f[0], "updated last 500 days ago")
}

test_ra3_results_not_disseminated_fails if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"results_disseminated": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3")
	count(f) == 1
	contains(f[0], "disseminated")
}

test_ra5_scan_overdue_fails if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"days_since_last": 31}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 30")
}

test_ra5_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"days_since_last": "1"}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_days_null_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"days_since_last": null}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_odp_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"odp": {"frequency_days": "1"}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_overdue_remediations_fail if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"overdue_remediations": 3}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "3 vulnerabilities open")
}

test_ra5_overdue_remediations_string_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"overdue_remediations": "0"}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_tools_not_updatable_fails if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"scanner_updatable": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5")
	count(f) == 1
	contains(f[0], "readily update")
}

test_ra6_attestation_missing_fails if {
	inp := object.union(_pass, {"ra_controls": {"tscm_survey": {"attestation": null}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-6")
	count(f) == 1
	contains(f[0], "attestation")
}

test_ra6_attested_string_true_fails if {
	inp := object.union(_pass, {"ra_controls": {"tscm_survey": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-6")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_ra6_attestation_empty_by_fails if {
	inp := object.union(_pass, {"ra_controls": {"tscm_survey": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-6")
	count(f) == 1
	contains(f[0], "attestation")
}

test_ra7_unaddressed_findings_fail if {
	inp := object.union(_pass, {"ra_controls": {"risk_response": {"unaddressed_findings": 2}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-7")
	count(f) == 1
	contains(f[0], "2 assessment")
}

test_ra7_unaddressed_findings_null_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"risk_response": {"unaddressed_findings": null}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-7")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra7_not_per_tolerance_fails if {
	inp := object.union(_pass, {"ra_controls": {"risk_response": {"per_risk_tolerance": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-7")
	count(f) == 1
	contains(f[0], "risk tolerance")
}

test_ra8_attestation_missing_fails if {
	inp := object.union(_pass, {"ra_controls": {"privacy_impact_assessment": {"attestation": null}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-8")
	count(f) == 1
	contains(f[0], "attestation")
}

test_ra8_attested_string_true_fails if {
	inp := object.union(_pass, {"ra_controls": {"privacy_impact_assessment": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-8")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_ra8_attestation_empty_by_fails if {
	inp := object.union(_pass, {"ra_controls": {"privacy_impact_assessment": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-8")
	count(f) == 1
	contains(f[0], "attestation")
}

test_ra9_not_performed_fails if {
	inp := object.union(_pass, {"ra_controls": {"criticality_analysis": {"performed": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-9")
	count(f) == 1
	contains(f[0], "criticality analysis")
}

test_ra10_no_capability_fails if {
	inp := object.union(_pass, {"ra_controls": {"threat_hunting": {"capability_established": false}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-10")
	count(f) == 1
	contains(f[0], "threat hunting capability")
}

test_ra10_hunting_overdue_fails if {
	inp := object.union(_pass, {"ra_controls": {"threat_hunting": {"days_since_last": 91}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-10")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 90")
}

test_ra10_capability_numeric_one_fails if {
	inp := object.union(_pass, {"ra_controls": {"threat_hunting": {"capability_established": 1}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-10")
	count(f) == 1
	contains(f[0], "evidence missing")
}

# --- Moderate-baseline enhancements -------------------------------------------------------------

test_ra3_1_not_performed_fails if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"supply_chain": {"performed": false}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3(1)")
	count(f) == 1
	contains(f[0], "supply chain risks are not assessed")
}

test_ra3_1_update_overdue_fails if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"supply_chain": {"days_since_last": 400}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3(1)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_ra3_1_unassessed_components_fail if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"supply_chain": {"unassessed_components": 2}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3(1)")
	count(f) == 1
	contains(f[0], "2 organization-defined")
}

test_ra3_1_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"risk_assessment": {"supply_chain": {"odp": {"frequency_days": null}}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-3(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_2_feed_stale_fails if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"vulnerability_updates": {"days_since_last": 8}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(2)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 7")
}

test_ra5_2_not_before_scan_fails if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"vulnerability_updates": {"updated_before_last_scan": false}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(2)")
	count(f) == 1
	contains(f[0], "before the most recent scan")
}

test_ra5_2_days_string_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"vulnerability_updates": {"days_since_last": "1"}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_2_days_null_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"vulnerability_updates": {"days_since_last": null}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_5_not_authorized_fails if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"privileged_access": {"authorized": false}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(5)")
	count(f) == 1
	contains(f[0], "privileged access is not authorized")
}

test_ra5_5_unprivileged_targets_fail if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"privileged_access": {"targets_without_privileged_scan": 4}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(5)")
	count(f) == 1
	contains(f[0], "4 organization-defined")
}

test_ra5_5_authorized_string_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"privileged_access": {"authorized": "true"}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(5)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ra5_11_no_channel_fails if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"public_disclosure": {"channel_published": false}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(11)")
	count(f) == 1
	contains(f[0], "public reporting channel")
}

test_ra5_11_missing_is_evidence_missing if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"public_disclosure": {"channel_published": null}}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 1
	f := _flagged(v, "RA-5(11)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_enhancement_missing_does_not_fail_base if {
	inp := object.union(_pass, {"ra_controls": {"vulnerability_scanning": {"vulnerability_updates": null, "privileged_access": null, "public_disclosure": null}, "risk_assessment": {"supply_chain": null}}})
	v := data.nist.sp800_53.risk_assessment.violation with input as inp
	count(v) == 4
	count(_flagged(v, "RA-3")) == 0
	count(_flagged(v, "RA-5")) == 0
}
