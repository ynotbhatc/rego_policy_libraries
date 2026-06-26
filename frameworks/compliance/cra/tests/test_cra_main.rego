package cra.main_test

import rego.v1
import data.cra.main

# ── Empty-input smoke tests ────────────────────────────────────────────────

test_compliance_report_defined_on_empty_input if {
    r := main.compliance_report with input as {}
    r.framework == "EU Cyber Resilience Act (CRA)"
    r.regulation == "Regulation (EU) 2024/2847"
    r.total_controls == 163
    is_number(r.violation_count)
}

test_non_compliant_on_empty_input if {
    not main.compliant with input as {}
}

test_violations_emitted_on_empty_input if {
    # All 6 modules should fire; expect close to total_controls.
    count(main.violations) > 50 with input as {}
}

test_module_summary_has_all_eleven_modules if {
    r := main.compliance_report with input as {}
    r.module_summary.essential_requirements
    r.module_summary.vulnerability_handling
    r.module_summary.incident_reporting
    r.module_summary.technical_documentation
    r.module_summary.conformity_assessment
    r.module_summary.manufacturer_obligations
    r.module_summary.authorised_representative
    r.module_summary.importer_obligations
    r.module_summary.distributor_obligations
    r.module_summary.oss_steward
    r.module_summary.user_information
}

test_defaults_for_metadata if {
    r := main.compliance_report with input as {}
    r.entity_name == "unknown"
    r.product_name == "unknown"
    r.product_class == "unknown"
    r.assessed_at == "unknown"
}

test_metadata_picked_up_from_input if {
    r := main.compliance_report with input as {
        "entity_name":     "Widget Maker GmbH",
        "product_name":    "ConnectedThermostat-7",
        "product_class":   "important_class_2",
        "assessment_date": "2026-06-26",
    }
    r.entity_name == "Widget Maker GmbH"
    r.product_class == "important_class_2"
    r.assessed_at == "2026-06-26"
}

# ── Targeted timeline-rule tests ────────────────────────────────────────────

# A vendor that is aware of an exploited vulnerability for >24h but hasn't
# sent early warning is in violation of Art.14(2)(a).
test_24h_early_warning_violation_when_late if {
    inp := {
        "incident_reporting": {
            "actively_exploited_vuln_known":   true,
            "hours_since_aware_of_vuln":       30,
            "early_warning_sent":              false,
        },
    }
    some v in main.violations with input as inp
    contains(v, "Art.14(2)(a)")
}

# A vendor that DID send the early warning within the window should not
# trigger Art.14(2)(a) (other rules may still fire).
test_24h_early_warning_clears_when_sent if {
    inp := {
        "incident_reporting": {
            "actively_exploited_vuln_known":   true,
            "hours_since_aware_of_vuln":       30,
            "early_warning_sent":              true,
        },
    }
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.14(2)(a)")]
    count(hits) == 0
}

# Important Class II product using Module A is non-conformant per Art.32(2).
test_module_a_insufficient_for_class_2 if {
    inp := {
        "conformity_assessment": {
            "product_class":    "important_class_2",
            "procedure_used":   "module_a",
        },
    }
    some v in main.violations with input as inp
    contains(v, "Art.32(2)")
}

# Support period below 5 years triggers Art.13(8) AND Annex II.2 rules
# (both essential vuln-handling + manufacturer modules check this).
test_short_support_period_triggers_both_rules if {
    inp := {
        "vulnerability_handling": {"support_period_years": 3},
        "manufacturer": {"support_period": {"declared": true, "years": 3}},
    }
    annex_hit := count([v | some v in main.violations with input as inp; contains(v, "Annex II.2")])
    art13_hit := count([v | some v in main.violations with input as inp; contains(v, "Art.13(8)")])
    annex_hit > 0
    art13_hit > 0
}

# ── Module A vs B+C / Module H conformity assessment branches ──────────────

test_class_2_module_a_fails if {
    inp := {"conformity_assessment": {"product_class": "important_class_2", "procedure_used": "module_a"}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.32(2)")]
    count(hits) > 0
}

test_class_2_module_h_clears_32_2 if {
    inp := {"conformity_assessment": {"product_class": "important_class_2", "procedure_used": "module_h",
            "notified_body": {"engaged": true, "id_number": "NB-9999"}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.32(2)")]
    count(hits) == 0
}

test_critical_product_requires_cyber_cert_scheme if {
    inp := {"conformity_assessment": {"product_class": "critical", "european_cyber_cert_scheme_used": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.32(3) / Art.8")]
    count(hits) > 0
}

test_third_party_assessment_requires_notified_body if {
    inp := {"conformity_assessment": {"procedure_used": "module_b_c",
                                       "notified_body": {"engaged": false}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.32(4): Third-party")]
    count(hits) > 0
}

# ── 72h + 14d incident reporting cascades ──────────────────────────────────

test_72h_notification_violation if {
    inp := {"incident_reporting": {"actively_exploited_vuln_known": true,
                                    "hours_since_aware_of_vuln": 80,
                                    "vulnerability_notification_sent": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.14(2)(b)")]
    count(hits) > 0
}

test_14d_final_report_violation if {
    inp := {"incident_reporting": {"actively_exploited_vuln_known": true,
                                    "hours_since_aware_of_vuln": 350,
                                    "days_since_aware_of_vuln": 15,
                                    "final_vuln_report_sent": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.14(2)(c)")]
    count(hits) > 0
}

# Severe incident timeline (Art.14(3) — same 24h/72h/1-month cascade)
test_severe_incident_24h_violation if {
    inp := {"incident_reporting": {"severe_incident_occurred": true,
                                    "hours_since_incident": 30,
                                    "incident_early_warning_sent": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.14(3)(a)")]
    count(hits) > 0
}

test_users_impacted_must_be_notified_with_mitigation if {
    inp := {"incident_reporting": {"users_impacted": true,
                                    "affected_users_notified": true,
                                    "mitigation_guidance_provided": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.14(9)")]
    count(hits) > 0
}

# ── Importer / distributor / auth-rep / OSS-steward modules ───────────────

test_importer_under_own_brand_assumes_manufacturer_role if {
    inp := {"importer": {"placed_under_own_brand": true,
                          "assumed_manufacturer_obligations": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.21:")]
    count(hits) > 0
}

test_distributor_modification_assumes_manufacturer_role if {
    inp := {"distributor": {"product_modified_after_placement": true,
                             "assumed_manufacturer_obligations": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.21:")]
    count(hits) > 0
}

test_non_eu_manufacturer_must_appoint_authorised_rep if {
    inp := {"authorised_representative": {"manufacturer_outside_eu": true,
                                            "appointed": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.18(1)")]
    count(hits) > 0
}

test_auth_rep_cannot_assume_conformity_assessment if {
    inp := {"authorised_representative": {
                "appointed": true,
                "tasks": {"conformity_assessment_delegated": true}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.18(4)")]
    count(hits) > 0
}

test_oss_steward_threshold_gate_holds if {
    # Entity that does NOT meet the "systematic and sustained / commercial" gate
    # should produce ZERO OSS-steward violations.
    inp := {"oss_steward": {
                "is_legal_person_other_than_natural": true,
                "provides_systematic_sustained_support": false,
                "oss_product_intended_for_commercial_activities": false}}
    r := main.compliance_report with input as inp
    r.module_summary.oss_steward.violations == 0
}

test_oss_steward_must_publish_cybersecurity_policy if {
    inp := {"oss_steward": {
                "is_legal_person_other_than_natural": true,
                "provides_systematic_sustained_support": true,
                "oss_product_intended_for_commercial_activities": true,
                "cybersecurity_policy": {"published": false}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.24(1)")]
    count(hits) > 0
}

# ── User information (Annex II) ───────────────────────────────────────────

test_user_info_must_disclose_end_of_support if {
    inp := {"user_information": {"support_period": {"disclosed": true, "end_of_support_date_disclosed": false}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Annex II.8: End-of-support")]
    count(hits) > 0
}

test_user_info_must_disclose_sbom_location if {
    inp := {"user_information": {"sbom_access": {"disclosed_to_user": false}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Annex II.7")]
    count(hits) > 0
}
