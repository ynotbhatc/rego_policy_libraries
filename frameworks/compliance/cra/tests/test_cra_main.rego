package cra.main_test

import rego.v1
import data.cra.main

# ── Empty-input smoke tests ────────────────────────────────────────────────

test_compliance_report_defined_on_empty_input if {
    r := main.compliance_report with input as {}
    r.framework == "EU Cyber Resilience Act (CRA)"
    r.regulation == "Regulation (EU) 2024/2847"
    r.total_controls == 244
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

# ── Declaration of Conformity content (Annex IV) ─────────────────────────

test_declaration_of_conformity_module_appears_in_summary if {
    r := main.compliance_report with input as {}
    r.module_summary.declaration_of_conformity
}

test_declaration_missing_sole_responsibility_statement if {
    inp := {"declaration_of_conformity": {"statement_of_sole_responsibility": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Annex IV.4")]
    count(hits) > 0
}

test_declaration_must_reference_cra_regulation if {
    inp := {"declaration_of_conformity": {"conformity_statement": {"references_cra": false}}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Annex IV.6")]
    count(hits) > 0
}

test_declaration_standards_must_include_dates_versions if {
    inp := {"declaration_of_conformity": {
                "standards": {
                    "harmonised_standards_referenced": true,
                    "standard_dates_versions_included": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex IV.7"); contains(v, "dates/versions")]
    count(hits) > 0
}

test_notified_body_block_only_fires_when_involved if {
    inp_not_involved := {"declaration_of_conformity": {"notified_body": {"involved": false}}}
    hits := [v | some v in main.violations with input as inp_not_involved;
             contains(v, "Annex IV.8: Notified body involvement is declared")]
    count(hits) == 0

    inp_involved_no_id := {"declaration_of_conformity": {
                              "notified_body": {"involved": true, "name": "TÜV"}}}
    hits2 := [v | some v in main.violations with input as inp_involved_no_id;
              contains(v, "Annex IV.8")]
    count(hits2) > 0
}

test_declaration_signature_must_include_signatory_function if {
    inp := {"declaration_of_conformity": {
                "signature": {
                    "signed_for_manufacturer": true,
                    "signatory_name": "J. Doe",
                    "signatory_function": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex IV.10"); contains(v, "function")]
    count(hits) > 0
}

# ── Substantial modification (Article 11) ────────────────────────────────

test_substantial_modification_module_appears if {
    r := main.compliance_report with input as {}
    r.module_summary.substantial_modification
}

test_substantial_modification_requires_reassessment if {
    inp := {"substantial_modification": {
                "modification_classified_substantial": true,
                "conformity_reassessment": {"performed": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.11(2)"); contains(v, "not been re-performed")]
    count(hits) > 0
}

test_substantial_modifier_assumes_manufacturer_role if {
    inp := {"substantial_modification": {
                "modification_classified_substantial": true,
                "modifier_is_not_original_manufacturer": true,
                "modifier_assumed_manufacturer_obligations": false}}
    hits := [v | some v in main.violations with input as inp; contains(v, "Art.11(3)")]
    count(hits) > 0
}

test_added_connectivity_requires_updated_risk_assessment if {
    inp := {"substantial_modification": {
                "changes": {
                    "added_network_connectivity": true,
                    "risk_assessment_updated": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.1 interaction")]
    count(hits) > 0
}

test_crypto_primitive_change_requires_review if {
    inp := {"substantial_modification": {
                "changes": {
                    "cryptographic_primitive_changed": true,
                    "cryptographic_review_performed": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.5/6 interaction")]
    count(hits) > 0
}

test_sbom_must_refresh_after_dependency_change if {
    inp := {"substantial_modification": {
                "changes": {
                    "sbom_changed": true,
                    "sbom_published_after_change": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex II.1 interaction")]
    count(hits) > 0
}

# ── Online marketplace (Article 22) ──────────────────────────────────────

test_online_marketplace_module_appears if {
    r := main.compliance_report with input as {}
    r.module_summary.online_marketplace
}

test_non_marketplace_entity_has_zero_marketplace_violations if {
    # An entity that is NOT a marketplace provider should produce zero
    # marketplace-module violations (the threshold gate is correct).
    inp := {"online_marketplace": {"is_marketplace_provider": false}}
    r := main.compliance_report with input as inp
    r.module_summary.online_marketplace.violations == 0
}

test_marketplace_must_designate_single_point_of_contact if {
    inp := {"online_marketplace": {
                "is_marketplace_provider": true,
                "products_offered": {"includes_products_with_digital_elements": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.22(1)"); contains(v, "single point of contact")]
    count(hits) > 0
}

test_marketplace_must_action_takedown_within_48h if {
    inp := {"online_marketplace": {
                "is_marketplace_provider": true,
                "products_offered": {"includes_products_with_digital_elements": true},
                "authority_takedown_order_received": true,
                "authority_takedown_order_hours_pending": 60,
                "authority_takedown_order_actioned": false}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.22(3)"); contains(v, "48h")]
    count(hits) > 0
}

test_marketplace_random_check_sample_below_one_percent_violates if {
    inp := {"online_marketplace": {
                "is_marketplace_provider": true,
                "products_offered": {"includes_products_with_digital_elements": true},
                "random_checks": {"performed": true, "sample_size_pct": 0.5}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.22(5)"); contains(v, "0.5")]
    count(hits) > 0
}

test_marketplace_high_severity_listing_must_be_removed if {
    inp := {"online_marketplace": {
                "is_marketplace_provider": true,
                "products_offered": {"includes_products_with_digital_elements": true},
                "non_compliant_listing_identified": true,
                "severity": "high",
                "listing_removed": false}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "high-severity non-compliant listing")]
    count(hits) > 0
}

# ── FOSS exclusion (Article 23) ──────────────────────────────────────────

test_foss_exclusion_module_appears if {
    r := main.compliance_report with input as {}
    r.module_summary.foss_exclusion
}

test_non_commercial_oss_is_exempt if {
    inp := {"foss": {
                "is_open_source_product": true,
                "outside_course_of_commercial_activity": true}}
    r := main.compliance_report with input as inp
    r.module_summary.foss_exclusion.exempt == true
    r.module_summary.foss_exclusion.violations == 0
}

test_default_state_is_not_exempt if {
    r := main.compliance_report with input as {}
    r.module_summary.foss_exclusion.exempt == false
}

test_misclaim_when_paid_support_offered if {
    inp := {"foss": {
                "claimed_exemption": true,
                "revenue": {"paid_support_offered": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.23 (mis-claim)"); contains(v, "paid support")]
    count(hits) > 0
}

test_misclaim_when_license_fees_collected if {
    inp := {"foss": {
                "claimed_exemption": true,
                "revenue": {"license_fees_collected": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "license/usage fees")]
    count(hits) > 0
}

test_misclaim_when_commercial_saas_hosting if {
    inp := {"foss": {
                "claimed_exemption": true,
                "revenue": {"commercial_saas_hosting": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "commercial hosted version")]
    count(hits) > 0
}

test_donation_full_time_devs_moves_to_steward_category if {
    inp := {"foss": {
                "claimed_exemption": true,
                "revenue": {"donations_received": true},
                "development": {
                    "employed_developers_paid_from_donations": true,
                    "developers_full_time": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.23 (boundary)"); contains(v, "OSS-steward category")]
    count(hits) > 0
}

test_recital_18_commercial_integration_violates if {
    inp := {"foss": {
                "claimed_exemption": true,
                "distribution": {
                    "integrated_into_commercial_product": true,
                    "distributed_in_eu_market": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Recital 18")]
    count(hits) > 0
}

test_exemption_basis_must_be_documented if {
    inp := {"foss": {
                "claimed_exemption": true,
                "process": {"exemption_basis_documented": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.23"); contains(v, "audit trail")]
    count(hits) > 0
}

# ── Supply-chain evidence (SLSA bridge) ──────────────────────────────────

test_supply_chain_evidence_module_appears if {
    r := main.compliance_report with input as {}
    r.module_summary.supply_chain_evidence
    r.module_summary.supply_chain_evidence.upstream == "data.supply_chain.slsa"
}

test_sbom_missing_maps_to_annex_ii_1a if {
    # An empty input → SLSA reports "No SBOM attached" → CRA bridge re-frames as Annex II.1(a)
    inp := {}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex II.1(a) (via SLSA)")]
    count(hits) > 0
}

test_unsigned_artifact_maps_to_annex_i_6a if {
    # SLSA fires "Artifact is not signed" on empty input → CRA bridge re-frames as Annex I.6(a)
    inp := {}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.6(a) (via SLSA)")]
    count(hits) > 0
}

test_sbom_change_without_refresh_violates_art_11_via_slsa if {
    inp := {"substantial_modification": {"changes": {"sbom_changed": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.11 (via SLSA)")]
    count(hits) > 0
}

# ── Crypto evidence (ISO 27001 A.10 bridge) ──────────────────────────────

test_crypto_evidence_module_appears if {
    r := main.compliance_report with input as {}
    r.module_summary.crypto_evidence
    r.module_summary.crypto_evidence.upstream == "data.iso27001.cryptography"
}

test_missing_crypto_policy_maps_to_annex_i_5 if {
    inp := {}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.5 (via ISO 27001 A.10.1.1)")]
    count(hits) > 0
}

test_weak_cipher_in_use_fires_annex_i_5b if {
    inp := {"cryptography": {"ciphers_in_use": ["AES-256-GCM", "DES"]}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.5(b)"); contains(v, "DES")]
    count(hits) > 0
}

test_deprecated_protocol_fires_annex_i_5b if {
    inp := {"cryptography": {"protocols_in_use": ["TLS1.0", "TLS1.3"]}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.5(b)"); contains(v, "TLS1.0")]
    count(hits) > 0
}

test_no_anti_rollback_fires_annex_i_6b if {
    inp := {"cryptography": {"signing": {"anti_rollback_enforced": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.6(b)"); contains(v, "Anti-rollback")]
    count(hits) > 0
}

test_signing_without_hardware_backed_storage_fires_i_6_i_4 if {
    inp := {"cryptography": {"signing": {"in_use": true,
                                          "hardware_backed_key_storage": false}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Annex I.6 (interaction with I.4)")]
    count(hits) > 0
}

test_donations_alone_do_not_create_misclaim if {
    # Recital 15 — donations alone don't make the entity commercial.
    # If an entity claims exemption AND only receives donations (no full-time
    # paid devs), the donation-related boundary rule must NOT fire.
    inp := {"foss": {
                "claimed_exemption": true,
                "is_open_source_product": true,
                "outside_course_of_commercial_activity": true,
                "revenue": {"donations_received": true},
                "process": {
                    "exemption_basis_documented": true,
                    "exemption_basis_reviewed_annually": true}}}
    hits := [v | some v in main.violations with input as inp;
             contains(v, "Art.23 (boundary)")]
    count(hits) == 0
}
