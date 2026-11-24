package cra.evidence_rule_test

import rego.v1

# Evidence rule (weekly audit 2026-11-24): only the boolean true passes a yes/no fact. Missing, null and
# wrongly typed values ("true", "false", "no", 0, 1) fail the control and the finding names the problem.
# A fact that switches an obligation on or off must be stated; it is never inferred from a missing field.
# Data-driven: one all-pass fixture per module, every leaf mutated.
#
# cra.crypto_evidence re-frames data.iso27001.cryptography and cra.supply_chain_evidence re-frames
# data.supply_chain.slsa; both upstream modules are replaced with a passing result so that only the facts the
# CRA modules read themselves are under test.

fixtures := {
	"authorised_representative": {
		"authorised_representative": {
			"appointed": true,
			"contact_in_user_info": true,
			"mandate_enables_required_tasks": true,
			"manufacturer_breaching_cra": true,
			"manufacturer_outside_eu": true,
			"tasks": {
				"conformity_assessment_delegated": false,
				"cooperate_on_cyber_risk_action": true,
				"essential_requirements_delegated": false,
				"keeps_declaration_of_conformity": true,
				"keeps_technical_documentation": true,
				"mandate_termination_considered": true,
				"notified_competent_authority": true,
				"provide_info_on_request": true,
				"retention_10_years": true,
			},
			"written_mandate_in_place": true,
		},
	},
	"conformity_assessment": {
		"conformity_assessment": {
			"ce_marking": {
				"affixed": true,
				"notified_body_number_included": true,
				"visible_legible_indelible": true,
			},
			"declaration_of_conformity": {
				"includes_required_elements": true,
				"prepared": true,
			},
			"notified_body": {
				"engaged": true,
				"id_number": true,
			},
			"procedure_selected": true,
			"procedure_used": "module_h",
			"product_class": "important_class_2",
			"product_placed_on_market": true,
			"reassessment_on_substantial_modification": true,
		},
	},
	"crypto_evidence": {
		"cryptography": {
			"at_rest": {
				"database_encryption_enabled": true,
				"disk_encryption_enabled": true,
			},
			"fips_validated": true,
			"signing": {
				"anti_rollback_enforced": true,
				"hardware_backed_key_storage": true,
				"in_use": true,
			},
		},
	},
	"declaration_of_conformity": {
		"declaration_of_conformity": {
			"additional_info": {
				"support_period_stated": true,
			},
			"authorised_representative": {
				"name": true,
				"postal_address": true,
				"required": true,
			},
			"conformity_statement": {
				"references_cra": true,
			},
			"languages": {
				"translated_for_member_states": true,
			},
			"manufacturer": {
				"name": true,
				"postal_address": true,
			},
			"notified_body": {
				"certificate_reference": true,
				"id_number": true,
				"involved": true,
				"name": true,
			},
			"object_description": {
				"sufficient_for_traceability": true,
			},
			"product_identification": {
				"model_id": true,
				"serial_or_batch": true,
			},
			"signature": {
				"place_and_date": true,
				"signatory_function": true,
				"signatory_name": true,
				"signed_for_manufacturer": true,
			},
			"standards": {
				"harmonised_standards_referenced": true,
				"standard_dates_versions_included": true,
			},
			"statement_of_sole_responsibility": true,
		},
	},
	"distributor_obligations": {
		"distributor": {
			"action": {
				"availability_suspended": true,
				"manufacturer_informed": true,
			},
			"assumed_manufacturer_obligations": true,
			"cooperation": {
				"cooperate_on_corrective_action": true,
				"provide_info_on_request": true,
			},
			"corrective_action": {
				"severity": "high",
				"taken": true,
				"withdrawal_or_recall": true,
			},
			"handling": {
				"storage_preserves_compliance": true,
			},
			"non_conformity_confirmed": true,
			"non_conformity_suspected": true,
			"product_is_imported": true,
			"product_modified_after_placement": true,
			"risk_awareness": {
				"market_surveillance_informed": true,
				"significant_risk_known": true,
			},
			"sold_under_own_brand": true,
			"verification": {
				"ce_marking_present": true,
				"declaration_of_conformity_provided": true,
				"importer_identification_clear": true,
				"manufacturer_identification_clear": true,
				"user_instructions_provided": true,
			},
		},
	},
	"essential_requirements": {
		"essential_requirements": {
			"access_protection": {
				"authentication_state_of_the_art": true,
				"identity_access_management": true,
			},
			"attack_surface": {
				"external_interfaces_minimized": true,
			},
			"availability": {
				"dos_protection": true,
				"essential_functions_preserved": true,
			},
			"confidentiality": {
				"data_at_rest_encrypted": true,
				"data_in_transit_encrypted": true,
			},
			"data_deletion": {
				"secure_erase_available": true,
			},
			"data_minimization": {
				"only_necessary_data_processed": true,
			},
			"default_config": {
				"allows_reset_to_secure_defaults": true,
				"secure_out_of_box": true,
			},
			"exploitation_mitigation": {
				"techniques_implemented": true,
			},
			"integrity": {
				"code_signing_enforced": true,
				"tamper_detection": true,
			},
			"logging": {
				"security_events_recorded": true,
				"user_can_opt_out": true,
			},
			"security_by_design": {
				"documented_assessment": true,
				"threat_modeled": true,
			},
			"vulnerability_protection": {
				"automatic_updates_default": true,
				"security_updates_distinct": true,
			},
		},
	},
	"foss_exclusion": {
		"foss": {
			"claimed_exemption": true,
			"distribution": {
				"claimant_integrates_into_own_commercial_product": false,
				"distributed_in_eu_market": false,
			},
			"is_open_source_product": true,
			"not_made_available_in_course_of_commercial_activity": true,
			"process": {
				"exemption_basis_documented": true,
				"exemption_basis_reviewed_annually": true,
			},
			"revenue": {
				"commercial_saas_hosting": false,
				"license_fees_collected": false,
				"paid_support_offered": false,
				"use_conditioned_on_personal_data": false,
			},
		},
	},
	"importer_obligations": {
		"importer": {
			"assumed_manufacturer_obligations": true,
			"cooperation": {
				"cooperate_with_authorities": true,
				"documentation_available_10_years": true,
			},
			"corrective_action": {
				"severity": "high",
				"taken_immediately": true,
				"withdrawal_or_recall_initiated": true,
			},
			"handling": {
				"storage_transport_preserves_compliance": true,
			},
			"identification": {
				"name_on_product": true,
				"postal_address_on_product": true,
			},
			"non_conformity_known": true,
			"placed_under_own_brand": true,
			"risk_awareness": {
				"manufacturer_informed": true,
				"market_surveillance_informed": true,
				"product_presents_cyber_risk": true,
				"significant_risk": true,
			},
			"verification": {
				"ce_marking_present": true,
				"conformity_assessment_performed": true,
				"declaration_of_conformity_accompanies_product": true,
				"technical_documentation_exists": true,
			},
		},
	},
	"incident_reporting": {
		"incident_reporting": {
			"actively_exploited_vuln_known": true,
			"affected_users_notified": true,
			"corrective_measure_available": true,
			"csirt_coordinator_identified": true,
			"days_since_corrective_measure_available": 20,
			"days_since_incident_notification": 40,
			"early_warning_sent": true,
			"final_vuln_report_sent": true,
			"hours_since_aware_of_incident": 80,
			"hours_since_aware_of_vuln": 80,
			"incident_early_warning_sent": true,
			"incident_final_report_sent": true,
			"incident_notification_sent": true,
			"mitigation_guidance_provided": true,
			"notification_machine_readable_where_appropriate": true,
			"process_documented": true,
			"process_tested_annually": true,
			"severe_incident_occurred": true,
			"users_impacted": true,
			"vulnerability_notification_sent": true,
		},
	},
	"manufacturer_obligations": {
		"manufacturer": {
			"eol": {
				"end_of_support_notification_planned": true,
			},
			"essential_requirements": {
				"met": true,
			},
			"governance": {
				"product_security_role_assigned": true,
			},
			"market_surveillance": {
				"cooperation_committed": true,
			},
			"reporting": {
				"process_to_enisa_documented": true,
			},
			"risk_assessment": {
				"in_technical_documentation": true,
				"performed": true,
			},
			"support_period": {
				"declared": true,
				"years": 5,
			},
			"third_party_components": {
				"due_diligence_performed": true,
				"vulnerabilities_monitored": true,
			},
			"user_information": {
				"instructions_provided": true,
				"security_relevant_info_included": true,
			},
			"vulnerability_handling": {
				"lifetime_coverage": true,
			},
		},
	},
	"online_marketplace": {
		"online_marketplace": {
			"affected_buyers_notified": true,
			"authority_takedown_order_actioned": true,
			"authority_takedown_order_hours_pending": 50,
			"authority_takedown_order_received": true,
			"buyers_affected": true,
			"cooperation": {
				"with_authorities_documented": true,
			},
			"is_marketplace_provider": true,
			"listing_removed": true,
			"manufacturer_notified": true,
			"non_compliant_listing_identified": true,
			"process_documentation": {
				"cra_process_documented": true,
			},
			"products_offered": {
				"includes_products_with_digital_elements": true,
			},
			"random_checks": {
				"performed": true,
				"sample_size_pct": 5,
			},
			"reporting_channel": {
				"exists_for_consumers": true,
			},
			"severity": "high",
			"single_point_of_contact": {
				"designated_for_authorities": true,
				"designated_for_end_users": true,
			},
			"trader_due_diligence": {
				"cra_compliance_attested": true,
				"identity_verified": true,
			},
		},
	},
	"oss_steward": {
		"oss_steward": {
			"actively_exploited_vuln_known": true,
			"affected_users_informed": true,
			"can_ensure_corrective_action": true,
			"cooperation": {
				"policy_providable_on_reasoned_request": true,
				"with_market_surveillance": true,
			},
			"csirt_coordinator_identified": true,
			"cvd_policy": {
				"in_place": true,
			},
			"cybersecurity_policy": {
				"covers_secure_development_practices": true,
				"covers_vulnerability_handling": true,
				"documented_verifiably": true,
				"fosters_voluntary_reporting_and_sharing": true,
			},
			"ensures_product_viability": true,
			"incident_notified": true,
			"involved_in_development": true,
			"is_legal_person": true,
			"not_manufacturer_of_product": true,
			"oss_product_intended_for_commercial_activities": true,
			"provides_development_infrastructure": true,
			"provides_systematic_sustained_support": true,
			"severe_incident_affecting_provided_infrastructure": true,
			"vulnerability_notified": true,
			"vulnerability_reporting_channel": {
				"exists": true,
			},
		},
	},
	"substantial_modification": {
		"substantial_modification": {
			"assessment_process": {
				"criteria_published": true,
				"documented": true,
				"reviewed_annually": true,
			},
			"changes": {
				"added_network_connectivity": true,
				"cryptographic_primitive_changed": true,
				"cryptographic_review_performed": true,
				"risk_assessment_updated": true,
				"sbom_changed": true,
				"sbom_published_after_change": true,
				"security_relevant": true,
				"users_notified": true,
			},
			"conformity_reassessment": {
				"performed": true,
				"scope_appropriate": true,
			},
			"declaration_of_conformity_reissued": true,
			"documentation_updated": true,
			"modification_classified_substantial": true,
			"modifier_assumed_manufacturer_obligations": true,
			"modifier_is_not_original_manufacturer": true,
			"support_period_recommitted": true,
		},
	},
	"technical_documentation": {
		"technical_documentation": {
			"declaration_of_conformity": {
				"signed": true,
			},
			"design": {
				"architecture_diagram": true,
				"cybersecurity_controls_mapped": true,
			},
			"product": {
				"classification": "critical",
			},
			"product_description": {
				"documented": true,
				"intended_purpose": true,
				"support_period_declared": true,
			},
			"retention": {
				"available_on_request": true,
				"maintained_10_years": true,
			},
			"risk_assessment": {
				"documented": true,
				"mitigations_documented": true,
				"threats_identified": true,
			},
			"sbom": {
				"included": true,
			},
			"testing": {
				"results_documented": true,
				"third_party_assessment": true,
			},
			"vuln_process": {
				"documented": true,
			},
		},
	},
	"user_information": {
		"user_information": {
			"cybersecurity_properties": {
				"described": true,
			},
			"decommissioning": {
				"guidance_provided": true,
			},
			"intended_purpose": {
				"described": true,
				"security_environment_specified": true,
			},
			"languages": {
				"member_state_languages_covered": true,
			},
			"manufacturer": {
				"contact_for_vulnerability_reports": true,
				"electronic_contact_provided": true,
				"name_provided": true,
				"postal_address_provided": true,
			},
			"product_identifier": {
				"batch_or_serial_provided": true,
				"type_provided": true,
				"version_provided": true,
			},
			"readability": {
				"appropriate_for_users": true,
			},
			"risks_and_threats": {
				"documented": true,
			},
			"sbom_access": {
				"disclosed_to_user": true,
			},
			"single_point_of_contact": {
				"published": true,
			},
			"support_period": {
				"disclosed": true,
				"end_of_support_date_disclosed": true,
			},
			"updates": {
				"access_method_disclosed": true,
				"installation_instructions": true,
			},
		},
	},
	"vulnerability_handling": {
		"vulnerability_handling": {
			"coordinated_disclosure": {
				"contact_point_provided": true,
				"policy_published": true,
			},
			"disclosure": {
				"cve_assigned": true,
				"public_disclosure_after_patch": true,
			},
			"mitigation": {
				"compensating_controls_documented": true,
			},
			"remediation": {
				"process_documented": true,
				"security_updates_provided_free": true,
			},
			"reporting_channel": {
				"exists": true,
			},
			"sbom": {
				"components_documented": true,
				"machine_readable_format": true,
				"maintained": true,
			},
			"support_period_years": 5,
			"testing": {
				"regular_testing_performed": true,
				"test_results_reviewed": true,
			},
			"update_distribution": {
				"secure_channel": true,
				"timely_delivery": true,
			},
		},
	},
}

all_pass_input := {
	"authorised_representative": {
		"appointed": true,
		"contact_in_user_info": true,
		"mandate_enables_required_tasks": true,
		"manufacturer_breaching_cra": true,
		"manufacturer_outside_eu": true,
		"tasks": {
			"conformity_assessment_delegated": false,
			"cooperate_on_cyber_risk_action": true,
			"essential_requirements_delegated": false,
			"keeps_declaration_of_conformity": true,
			"keeps_technical_documentation": true,
			"mandate_termination_considered": true,
			"notified_competent_authority": true,
			"provide_info_on_request": true,
			"retention_10_years": true,
		},
		"written_mandate_in_place": true,
	},
	"conformity_assessment": {
		"ce_marking": {
			"affixed": true,
			"notified_body_number_included": true,
			"visible_legible_indelible": true,
		},
		"declaration_of_conformity": {
			"includes_required_elements": true,
			"prepared": true,
		},
		"notified_body": {
			"engaged": true,
			"id_number": true,
		},
		"procedure_selected": true,
		"procedure_used": "module_h",
		"product_class": "important_class_2",
		"product_placed_on_market": true,
		"reassessment_on_substantial_modification": true,
	},
	"cryptography": {
		"at_rest": {
			"database_encryption_enabled": true,
			"disk_encryption_enabled": true,
		},
		"fips_validated": true,
		"signing": {
			"anti_rollback_enforced": true,
			"hardware_backed_key_storage": true,
			"in_use": true,
		},
	},
	"declaration_of_conformity": {
		"additional_info": {
			"support_period_stated": true,
		},
		"authorised_representative": {
			"name": true,
			"postal_address": true,
			"required": true,
		},
		"conformity_statement": {
			"references_cra": true,
		},
		"languages": {
			"translated_for_member_states": true,
		},
		"manufacturer": {
			"name": true,
			"postal_address": true,
		},
		"notified_body": {
			"certificate_reference": true,
			"id_number": true,
			"involved": true,
			"name": true,
		},
		"object_description": {
			"sufficient_for_traceability": true,
		},
		"product_identification": {
			"model_id": true,
			"serial_or_batch": true,
		},
		"signature": {
			"place_and_date": true,
			"signatory_function": true,
			"signatory_name": true,
			"signed_for_manufacturer": true,
		},
		"standards": {
			"harmonised_standards_referenced": true,
			"standard_dates_versions_included": true,
		},
		"statement_of_sole_responsibility": true,
	},
	"distributor": {
		"action": {
			"availability_suspended": true,
			"manufacturer_informed": true,
		},
		"assumed_manufacturer_obligations": true,
		"cooperation": {
			"cooperate_on_corrective_action": true,
			"provide_info_on_request": true,
		},
		"corrective_action": {
			"severity": "high",
			"taken": true,
			"withdrawal_or_recall": true,
		},
		"handling": {
			"storage_preserves_compliance": true,
		},
		"non_conformity_confirmed": true,
		"non_conformity_suspected": true,
		"product_is_imported": true,
		"product_modified_after_placement": true,
		"risk_awareness": {
			"market_surveillance_informed": true,
			"significant_risk_known": true,
		},
		"sold_under_own_brand": true,
		"verification": {
			"ce_marking_present": true,
			"declaration_of_conformity_provided": true,
			"importer_identification_clear": true,
			"manufacturer_identification_clear": true,
			"user_instructions_provided": true,
		},
	},
	"essential_requirements": {
		"access_protection": {
			"authentication_state_of_the_art": true,
			"identity_access_management": true,
		},
		"attack_surface": {
			"external_interfaces_minimized": true,
		},
		"availability": {
			"dos_protection": true,
			"essential_functions_preserved": true,
		},
		"confidentiality": {
			"data_at_rest_encrypted": true,
			"data_in_transit_encrypted": true,
		},
		"data_deletion": {
			"secure_erase_available": true,
		},
		"data_minimization": {
			"only_necessary_data_processed": true,
		},
		"default_config": {
			"allows_reset_to_secure_defaults": true,
			"secure_out_of_box": true,
		},
		"exploitation_mitigation": {
			"techniques_implemented": true,
		},
		"integrity": {
			"code_signing_enforced": true,
			"tamper_detection": true,
		},
		"logging": {
			"security_events_recorded": true,
			"user_can_opt_out": true,
		},
		"security_by_design": {
			"documented_assessment": true,
			"threat_modeled": true,
		},
		"vulnerability_protection": {
			"automatic_updates_default": true,
			"security_updates_distinct": true,
		},
	},
	"foss": {
		"claimed_exemption": true,
		"distribution": {
			"claimant_integrates_into_own_commercial_product": false,
			"distributed_in_eu_market": false,
		},
		"is_open_source_product": true,
		"not_made_available_in_course_of_commercial_activity": true,
		"process": {
			"exemption_basis_documented": true,
			"exemption_basis_reviewed_annually": true,
		},
		"revenue": {
			"commercial_saas_hosting": false,
			"license_fees_collected": false,
			"paid_support_offered": false,
			"use_conditioned_on_personal_data": false,
		},
	},
	"importer": {
		"assumed_manufacturer_obligations": true,
		"cooperation": {
			"cooperate_with_authorities": true,
			"documentation_available_10_years": true,
		},
		"corrective_action": {
			"severity": "high",
			"taken_immediately": true,
			"withdrawal_or_recall_initiated": true,
		},
		"handling": {
			"storage_transport_preserves_compliance": true,
		},
		"identification": {
			"name_on_product": true,
			"postal_address_on_product": true,
		},
		"non_conformity_known": true,
		"placed_under_own_brand": true,
		"risk_awareness": {
			"manufacturer_informed": true,
			"market_surveillance_informed": true,
			"product_presents_cyber_risk": true,
			"significant_risk": true,
		},
		"verification": {
			"ce_marking_present": true,
			"conformity_assessment_performed": true,
			"declaration_of_conformity_accompanies_product": true,
			"technical_documentation_exists": true,
		},
	},
	"incident_reporting": {
		"actively_exploited_vuln_known": true,
		"affected_users_notified": true,
		"corrective_measure_available": true,
		"csirt_coordinator_identified": true,
		"days_since_corrective_measure_available": 20,
		"days_since_incident_notification": 40,
		"early_warning_sent": true,
		"final_vuln_report_sent": true,
		"hours_since_aware_of_incident": 80,
		"hours_since_aware_of_vuln": 80,
		"incident_early_warning_sent": true,
		"incident_final_report_sent": true,
		"incident_notification_sent": true,
		"mitigation_guidance_provided": true,
		"notification_machine_readable_where_appropriate": true,
		"process_documented": true,
		"process_tested_annually": true,
		"severe_incident_occurred": true,
		"users_impacted": true,
		"vulnerability_notification_sent": true,
	},
	"manufacturer": {
		"eol": {
			"end_of_support_notification_planned": true,
		},
		"essential_requirements": {
			"met": true,
		},
		"governance": {
			"product_security_role_assigned": true,
		},
		"market_surveillance": {
			"cooperation_committed": true,
		},
		"reporting": {
			"process_to_enisa_documented": true,
		},
		"risk_assessment": {
			"in_technical_documentation": true,
			"performed": true,
		},
		"support_period": {
			"declared": true,
			"years": 5,
		},
		"third_party_components": {
			"due_diligence_performed": true,
			"vulnerabilities_monitored": true,
		},
		"user_information": {
			"instructions_provided": true,
			"security_relevant_info_included": true,
		},
		"vulnerability_handling": {
			"lifetime_coverage": true,
		},
	},
	"online_marketplace": {
		"affected_buyers_notified": true,
		"authority_takedown_order_actioned": true,
		"authority_takedown_order_hours_pending": 50,
		"authority_takedown_order_received": true,
		"buyers_affected": true,
		"cooperation": {
			"with_authorities_documented": true,
		},
		"is_marketplace_provider": true,
		"listing_removed": true,
		"manufacturer_notified": true,
		"non_compliant_listing_identified": true,
		"process_documentation": {
			"cra_process_documented": true,
		},
		"products_offered": {
			"includes_products_with_digital_elements": true,
		},
		"random_checks": {
			"performed": true,
			"sample_size_pct": 5,
		},
		"reporting_channel": {
			"exists_for_consumers": true,
		},
		"severity": "high",
		"single_point_of_contact": {
			"designated_for_authorities": true,
			"designated_for_end_users": true,
		},
		"trader_due_diligence": {
			"cra_compliance_attested": true,
			"identity_verified": true,
		},
	},
	"oss_steward": {
		"actively_exploited_vuln_known": true,
		"affected_users_informed": true,
		"can_ensure_corrective_action": true,
		"cooperation": {
			"policy_providable_on_reasoned_request": true,
			"with_market_surveillance": true,
		},
		"csirt_coordinator_identified": true,
		"cvd_policy": {
			"in_place": true,
		},
		"cybersecurity_policy": {
			"covers_secure_development_practices": true,
			"covers_vulnerability_handling": true,
			"documented_verifiably": true,
			"fosters_voluntary_reporting_and_sharing": true,
		},
		"ensures_product_viability": true,
		"incident_notified": true,
		"involved_in_development": true,
		"is_legal_person": true,
		"not_manufacturer_of_product": true,
		"oss_product_intended_for_commercial_activities": true,
		"provides_development_infrastructure": true,
		"provides_systematic_sustained_support": true,
		"severe_incident_affecting_provided_infrastructure": true,
		"vulnerability_notified": true,
		"vulnerability_reporting_channel": {
			"exists": true,
		},
	},
	"substantial_modification": {
		"assessment_process": {
			"criteria_published": true,
			"documented": true,
			"reviewed_annually": true,
		},
		"changes": {
			"added_network_connectivity": true,
			"cryptographic_primitive_changed": true,
			"cryptographic_review_performed": true,
			"risk_assessment_updated": true,
			"sbom_changed": true,
			"sbom_published_after_change": true,
			"security_relevant": true,
			"users_notified": true,
		},
		"conformity_reassessment": {
			"performed": true,
			"scope_appropriate": true,
		},
		"declaration_of_conformity_reissued": true,
		"documentation_updated": true,
		"modification_classified_substantial": true,
		"modifier_assumed_manufacturer_obligations": true,
		"modifier_is_not_original_manufacturer": true,
		"support_period_recommitted": true,
	},
	"technical_documentation": {
		"declaration_of_conformity": {
			"signed": true,
		},
		"design": {
			"architecture_diagram": true,
			"cybersecurity_controls_mapped": true,
		},
		"product": {
			"classification": "critical",
		},
		"product_description": {
			"documented": true,
			"intended_purpose": true,
			"support_period_declared": true,
		},
		"retention": {
			"available_on_request": true,
			"maintained_10_years": true,
		},
		"risk_assessment": {
			"documented": true,
			"mitigations_documented": true,
			"threats_identified": true,
		},
		"sbom": {
			"included": true,
		},
		"testing": {
			"results_documented": true,
			"third_party_assessment": true,
		},
		"vuln_process": {
			"documented": true,
		},
	},
	"user_information": {
		"cybersecurity_properties": {
			"described": true,
		},
		"decommissioning": {
			"guidance_provided": true,
		},
		"intended_purpose": {
			"described": true,
			"security_environment_specified": true,
		},
		"languages": {
			"member_state_languages_covered": true,
		},
		"manufacturer": {
			"contact_for_vulnerability_reports": true,
			"electronic_contact_provided": true,
			"name_provided": true,
			"postal_address_provided": true,
		},
		"product_identifier": {
			"batch_or_serial_provided": true,
			"type_provided": true,
			"version_provided": true,
		},
		"readability": {
			"appropriate_for_users": true,
		},
		"risks_and_threats": {
			"documented": true,
		},
		"sbom_access": {
			"disclosed_to_user": true,
		},
		"single_point_of_contact": {
			"published": true,
		},
		"support_period": {
			"disclosed": true,
			"end_of_support_date_disclosed": true,
		},
		"updates": {
			"access_method_disclosed": true,
			"installation_instructions": true,
		},
	},
	"vulnerability_handling": {
		"coordinated_disclosure": {
			"contact_point_provided": true,
			"policy_published": true,
		},
		"disclosure": {
			"cve_assigned": true,
			"public_disclosure_after_patch": true,
		},
		"mitigation": {
			"compensating_controls_documented": true,
		},
		"remediation": {
			"process_documented": true,
			"security_updates_provided_free": true,
		},
		"reporting_channel": {
			"exists": true,
		},
		"sbom": {
			"components_documented": true,
			"machine_readable_format": true,
			"maintained": true,
		},
		"support_period_years": 5,
		"testing": {
			"regular_testing_performed": true,
			"test_results_reviewed": true,
		},
		"update_distribution": {
			"secure_channel": true,
			"timely_delivery": true,
		},
	},
}

_iso_ok := {"cryptographic_policy": true, "key_management": true, "key_generation_secure": true, "key_distribution_secure": true, "key_usage_controlled": true, "key_destruction_secure": true}

# ── Mutations ───────────────────────────────────────────────────────────────
# Every leaf of an all-pass fixture is evidence. A boolean is swapped for the strings "false", "true"
# and "no", for null, 0 and 1; a number for its string form and null; a text value for null and a
# number; and every leaf is removed once. None of the resulting inputs may pass.
_leaves(fx) := [[path, value] |
	walk(fx, [path, value])
	not is_object(value)
]

_swaps(value) := ["false", "true", "no", null, 0, 1] if is_boolean(value)

_swaps(value) := [sprintf("%v", [value]), null] if is_number(value)

_swaps(value) := [null, 7] if is_string(value)

_bad_inputs(fx) := array.concat(
	[{"case": sprintf("%s := %s", [concat(".", path), json.marshal(swap)]), "input": json.patch(fx, [{"op": "replace", "path": path, "value": swap}])} |
		some [path, value] in _leaves(fx)
		some swap in _swaps(value)
	],
	[{"case": sprintf("%s removed", [concat(".", path)]), "input": json.patch(fx, [{"op": "remove", "path": path}])} |
		some [path, _] in _leaves(fx)
	],
)

test_empty_input_fails_every_module if {
	every name, _ in fixtures {
		not data.cra[name].compliant with input as {} with data.iso27001.cryptography as _iso_ok
	}
}

# No `with input`: the input document is undefined, as when the caller sends no input at all.
test_no_input_document_fails_like_empty_input if {
	every name, _ in fixtures {
		on_empty := data.cra[name].violation with input as {} with data.iso27001.cryptography as _iso_ok
		on_nothing := data.cra[name].violation with data.iso27001.cryptography as _iso_ok
		count(on_empty) > 0
		on_nothing == on_empty
	}
}

test_all_pass_fixture_passes_every_module if {
	every name, fx in fixtures {
		data.cra[name].compliant with input as fx with data.iso27001.cryptography as _iso_ok
		count(data.cra[name].violation) == 0 with input as fx with data.iso27001.cryptography as _iso_ok
	}
}

_passing_mutations := [sprintf("%s: %s", [name, bad.case]) |
	some name, fx in fixtures
	some bad in _bad_inputs(fx)
	data.cra[name].compliant with input as bad.input with data.iso27001.cryptography as _iso_ok
]

test_no_mutated_fixture_passes if {
	_passing_mutations == []
}

# The audit's case: every yes/no fact of the vulnerability-handling module sent as the string "false".
test_vulnerability_handling_string_false_fails_every_check if {
	inp := {"vulnerability_handling": object.union(
		{section: {field: "false" | some field, _ in facts} |
			some section, facts in fixtures.vulnerability_handling.vulnerability_handling
			is_object(facts)
		},
		{"support_period_years": 5},
	)}
	r := data.cra.vulnerability_handling.compliance_report with input as inp
	r.compliant == false
	r.violation_count == 15
	every v in r.violations {
		contains(v, "is not a boolean (got string)")
	}
}

test_finding_names_the_evidence_problem if {
	base := fixtures.essential_requirements
	some [path, value] in _leaves(base)
	value == true
	label := concat(".", path)
	missing := data.cra.essential_requirements.violation with input as json.patch(base, [{"op": "remove", "path": path}])
	some m in missing
	endswith(m, sprintf("evidence missing: %s not collected", [label]))
	wrong := data.cra.essential_requirements.violation with input as json.patch(base, [{"op": "replace", "path": path, "value": "false"}])
	some w in wrong
	endswith(w, sprintf("evidence invalid: %s is not a boolean (got string)", [label]))
	collected_false := data.cra.essential_requirements.violation with input as json.patch(base, [{"op": "replace", "path": path, "value": false}])
	count(collected_false) == 1
	every f in collected_false {
		not contains(f, "evidence")
	}
}

# A condition is stated, never inferred from a missing field; an explicit false is "does not apply".
test_conditions_must_be_stated if {
	undeclared := data.cra.incident_reporting.violation with input as {"incident_reporting": {}}
	"CRA Art.14(1): applicability not determined — evidence missing: incident_reporting.actively_exploited_vuln_known not collected" in undeclared
	stated := json.patch(fixtures.incident_reporting, [{"op": "replace", "path": ["incident_reporting", field], "value": false} |
		some field in ["actively_exploited_vuln_known", "severe_incident_occurred", "users_impacted"]
	])
	data.cra.incident_reporting.compliant with input as stated
	as_text := json.patch(stated, [{"op": "replace", "path": ["incident_reporting", "severe_incident_occurred"], "value": "false"}])
	not data.cra.incident_reporting.compliant with input as as_text
	some t in data.cra.incident_reporting.violation with input as as_text
	endswith(t, "evidence invalid: incident_reporting.severe_incident_occurred is not a boolean (got string)")
}

# A clock is evidence whenever its obligation is on, even when the report is said to have been sent.
test_incident_clock_as_text_is_not_a_pass if {
	inp := json.patch(fixtures.incident_reporting, [{"op": "replace", "path": ["incident_reporting", "hours_since_aware_of_vuln"], "value": "80"}])
	not data.cra.incident_reporting.compliant with input as inp
}

# ── Orchestrator ────────────────────────────────────────────────────────────
test_main_passes_the_all_pass_input if {
	r := data.cra.main.compliance_report with input as all_pass_input
		with data.iso27001.cryptography as _iso_ok
		with data.supply_chain.slsa.violations as set()
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
}

test_main_string_false_everywhere_fails_like_missing_evidence if {
	as_text := json.patch(all_pass_input, [{"op": "replace", "path": path, "value": "false"} |
		some [path, value] in _leaves(all_pass_input)
		is_boolean(value)
	])
	r := data.cra.main.compliance_report with input as as_text
		with data.iso27001.cryptography as _iso_ok
		with data.supply_chain.slsa.violations as set()
	r.compliant == false
	r.violation_count > 150
	r.failed_controls <= r.total_controls
}
