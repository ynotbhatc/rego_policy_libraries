package eu_ai_act.high_risk

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# =============================================================================
# Article 9 — Risk Management System
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.risk_management.system_established == true
	msg := "Article 9: Continuous risk management system not established for this high-risk AI system as required throughout the entire lifecycle"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.risk_management.system_documented == true
	msg := "Article 9: Risk management system not documented; written records of risk identification, estimation, and evaluation measures are required"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.risk_management.risks_identified == true
	msg := "Article 9: Known and reasonably foreseeable risks to health, safety, or fundamental rights have not been identified and estimated"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.risk_management.risks_evaluated_with_representative_data == true
	msg := "Article 9: Risk evaluation not conducted against testing data representative of the intended purpose and conditions of use"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.risk_management.residual_risks_communicated == true
	msg := "Article 9: Residual risks after risk mitigation measures have not been communicated to deployers in instructions for use"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.risk_management.updated_post_market == true
	msg := "Article 9: Risk management system not updated based on post-market monitoring data; continuous lifecycle review is required"
}

# =============================================================================
# Article 10 — Data and Data Governance
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.data_governance.training_data_governance_established == true
	msg := "Article 10: Data governance practices not established for training datasets used to develop the high-risk AI system"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.data_governance.validation_data_governance_established == true
	msg := "Article 10: Data governance practices not established for validation datasets; separate validation from training data is required"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.data_governance.test_data_governance_established == true
	msg := "Article 10: Data governance practices not established for test datasets used to evaluate system performance"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.data_governance.datasets_examined_for_biases == true
	msg := "Article 10: Training, validation, and test datasets not examined for possible biases that could lead to discriminatory outcomes"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.data_governance.data_lineage_documented == true
	msg := "Article 10: Data provenance and lineage not documented; origin, collection method, and transformations of datasets must be recorded"
}

violations contains msg if {
	input.eu_ai_act.high_risk.data_governance.processes_personal_data == true
	not input.eu_ai_act.high_risk.data_governance.gdpr_compliant_practices == true
	msg := "Article 10: Personal data in training or evaluation datasets processed without GDPR-compliant data protection practices"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.data_governance.datasets_adequate_for_intended_purpose == true
	msg := "Article 10: Datasets not verified to be sufficiently adequate, representative, and free of errors for the intended purpose of the AI system"
}

# =============================================================================
# Article 11 — Technical Documentation
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.technical_documentation.prepared_before_market_placement == true
	msg := "Article 11: Technical documentation (per Annex IV) not prepared before the high-risk AI system was placed on the market or put into service"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.technical_documentation.kept_up_to_date == true
	msg := "Article 11: Technical documentation not kept up to date following material changes to the AI system or its intended purpose"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.technical_documentation.contains_annex_iv_content == true
	msg := "Article 11: Technical documentation does not contain all required elements specified in Annex IV of the EU AI Act"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.technical_documentation.available_to_national_authorities == true
	msg := "Article 11: Technical documentation not available or accessible to national competent authorities upon request"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.technical_documentation.describes_design_specifications == true
	msg := "Article 11: Technical documentation does not describe general design specifications, choices made, and assumptions relied upon"
}

# =============================================================================
# Article 12 — Record-Keeping and Logging
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.record_keeping.automatic_logging_enabled == true
	msg := "Article 12: Automatic logging of events during system operation not enabled; high-risk AI systems must generate logs throughout their operational lifetime"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.record_keeping.log_retention_period_adequate == true
	msg := "Article 12: Log retention period does not meet requirements; logs must be retained for an appropriate period aligned with legal obligations"
}

violations contains msg if {
	input.eu_ai_act.high_risk.record_keeping.is_biometric_system == true
	not input.eu_ai_act.high_risk.record_keeping.biometric_logs_retained_for_law_enforcement_duration == true
	msg := "Article 12: Biometric identification system logs not retained for the duration required for law enforcement use cases"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.record_keeping.logs_enable_post_hoc_audit == true
	msg := "Article 12: Logs do not enable post-hoc verification and monitoring of system performance by competent authorities"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.record_keeping.event_types_sufficient == true
	msg := "Article 12: Event types captured in logs are insufficient relative to the level of risk and the intended purpose of the system"
}

# =============================================================================
# Article 13 — Transparency and Information to Deployers
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.instructions_for_use_provided == true
	msg := "Article 13: Instructions for use not provided to deployers; high-risk AI systems must be accompanied by adequate instructions in accessible language"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.intended_purpose_disclosed == true
	msg := "Article 13: Intended purpose of the AI system not disclosed in instructions for use"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.accuracy_level_disclosed == true
	msg := "Article 13: Level of accuracy, robustness, and cybersecurity performance not disclosed in instructions for use"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.known_risks_disclosed == true
	msg := "Article 13: Known and foreseeable risks to health, safety, and fundamental rights not disclosed to deployers"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.human_oversight_measures_described == true
	msg := "Article 13: Human oversight measures not described in instructions for use; deployers must be informed of required oversight responsibilities"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.capability_limitations_disclosed == true
	msg := "Article 13: Technical capabilities and limitations of the AI system not disclosed, including circumstances where reliability may be compromised"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.transparency.residual_risks_disclosed_to_deployers == true
	msg := "Article 13: Residual risks not communicated to deployers in instructions for use"
}

# =============================================================================
# Article 14 — Human Oversight
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.human_oversight.oversight_measures_built_in == true
	not input.eu_ai_act.high_risk.human_oversight.oversight_measures_specified_for_deployers == true
	msg := "Article 14: Human oversight measures neither built into the system design nor specified for deployer implementation"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.human_oversight.effective_monitoring_by_natural_persons == true
	msg := "Article 14: System not designed to enable effective monitoring by natural persons during the period of use"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.human_oversight.halt_capability_provided == true
	msg := "Article 14: No capability provided to halt or interrupt system operation; deployers must be able to stop the system using a stop button or equivalent procedure"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.human_oversight.override_capability_provided == true
	msg := "Article 14: Deployers cannot disregard or override system outputs; capability to intervene in system operation is required"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.human_oversight.over_reliance_prevention_documented == true
	msg := "Article 14: No documented measures to prevent automation bias or over-reliance on AI system outputs by deployer staff"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.human_oversight.responsible_persons_identified == true
	msg := "Article 14: Natural persons responsible for human oversight not identified and assigned appropriate competence, authority, and resources"
}

# =============================================================================
# Article 15 — Accuracy, Robustness, and Cybersecurity
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.accuracy_robustness.accuracy_levels_specified == true
	msg := "Article 15: Accuracy levels for the high-risk AI system not specified and validated against representative datasets"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.accuracy_robustness.robustness_against_errors_demonstrated == true
	msg := "Article 15: Robustness of the AI system against errors, faults, and inconsistencies not demonstrated through appropriate testing"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.accuracy_robustness.resilience_against_manipulation_demonstrated == true
	msg := "Article 15: Resilience against hostile third-party attempts to alter system use, outputs, or performance not demonstrated"
}

violations contains msg if {
	input.eu_ai_act.high_risk.accuracy_robustness.safety_critical_system == true
	not input.eu_ai_act.high_risk.accuracy_robustness.technical_redundancy_solutions_implemented == true
	msg := "Article 15: Technical redundancy solutions not implemented for safety-critical high-risk AI system; backup or fail-safe mechanisms are required"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.accuracy_robustness.cybersecurity_measures_implemented == true
	msg := "Article 15: Cybersecurity measures not implemented to protect the AI system against unauthorized access, tampering, and data poisoning"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.accuracy_robustness.metrics_publicly_disclosed == true
	msg := "Article 15: Performance metrics including accuracy and robustness not disclosed in technical documentation or instructions for use"
}

# =============================================================================
# Article 16 — Obligations of Providers
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.provider_obligations.conformity_assessment_completed == true
	msg := "Article 16: Conformity assessment not completed before placing the high-risk AI system on the EU market or putting it into service"
}

violations contains msg if {
	input.eu_ai_act.high_risk.provider_obligations.ce_marking_required == true
	not input.eu_ai_act.high_risk.provider_obligations.ce_marking_affixed == true
	msg := "Article 16: CE marking not affixed; high-risk AI systems must bear CE marking indicating conformity with the EU AI Act"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.provider_obligations.eu_declaration_of_conformity_drawn_up == true
	msg := "Article 16: EU Declaration of Conformity not drawn up; providers must declare that the high-risk AI system meets all applicable requirements"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.provider_obligations.registered_in_eu_database == true
	msg := "Article 16: High-risk AI system (Annex III use case) not registered in the EU database for high-risk AI systems before market placement"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.provider_obligations.post_market_monitoring_in_place == true
	msg := "Article 16: Post-market monitoring system not established; providers must actively collect and analyze data on system performance after deployment"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.provider_obligations.serious_incident_reporting_procedure == true
	msg := "Article 16: Serious incident reporting procedure not established; providers must report serious incidents to national competent authorities"
}

# =============================================================================
# Article 17 — Quality Management System
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.high_risk.quality_management.qms_established == true
	msg := "Article 17: Quality management system not established; providers of high-risk AI systems must implement a documented QMS covering all provider obligations"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.quality_management.written_compliance_policies == true
	msg := "Article 17: Written policies and procedures for regulatory compliance not established as part of the quality management system"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.quality_management.resource_management_documented == true
	msg := "Article 17: Resource management procedures (technical, human, computational) not documented in the quality management system"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.quality_management.competence_awareness_training_procedures == true
	msg := "Article 17: Competence, awareness, and training procedures for personnel involved in AI system development not established"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.quality_management.design_development_control_procedures == true
	msg := "Article 17: Design and development control procedures not established, including design reviews, verification, and validation activities"
}

violations contains msg if {
	not input.eu_ai_act.high_risk.quality_management.corrective_action_procedures == true
	msg := "Article 17: Corrective action procedures for non-conformities and incidents not established in the quality management system"
}

# =============================================================================
# Compliance report
# =============================================================================

compliance_report := {
	"module": "high_risk_requirements",
	"standard": "EU AI Act — Title III, Articles 6-49",
	"applies_from": "August 2026",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"articles_assessed": [
		"Article 9 — Risk Management System",
		"Article 10 — Data and Data Governance",
		"Article 11 — Technical Documentation",
		"Article 12 — Record-Keeping and Logging",
		"Article 13 — Transparency and Information to Deployers",
		"Article 14 — Human Oversight",
		"Article 15 — Accuracy, Robustness, and Cybersecurity",
		"Article 16 — Obligations of Providers",
		"Article 17 — Quality Management System",
	],
}
