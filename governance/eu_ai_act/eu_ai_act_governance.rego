package eu_ai_act.governance

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# =============================================================================
# Article 26 — Obligations of Deployers
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.governance.deployer.uses_system_per_provider_instructions == true
	msg := "Article 26.1: High-risk AI system not used in accordance with provider's instructions for use; deployers must follow intended purpose and usage conditions"
}

violations contains msg if {
	not input.eu_ai_act.governance.deployer.human_oversight_assigned == true
	msg := "Article 26.1: Human oversight not assigned to competent natural persons with the authority, competence, and resources to perform effective oversight"
}

violations contains msg if {
	not input.eu_ai_act.governance.deployer.oversight_persons_adequately_trained == true
	msg := "Article 26.1: Persons assigned to human oversight not provided with adequate training, instructions, and authority to identify and address anomalies"
}

violations contains msg if {
	input.eu_ai_act.governance.deployer.high_risk_public_or_private_sector == true
	not input.eu_ai_act.governance.deployer.fundamental_rights_impact_assessment_conducted == true
	msg := "Article 26.9 / Article 27: Fundamental Rights Impact Assessment (FRIA) not conducted before deploying high-risk AI system in public or private sector context"
}

violations contains msg if {
	not input.eu_ai_act.governance.deployer.registered_use_in_eu_database == true
	input.eu_ai_act.governance.deployer.annex_iii_use_case == true
	msg := "Article 26.8: Deployer's use of Annex III high-risk AI system not registered in the EU database for high-risk AI systems"
}

violations contains msg if {
	not input.eu_ai_act.governance.deployer.data_breach_reporting_established == true
	msg := "Article 26: Data breach and serious incident reporting procedures not established for the deployed high-risk AI system"
}

violations contains msg if {
	not input.eu_ai_act.governance.deployer.input_data_relevance_verified == true
	msg := "Article 26.5: Deployer has not verified that input data is relevant and sufficiently representative for the intended purpose of the high-risk AI system"
}

# =============================================================================
# Article 27 — Fundamental Rights Impact Assessment (FRIA)
# =============================================================================

violations contains msg if {
	input.eu_ai_act.governance.fria.assessment_required == true
	not input.eu_ai_act.governance.fria.assessment_conducted == true
	msg := "Article 27: Fundamental Rights Impact Assessment (FRIA) not conducted before deploying high-risk AI in contexts affecting natural persons' rights"
}

violations contains msg if {
	input.eu_ai_act.governance.fria.assessment_required == true
	not input.eu_ai_act.governance.fria.affected_fundamental_rights_identified == true
	msg := "Article 27: FRIA completed but affected fundamental rights (dignity, non-discrimination, privacy, fair trial, etc.) not specifically identified and assessed"
}

violations contains msg if {
	input.eu_ai_act.governance.fria.assessment_required == true
	not input.eu_ai_act.governance.fria.notification_of_affected_persons_process == true
	msg := "Article 27: Process for notifying affected persons about the high-risk AI deployment and their rights not established as part of the FRIA"
}

violations contains msg if {
	input.eu_ai_act.governance.fria.assessment_required == true
	not input.eu_ai_act.governance.fria.results_available_to_competent_authorities == true
	msg := "Article 27: FRIA results not available to competent authorities upon request; assessments must be retained and accessible for regulatory review"
}

violations contains msg if {
	input.eu_ai_act.governance.fria.assessment_required == true
	not input.eu_ai_act.governance.fria.risk_mitigation_measures_identified == true
	msg := "Article 27: FRIA did not result in identification of risk mitigation measures for identified fundamental rights impacts"
}

# =============================================================================
# Article 28 — Obligations when Deployer Becomes Provider
# =============================================================================

violations contains msg if {
	input.eu_ai_act.governance.deployer_as_provider.substantially_modified_high_risk_ai == true
	not input.eu_ai_act.governance.deployer_as_provider.provider_obligations_assumed == true
	msg := "Article 28: Deployer has substantially modified a high-risk AI system but has not assumed full provider obligations; substantial modification triggers all Article 16 and 17 requirements"
}

violations contains msg if {
	input.eu_ai_act.governance.deployer_as_provider.placed_under_own_name_or_trademark == true
	not input.eu_ai_act.governance.deployer_as_provider.provider_obligations_assumed == true
	msg := "Article 28: Deployer has placed high-risk AI system on market under own name or trademark without assuming provider obligations; this constitutes acting as a provider"
}

violations contains msg if {
	input.eu_ai_act.governance.deployer_as_provider.provider_obligations_assumed == true
	not input.eu_ai_act.governance.deployer_as_provider.conformity_assessment_redone == true
	msg := "Article 28: Deployer acting as provider has not conducted a new conformity assessment after substantially modifying the high-risk AI system"
}

# =============================================================================
# Article 72 — Post-Market Monitoring
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.governance.post_market.monitoring_plan_established == true
	msg := "Article 72: Post-market monitoring plan not established; providers of high-risk AI must actively collect and analyze performance data after deployment"
}

violations contains msg if {
	not input.eu_ai_act.governance.post_market.monitoring_covers_annex_vii_content == true
	msg := "Article 72: Post-market monitoring plan does not address required elements specified in Annex VII of the EU AI Act"
}

violations contains msg if {
	not input.eu_ai_act.governance.post_market.serious_incidents_reported_to_authority == true
	msg := "Article 72: Serious incidents involving the high-risk AI system not reported to national competent authority without undue delay upon discovery"
}

violations contains msg if {
	not input.eu_ai_act.governance.post_market.near_misses_tracked == true
	msg := "Article 72: Near-miss events (incidents that did not cause harm but could have) not tracked and analyzed as part of post-market monitoring"
}

violations contains msg if {
	not input.eu_ai_act.governance.post_market.performance_metrics_collected == true
	msg := "Article 72: Performance metrics required by the post-market monitoring plan not systematically collected from deployed high-risk AI systems"
}

violations contains msg if {
	not input.eu_ai_act.governance.post_market.corrective_actions_taken_when_needed == true
	msg := "Article 72: Corrective actions not taken when post-market monitoring data indicates the AI system no longer meets applicable requirements"
}

# =============================================================================
# Article 77 — Fundamental Rights Authorities Access
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.governance.fundamental_rights_bodies.dpa_access_granted == true
	msg := "Article 77: Data Protection Authority (DPA) not granted access to documentation, logs, and conformity assessment records for fundamental rights oversight"
}

violations contains msg if {
	not input.eu_ai_act.governance.fundamental_rights_bodies.equality_body_access_granted == true
	msg := "Article 77: Equality body not granted access to documentation required for fundamental rights review of high-risk AI systems under their oversight mandate"
}

violations contains msg if {
	not input.eu_ai_act.governance.fundamental_rights_bodies.cooperation_procedure_established == true
	msg := "Article 77: No cooperation procedure established with fundamental rights bodies; providers and deployers must have a process for responding to access requests from these bodies"
}

# =============================================================================
# Article 78 — Confidentiality
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.governance.confidentiality.trade_secrets_protected_in_assessments == true
	msg := "Article 78: Trade secrets and commercially sensitive information not protected during conformity assessment processes and authority reviews"
}

violations contains msg if {
	not input.eu_ai_act.governance.confidentiality.competent_authority_confidentiality_binding == true
	msg := "Article 78: National competent authorities have not established binding confidentiality obligations for personnel handling commercially sensitive AI system information"
}

violations contains msg if {
	not input.eu_ai_act.governance.confidentiality.confidentiality_obligations_documented == true
	msg := "Article 78: Confidentiality obligations for information disclosed during conformity assessments and market surveillance activities not documented in agreements or procedures"
}

# =============================================================================
# Compliance report
# =============================================================================

compliance_report := {
	"module": "governance_deployer",
	"standard": "EU AI Act — Title VI, Articles 26-28, 72, 77-78",
	"applies_from": "August 2026",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"articles_assessed": [
		"Article 26 — Obligations of deployers",
		"Article 27 — Fundamental Rights Impact Assessment (FRIA)",
		"Article 28 — Obligations when deployer becomes provider",
		"Article 72 — Post-market monitoring",
		"Article 77 — Access for fundamental rights authorities",
		"Article 78 — Confidentiality",
	],
}
