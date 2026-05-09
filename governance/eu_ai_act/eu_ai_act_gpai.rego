package eu_ai_act.gpai

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# =============================================================================
# Article 53 — Obligations for All GPAI Model Providers
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.technical_documentation_drawn_up == true
	msg := "Article 53.1: Technical documentation for the GPAI model not drawn up and maintained in accordance with Annex XI requirements"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.technical_documentation_kept_current == true
	msg := "Article 53.1: GPAI model technical documentation not kept up to date following material changes to the model or its capabilities"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.information_provided_to_downstream_providers == true
	msg := "Article 53.1: Information and documentation not provided to downstream providers intending to integrate the GPAI model into their AI systems"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.downstream_documentation_adequate == true
	msg := "Article 53.1: Documentation provided to downstream providers does not adequately describe the model's capabilities, limitations, and conditions of use"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.copyright_compliance_policy_established == true
	msg := "Article 53.1(c): Copyright compliance policy not established; GPAI model providers must implement a policy to respect copyright law in training data"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.copyright_compliance_policy_published == true
	msg := "Article 53.1(c): Copyright compliance policy not made publicly available; transparency about training data copyright practices is required"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.training_data_summary_published == true
	msg := "Article 53.1(d): Summary of training data used to develop the GPAI model not published and made publicly available"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.training_data_summary_adequate == true
	msg := "Article 53.1(d): Published summary of training data is not sufficiently detailed to enable understanding of the model's capabilities and limitations"
}

violations contains msg if {
	not input.eu_ai_act.gpai.article_53.model_cards_or_equivalent == true
	msg := "Article 53: No model card or equivalent technical summary document available describing intended use cases, known limitations, and evaluation results"
}

# =============================================================================
# Article 54 — Authorized Representatives for Non-EU Providers
# =============================================================================

violations contains msg if {
	input.eu_ai_act.gpai.article_54.provider_established_outside_eu == true
	not input.eu_ai_act.gpai.article_54.authorized_representative_designated == true
	msg := "Article 54: GPAI model provider established outside the EU has not designated an authorized representative established in the EU"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_54.provider_established_outside_eu == true
	not input.eu_ai_act.gpai.article_54.representative_has_full_mandate == true
	msg := "Article 54: Designated EU authorized representative does not hold a full mandate to act on behalf of the provider and be held responsible for obligations"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_54.provider_established_outside_eu == true
	not input.eu_ai_act.gpai.article_54.representative_registered_with_national_authority == true
	msg := "Article 54: Authorized representative not registered with the relevant national competent authority in the EU member state of establishment"
}

# =============================================================================
# Article 55 — Systemic Risk Classification and Obligations (>10^25 FLOPs)
# =============================================================================

violations contains msg if {
	input.eu_ai_act.gpai.article_55.training_flops_exceeds_threshold == true
	not input.eu_ai_act.gpai.article_55.notified_to_ai_office == true
	msg := "Article 55.1: GPAI model with training computation exceeding 10^25 FLOPs not notified to the AI Office within two weeks of classification"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.training_flops_exceeds_threshold == true
	not input.eu_ai_act.gpai.article_55.notification_timely == true
	msg := "Article 55.1: Notification to AI Office for systemic-risk GPAI model not submitted within the two-week deadline after reaching the 10^25 FLOPs threshold"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.model_evaluation_conducted == true
	msg := "Article 55.1(a): Model evaluation including adversarial testing not conducted for GPAI model with systemic risk; standardized protocols must be followed"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.adversarial_testing_performed == true
	msg := "Article 55.1(a): Adversarial testing not performed on systemic-risk GPAI model to assess and mitigate systemic risks including critical infrastructure harms"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.serious_incident_reporting_established == true
	msg := "Article 55.1(b): Serious incident reporting procedure not established for systemic-risk GPAI model; incidents must be reported to the AI Office without undue delay"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.cybersecurity_measures_proportionate == true
	msg := "Article 55.1(c): Cybersecurity measures not implemented or not proportionate to the systemic risks posed by the GPAI model"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.physical_cybersecurity_protections == true
	msg := "Article 55.1(c): Physical and logical access controls to protect model weights, parameters, and infrastructure not implemented for systemic-risk GPAI model"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.energy_efficiency_reporting_provided == true
	msg := "Article 55.1(d): Energy efficiency reporting not provided to the European Commission for systemic-risk GPAI model; power consumption data must be disclosed"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_55.systemic_risk_model == true
	not input.eu_ai_act.gpai.article_55.systemic_risk_mitigation_measures_documented == true
	msg := "Article 55: Systemic risk mitigation measures not documented; providers of systemic-risk GPAI models must maintain records of identified risks and mitigation actions"
}

# =============================================================================
# Article 56 — Codes of Practice
# =============================================================================

violations contains msg if {
	not input.eu_ai_act.gpai.article_56.code_of_practice_adhered_to == true
	not input.eu_ai_act.gpai.article_56.equivalent_compliance_demonstrated == true
	msg := "Article 56: GPAI model provider has not adhered to a relevant code of practice or demonstrated equivalent compliance through alternative means accepted by the AI Office"
}

violations contains msg if {
	input.eu_ai_act.gpai.article_56.equivalent_compliance_demonstrated == true
	not input.eu_ai_act.gpai.article_56.equivalent_compliance_documented == true
	msg := "Article 56: Equivalent compliance with GPAI code of practice claimed but technical and organizational measures demonstrating equivalence are not documented"
}

# =============================================================================
# Compliance report
# =============================================================================

compliance_report := {
	"module": "gpai_obligations",
	"standard": "EU AI Act — Title VIII, Articles 51-56",
	"applies_from": "August 2025",
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"articles_assessed": [
		"Article 53 — Obligations for all GPAI model providers",
		"Article 54 — Authorized representatives for non-EU providers",
		"Article 55 — Systemic risk classification and obligations (>10^25 FLOPs)",
		"Article 56 — Codes of practice",
	],
}
