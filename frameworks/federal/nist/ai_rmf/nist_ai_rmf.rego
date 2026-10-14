# NIST AI RMF 1.0 — fact checks (collector facts under input.govern, input.map, input.measure, input.manage,
# input.ai_system). Each violation below is labelled with the AI RMF 1.0 subcategory (NIST AI 100-1, Section 5,
# Tables 1-4) it decides in nist.ai_rmf.main. The checks predate the 72-subcategory catalog and most carried a
# subcategory label that did not match the Core text. A check keeps deciding a subcategory only when it tests that
# subcategory's outcome as the Core prints it (mapped by what the check tests, not by its old label); the other
# 22 checks were removed and their lineage is the `legacy` data table at the end (old label, facts read,
# reason). Every kept check is fail-closed: a fact that is missing or not exactly true is a violation.
#
# Kept (15 checks -> 14 subcategories):
#   input.govern.ai_governance_roles_defined            old label GOVERN 1.1                 -> GOVERN 2.1
#   input.govern.ai_risk_tolerance_defined              old label GOVERN 1.2                 -> MAP 1.5
#   input.govern.team_diversity_considered              old label GOVERN 1.4                 -> GOVERN 3.1
#   input.govern.organizational_training_on_ai_risk     old label GOVERN 1.5                 -> GOVERN 2.2
#   input.map.intended_use_documented                   old label MAP 1.1                    -> MAP 1.1
#   input.measure.ai_risk_metrics_defined               old label MEASURE 1.1                -> MEASURE 1.1
#   input.measure.bias_testing_conducted                old label MEASURE 2.2                -> MEASURE 2.11
#   input.measure.performance_monitored_post_deployment old label MEASURE 2.7                -> MEASURE 2.4
#   input.measure.privacy_risk_assessed                 old label MEASURE 2.10               -> MEASURE 2.10
#   input.measure.explainability_assessed               old label MEASURE 2.11               -> MEASURE 2.9
#   input.measure.regular_risk_assessments              old label MEASURE 4.1                -> MEASURE 3.1
#   input.manage.risk_treatment_plans_documented        old label MANAGE 1.1                 -> MANAGE 1.3
#   input.manage.human_override_available               old label MANAGE 2.4                 -> MANAGE 2.4
#   input.manage.retire_plan_documented                 old label MANAGE 4.2                 -> GOVERN 1.7
#   input.ai_system.fairness_assessed                   old label NIST AI RMF (Trustworthy)  -> MEASURE 2.11

# METADATA
# title: "NIST AI RMF 1.0 — fact checks labelled with the AI 100-1 Core subcategory they decide"
# custom:
#   class: compliance
#   framework: nist_ai_rmf
#   source: nist
#   domains: [us-federal, ai]
#   coverage:
#     checks: 15
#     cited: 14
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package nist.ai_rmf

import rego.v1

violation contains "NIST AI RMF GOVERN 2.1: AI governance roles and responsibilities are not defined. Designate accountability for AI risk management." if {
	not input.govern.ai_governance_roles_defined == true
}

violation contains "NIST AI RMF MAP 1.5: AI risk tolerance has not been defined. Organizations must establish acceptable risk levels for AI systems." if {
	not input.govern.ai_risk_tolerance_defined == true
}

violation contains "NIST AI RMF GOVERN 3.1: Team diversity has not been considered in AI development. Diverse teams reduce the risk of bias in AI systems." if {
	not input.govern.team_diversity_considered == true
}

violation contains "NIST AI RMF GOVERN 2.2: Organizational training on AI risk has not been conducted. Workforce must understand AI risks and responsibilities." if {
	not input.govern.organizational_training_on_ai_risk == true
}

violation contains "NIST AI RMF MAP 1.1: AI system intended use is not documented. Document intended uses, users, and deployment context." if {
	not input.map.intended_use_documented == true
}

violation contains "NIST AI RMF MEASURE 1.1: AI risk metrics are not defined. Establish quantitative and qualitative measures for AI risks." if {
	not input.measure.ai_risk_metrics_defined == true
}

violation contains "NIST AI RMF MEASURE 2.11: Bias testing has not been conducted. Test for demographic biases and disparate impacts across population groups." if {
	not input.measure.bias_testing_conducted == true
}

violation contains "NIST AI RMF MEASURE 2.4: AI performance is not monitored post-deployment. Ongoing monitoring is required to detect performance degradation and drift." if {
	not input.measure.performance_monitored_post_deployment == true
}

violation contains "NIST AI RMF MEASURE 2.10: Privacy risks from AI have not been assessed. Evaluate data privacy risks including inference attacks." if {
	not input.measure.privacy_risk_assessed == true
}

violation contains "NIST AI RMF MEASURE 2.9: AI explainability has not been assessed. Evaluate the degree to which AI decisions can be explained to affected parties." if {
	not input.measure.explainability_assessed == true
}

violation contains "NIST AI RMF MEASURE 3.1: Regular risk reassessments are not scheduled. AI risks must be reassessed as the system and its context evolve." if {
	not input.measure.regular_risk_assessments == true
}

violation contains "NIST AI RMF MANAGE 1.3: Risk treatment plans are not documented. Document how each identified risk will be mitigated, accepted, transferred, or avoided." if {
	not input.manage.risk_treatment_plans_documented == true
}

violation contains "NIST AI RMF MANAGE 2.4: No human override capability. AI systems making consequential decisions must support human override." if {
	not input.manage.human_override_available == true
}

violation contains "NIST AI RMF GOVERN 1.7: No AI system retirement plan. Document how the system will be safely retired and what happens to its data and models." if {
	not input.manage.retire_plan_documented == true
}

violation contains "NIST AI RMF MEASURE 2.11: AI system fairness has not been assessed. Evaluate and document fairness across demographic groups." if {
	not input.ai_system.fairness_assessed == true
}

# Lineage of the fact checks this module no longer evaluates (data only, no rule behind it, not a control).
# Keyed by the fact the check read. old_label: the subcategory label the check carried; reason: why it does not
# decide one AI RMF 1.0 subcategory. Each subcategory is decided in nist.ai_rmf.main on its own basis.
legacy := {
	"govern.ai_risk_policy_documented": {
		"fact_read": "input.govern.ai_risk_policy_documented",
		"old_label": "GOVERN",
		"legacy_message": "No AI risk management policy documented. Organizations must establish policies for AI risk management.",
		"status": "unmapped",
		"reason": "category-level (GOVERN 1 as a whole); no single subcategory is a documented AI risk policy",
	},
	"govern.ai_lifecycle_policies": {
		"fact_read": "input.govern.ai_lifecycle_policies",
		"old_label": "GOVERN 1.3",
		"legacy_message": "No policies covering the full AI lifecycle. Policies must cover design, development, deployment, evaluation, and retirement.",
		"status": "unmapped",
		"reason": "spans GOVERN 1.2-1.7 (policies across the lifecycle); not one subcategory",
	},
	"govern.policies_reviewed_regularly": {
		"fact_read": "input.govern.policies_reviewed_regularly",
		"old_label": "GOVERN 1.6",
		"legacy_message": "AI risk policies are not reviewed regularly. Policies must be updated to reflect evolving AI capabilities and risks.",
		"status": "unmapped",
		"reason": "partial: GOVERN 1.5 is ongoing monitoring and periodic review of the risk management process with defined roles and review frequency; a policy review alone does not test that outcome",
	},
	"govern.accountability_mechanism": {
		"fact_read": "input.govern.accountability_mechanism",
		"old_label": "GOVERN 6.1",
		"legacy_message": "No accountability mechanism for AI decisions. Clear accountability is required for AI system outcomes.",
		"status": "unmapped",
		"reason": "GOVERN 6.1 is third-party risk; accountability for AI outcomes spans GOVERN 2.1/2.3 and is not one subcategory",
	},
	"govern.third_party_risk_considered": {
		"fact_read": "input.govern.third_party_risk_considered",
		"old_label": "GOVERN 6.2",
		"legacy_message": "Third-party AI risks are not assessed. Risks from AI components, models, and services obtained from third parties must be evaluated.",
		"status": "unmapped",
		"reason": "partial: GOVERN 6.1 requires policies and procedures for third-party risk including IP infringement, MANAGE 3.1 regular monitoring with controls; an assessment of third-party risk tests neither whole outcome",
	},
	"map.impacted_populations_identified": {
		"fact_read": "input.map.impacted_populations_identified",
		"old_label": "MAP 1.5",
		"legacy_message": "Impacted populations have not been identified. Assess who is affected by the AI system's outputs and decisions.",
		"status": "unmapped",
		"reason": "MAP 1.5 is risk tolerance; identifying impacted populations is part of MAP 1.1 and MAP 5.1, not the whole of either",
	},
	"map.risk_categories_identified": {
		"fact_read": "input.map.risk_categories_identified",
		"old_label": "MAP 1.6",
		"legacy_message": "AI risk categories have not been identified. Categorize risks including bias, privacy, security, and accuracy.",
		"status": "unmapped",
		"reason": "MAP 1.6 is system requirements; risk categorisation has no single subcategory in the Core",
	},
	"map.known_failure_modes_documented": {
		"fact_read": "input.map.known_failure_modes_documented",
		"old_label": "MAP 2.1",
		"legacy_message": "Known failure modes are not documented. Identify and document how the AI system can fail.",
		"status": "unmapped",
		"reason": "MAP 2.1 is task and method definition; failure modes are part of MAP 2.2 knowledge limits, not its whole outcome",
	},
	"map.context_specific_risks_assessed": {
		"fact_read": "input.map.context_specific_risks_assessed",
		"old_label": "MAP 2.2",
		"legacy_message": "Context-specific risks have not been assessed. Evaluate risks in the specific deployment environment.",
		"status": "unmapped",
		"reason": "MAP 2.2 is knowledge limits and human oversight documentation; context-specific risk assessment spans MAP 1 and MAP 5",
	},
	"map.human_ai_interaction_considered": {
		"fact_read": "input.map.human_ai_interaction_considered",
		"old_label": "MAP 3.1",
		"legacy_message": "Human-AI interaction risks have not been considered. Assess how humans interact with and rely on the AI system.",
		"status": "unmapped",
		"reason": "MAP 3.1 is potential benefits; human-AI configuration is split over GOVERN 3.2, MAP 3.5 and MEASURE 2.8",
	},
	"map.organizational_risk_tolerance_applied": {
		"fact_read": "input.map.organizational_risk_tolerance_applied",
		"old_label": "MAP 5.1",
		"legacy_message": "Organizational risk tolerance has not been applied to AI risk prioritization. Prioritize risks based on organizational risk tolerance.",
		"status": "unmapped",
		"reason": "MAP 5.1 is likelihood and magnitude of impacts; MANAGE 1.2 prioritises on impact, likelihood and resources, not risk tolerance",
	},
	"measure.evaluation_methods_appropriate": {
		"fact_read": "input.measure.evaluation_methods_appropriate",
		"old_label": "MEASURE 1.3",
		"legacy_message": "Evaluation methods have not been assessed for appropriateness. Evaluation methods must be fit for the AI use case.",
		"status": "unmapped",
		"reason": "MEASURE 1.3 is independent assessors; MEASURE 1.2 regular assessment of metric appropriateness and control effectiveness is wider than this check",
	},
	"measure.adversarial_testing_conducted": {
		"fact_read": "input.measure.adversarial_testing_conducted",
		"old_label": "MEASURE 2.5",
		"legacy_message": "Adversarial testing (red-teaming) has not been conducted. Test AI system robustness against adversarial inputs.",
		"status": "unmapped",
		"reason": "partial: MEASURE 2.7 evaluates and documents security and resilience as a whole; red-teaming is one method within it",
	},
	"measure.uncertainty_quantified": {
		"fact_read": "input.measure.uncertainty_quantified",
		"old_label": "MEASURE 2.6",
		"legacy_message": "AI output uncertainty is not quantified. AI systems should communicate confidence levels and uncertainty.",
		"status": "unmapped",
		"reason": "no Core subcategory is uncertainty quantification (MEASURE 2.6 is safety)",
	},
	"manage.residual_risks_accepted_by_authority": {
		"fact_read": "input.manage.residual_risks_accepted_by_authority",
		"old_label": "MANAGE 1.3",
		"legacy_message": "Residual risks have not been formally accepted by an authorizing authority. Formal risk acceptance is required.",
		"status": "unmapped",
		"reason": "MANAGE 1.4 documents negative residual risks to acquirers and end users; formal acceptance by an authority is not that outcome",
	},
	"manage.incident_response_for_ai": {
		"fact_read": "input.manage.incident_response_for_ai",
		"old_label": "MANAGE 2.2",
		"legacy_message": "No incident response plan for AI failures. AI-specific incidents require dedicated response procedures.",
		"status": "unmapped",
		"reason": "partial: MANAGE 2.3 (respond to and recover from previously unknown risks) and MANAGE 4.3 (incidents communicated; response processes followed and documented) are each wider than a plan",
	},
	"manage.rollback_capability": {
		"fact_read": "input.manage.rollback_capability",
		"old_label": "MANAGE 3.1",
		"legacy_message": "No rollback capability for AI model changes. Ability to revert to previous model versions is required for risk management.",
		"status": "unmapped",
		"reason": "MANAGE 3.1 is third-party monitoring; rollback has no single Core subcategory",
	},
	"manage.affected_parties_can_appeal": {
		"fact_read": "input.manage.affected_parties_can_appeal",
		"old_label": "MANAGE 4.1",
		"legacy_message": "No mechanism for affected parties to contest AI decisions. Individuals affected by consequential AI decisions must have recourse.",
		"status": "unmapped",
		"reason": "partial: MEASURE 3.3 also requires integration into evaluation metrics; MANAGE 4.1 lists appeal as one element of a monitoring plan",
	},
	"ai_system.accuracy_benchmarks_met": {
		"fact_read": "input.ai_system.accuracy_benchmarks_met",
		"old_label": "NIST AI RMF (Trustworthy)",
		"legacy_message": "AI system does not meet defined accuracy benchmarks. Accuracy requirements must be defined and met before deployment.",
		"status": "unmapped",
		"reason": "trustworthiness characteristic, not a Core subcategory; MEASURE 2.3/2.5 measure and demonstrate performance and validity rather than a benchmark pass",
	},
	"ai_system.transparency_documentation": {
		"fact_read": "input.ai_system.transparency_documentation",
		"old_label": "NIST AI RMF (Trustworthy)",
		"legacy_message": "No transparency documentation for AI system. Document model architecture, training data, and known limitations.",
		"status": "unmapped",
		"reason": "trustworthiness characteristic; MEASURE 2.8 examines transparency and accountability risks, MAP 2.2 documents knowledge limits; not one subcategory",
	},
	"ai_system.security_hardened": {
		"fact_read": "input.ai_system.security_hardened",
		"old_label": "NIST AI RMF (Trustworthy)",
		"legacy_message": "AI system has not been security hardened. Protect against adversarial attacks, model theft, and data poisoning.",
		"status": "unmapped",
		"reason": "trustworthiness characteristic; MEASURE 2.7 evaluates security and resilience, it does not require hardening",
	},
	"ai_system.privacy_preserving": {
		"fact_read": "input.ai_system.privacy_preserving",
		"old_label": "NIST AI RMF (Trustworthy)",
		"legacy_message": "Privacy-preserving techniques have not been applied. Consider differential privacy, federated learning, or data minimization.",
		"status": "unmapped",
		"reason": "trustworthiness characteristic; MEASURE 2.10 examines privacy risk, it does not require privacy-enhancing techniques",
	},
}

# facts-basis subcategory -> the facts that decide it (read by nist.ai_rmf.main)
facts_for := {
	"GOVERN 1.7": ["input.manage.retire_plan_documented"],
	"GOVERN 2.1": ["input.govern.ai_governance_roles_defined"],
	"GOVERN 2.2": ["input.govern.organizational_training_on_ai_risk"],
	"GOVERN 3.1": ["input.govern.team_diversity_considered"],
	"MAP 1.1": ["input.map.intended_use_documented"],
	"MAP 1.5": ["input.govern.ai_risk_tolerance_defined"],
	"MEASURE 1.1": ["input.measure.ai_risk_metrics_defined"],
	"MEASURE 2.4": ["input.measure.performance_monitored_post_deployment"],
	"MEASURE 2.9": ["input.measure.explainability_assessed"],
	"MEASURE 2.10": ["input.measure.privacy_risk_assessed"],
	"MEASURE 2.11": ["input.measure.bias_testing_conducted", "input.ai_system.fairness_assessed"],
	"MEASURE 3.1": ["input.measure.regular_risk_assessments"],
	"MANAGE 1.3": ["input.manage.risk_treatment_plans_documented"],
	"MANAGE 2.4": ["input.manage.human_override_available"],
}
