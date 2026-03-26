package nist.ai_rmf

import rego.v1

# =============================================================================
# NIST AI Risk Management Framework (AI RMF 1.0)
# Published January 2023
# https://airc.nist.gov/
#
# Core Functions:
#   GOVERN — Cultivate organizational culture for AI risk management
#   MAP    — Categorize and prioritize AI risks
#   MEASURE — Analyze and assess AI risks
#   MANAGE  — Prioritize and address AI risks
#
# Input shape:
#   input.ai_system             - AI system being assessed
#   input.organization          - organizational context
#   input.govern                - GOVERN function implementation
#   input.map                   - MAP function implementation
#   input.measure               - MEASURE function implementation
#   input.manage                - MANAGE function implementation
# =============================================================================

# ---------------------------------------------------------------------------
# GOVERN — Cultivate organizational AI risk management culture
# ---------------------------------------------------------------------------

violation_govern contains msg if {
    not input.govern.ai_risk_policy_documented
    msg := "NIST AI RMF GOVERN: No AI risk management policy documented. Organizations must establish policies for AI risk management."
}

violation_govern contains msg if {
    not input.govern.ai_governance_roles_defined
    msg := "NIST AI RMF GOVERN 1.1: AI governance roles and responsibilities are not defined. Designate accountability for AI risk management."
}

violation_govern contains msg if {
    not input.govern.ai_risk_tolerance_defined
    msg := "NIST AI RMF GOVERN 1.2: AI risk tolerance has not been defined. Organizations must establish acceptable risk levels for AI systems."
}

violation_govern contains msg if {
    not input.govern.ai_lifecycle_policies
    msg := "NIST AI RMF GOVERN 1.3: No policies covering the full AI lifecycle. Policies must cover design, development, deployment, evaluation, and retirement."
}

violation_govern contains msg if {
    not input.govern.team_diversity_considered
    msg := "NIST AI RMF GOVERN 1.4: Team diversity has not been considered in AI development. Diverse teams reduce the risk of bias in AI systems."
}

violation_govern contains msg if {
    not input.govern.organizational_training_on_ai_risk
    msg := "NIST AI RMF GOVERN 1.5: Organizational training on AI risk has not been conducted. Workforce must understand AI risks and responsibilities."
}

violation_govern contains msg if {
    not input.govern.policies_reviewed_regularly
    msg := "NIST AI RMF GOVERN 1.6: AI risk policies are not reviewed regularly. Policies must be updated to reflect evolving AI capabilities and risks."
}

violation_govern contains msg if {
    not input.govern.accountability_mechanism
    msg := "NIST AI RMF GOVERN 6.1: No accountability mechanism for AI decisions. Clear accountability is required for AI system outcomes."
}

violation_govern contains msg if {
    not input.govern.third_party_risk_considered
    msg := "NIST AI RMF GOVERN 6.2: Third-party AI risks are not assessed. Risks from AI components, models, and services obtained from third parties must be evaluated."
}

# ---------------------------------------------------------------------------
# MAP — Categorize and contextualize AI risks
# ---------------------------------------------------------------------------

violation_map contains msg if {
    not input.map.intended_use_documented
    msg := "NIST AI RMF MAP 1.1: AI system intended use is not documented. Document intended uses, users, and deployment context."
}

violation_map contains msg if {
    not input.map.impacted_populations_identified
    msg := "NIST AI RMF MAP 1.5: Impacted populations have not been identified. Assess who is affected by the AI system's outputs and decisions."
}

violation_map contains msg if {
    not input.map.risk_categories_identified
    msg := "NIST AI RMF MAP 1.6: AI risk categories have not been identified. Categorize risks including bias, privacy, security, and accuracy."
}

violation_map contains msg if {
    not input.map.known_failure_modes_documented
    msg := "NIST AI RMF MAP 2.1: Known failure modes are not documented. Identify and document how the AI system can fail."
}

violation_map contains msg if {
    not input.map.context_specific_risks_assessed
    msg := "NIST AI RMF MAP 2.2: Context-specific risks have not been assessed. Evaluate risks in the specific deployment environment."
}

violation_map contains msg if {
    not input.map.human_ai_interaction_considered
    msg := "NIST AI RMF MAP 3.1: Human-AI interaction risks have not been considered. Assess how humans interact with and rely on the AI system."
}

violation_map contains msg if {
    not input.map.organizational_risk_tolerance_applied
    msg := "NIST AI RMF MAP 5.1: Organizational risk tolerance has not been applied to AI risk prioritization. Prioritize risks based on organizational risk tolerance."
}

# ---------------------------------------------------------------------------
# MEASURE — Analyze and assess AI risks quantitatively/qualitatively
# ---------------------------------------------------------------------------

violation_measure contains msg if {
    not input.measure.ai_risk_metrics_defined
    msg := "NIST AI RMF MEASURE 1.1: AI risk metrics are not defined. Establish quantitative and qualitative measures for AI risks."
}

violation_measure contains msg if {
    not input.measure.evaluation_methods_appropriate
    msg := "NIST AI RMF MEASURE 1.3: Evaluation methods have not been assessed for appropriateness. Evaluation methods must be fit for the AI use case."
}

violation_measure contains msg if {
    not input.measure.bias_testing_conducted
    msg := "NIST AI RMF MEASURE 2.2: Bias testing has not been conducted. Test for demographic biases and disparate impacts across population groups."
}

violation_measure contains msg if {
    not input.measure.adversarial_testing_conducted
    msg := "NIST AI RMF MEASURE 2.5: Adversarial testing (red-teaming) has not been conducted. Test AI system robustness against adversarial inputs."
}

violation_measure contains msg if {
    not input.measure.uncertainty_quantified
    msg := "NIST AI RMF MEASURE 2.6: AI output uncertainty is not quantified. AI systems should communicate confidence levels and uncertainty."
}

violation_measure contains msg if {
    not input.measure.performance_monitored_post_deployment
    msg := "NIST AI RMF MEASURE 2.7: AI performance is not monitored post-deployment. Ongoing monitoring is required to detect performance degradation and drift."
}

violation_measure contains msg if {
    not input.measure.privacy_risk_assessed
    msg := "NIST AI RMF MEASURE 2.10: Privacy risks from AI have not been assessed. Evaluate data privacy risks including inference attacks."
}

violation_measure contains msg if {
    not input.measure.explainability_assessed
    msg := "NIST AI RMF MEASURE 2.11: AI explainability has not been assessed. Evaluate the degree to which AI decisions can be explained to affected parties."
}

violation_measure contains msg if {
    not input.measure.regular_risk_assessments
    msg := "NIST AI RMF MEASURE 4.1: Regular risk reassessments are not scheduled. AI risks must be reassessed as the system and its context evolve."
}

# ---------------------------------------------------------------------------
# MANAGE — Prioritize and address identified AI risks
# ---------------------------------------------------------------------------

violation_manage contains msg if {
    not input.manage.risk_treatment_plans_documented
    msg := "NIST AI RMF MANAGE 1.1: Risk treatment plans are not documented. Document how each identified risk will be mitigated, accepted, transferred, or avoided."
}

violation_manage contains msg if {
    not input.manage.residual_risks_accepted_by_authority
    msg := "NIST AI RMF MANAGE 1.3: Residual risks have not been formally accepted by an authorizing authority. Formal risk acceptance is required."
}

violation_manage contains msg if {
    not input.manage.incident_response_for_ai
    msg := "NIST AI RMF MANAGE 2.2: No incident response plan for AI failures. AI-specific incidents require dedicated response procedures."
}

violation_manage contains msg if {
    not input.manage.human_override_available
    msg := "NIST AI RMF MANAGE 2.4: No human override capability. AI systems making consequential decisions must support human override."
}

violation_manage contains msg if {
    not input.manage.rollback_capability
    msg := "NIST AI RMF MANAGE 3.1: No rollback capability for AI model changes. Ability to revert to previous model versions is required for risk management."
}

violation_manage contains msg if {
    not input.manage.affected_parties_can_appeal
    msg := "NIST AI RMF MANAGE 4.1: No mechanism for affected parties to contest AI decisions. Individuals affected by consequential AI decisions must have recourse."
}

violation_manage contains msg if {
    not input.manage.retire_plan_documented
    msg := "NIST AI RMF MANAGE 4.2: No AI system retirement plan. Document how the system will be safely retired and what happens to its data and models."
}

# ---------------------------------------------------------------------------
# AI System-Specific Trustworthiness Properties
# ---------------------------------------------------------------------------

violation_trustworthiness contains msg if {
    not input.ai_system.accuracy_benchmarks_met
    msg := "NIST AI RMF (Trustworthy): AI system does not meet defined accuracy benchmarks. Accuracy requirements must be defined and met before deployment."
}

violation_trustworthiness contains msg if {
    not input.ai_system.fairness_assessed
    msg := "NIST AI RMF (Trustworthy): AI system fairness has not been assessed. Evaluate and document fairness across demographic groups."
}

violation_trustworthiness contains msg if {
    not input.ai_system.transparency_documentation
    msg := "NIST AI RMF (Trustworthy): No transparency documentation for AI system. Document model architecture, training data, and known limitations."
}

violation_trustworthiness contains msg if {
    not input.ai_system.security_hardened
    msg := "NIST AI RMF (Trustworthy): AI system has not been security hardened. Protect against adversarial attacks, model theft, and data poisoning."
}

violation_trustworthiness contains msg if {
    not input.ai_system.privacy_preserving
    msg := "NIST AI RMF (Trustworthy): Privacy-preserving techniques have not been applied. Consider differential privacy, federated learning, or data minimization."
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_govern],
        [v | some v in violation_map]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_measure],
            [v | some v in violation_manage]
        ),
        [v | some v in violation_trustworthiness]
    )
)

ai_rmf_compliant if { count(all_violations) == 0 }

functions_passing := count([f |
    f := [
        count(violation_govern) == 0,
        count(violation_map) == 0,
        count(violation_measure) == 0,
        count(violation_manage) == 0,
        count(violation_trustworthiness) == 0,
    ][_]
    f == true
])

compliance_score := round((functions_passing / 5) * 100)

ai_rmf_compliance_report := {
    "standard":         "NIST AI RMF 1.0",
    "full_title":       "NIST Artificial Intelligence Risk Management Framework",
    "ai_system":        input.ai_system.name,
    "compliant":        ai_rmf_compliant,
    "compliance_score": compliance_score,
    "total_violations": count(all_violations),
    "violations":       all_violations,
    "core_functions": {
        "GOVERN": {
            "compliant":        count(violation_govern) == 0,
            "violation_count":  count(violation_govern),
            "violations":       violation_govern,
        },
        "MAP": {
            "compliant":        count(violation_map) == 0,
            "violation_count":  count(violation_map),
            "violations":       violation_map,
        },
        "MEASURE": {
            "compliant":        count(violation_measure) == 0,
            "violation_count":  count(violation_measure),
            "violations":       violation_measure,
        },
        "MANAGE": {
            "compliant":        count(violation_manage) == 0,
            "violation_count":  count(violation_manage),
            "violations":       violation_manage,
        },
    },
}
