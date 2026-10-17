# METADATA
# title: "Digital Sovereignty — AI/ML Sovereignty"
# custom:
#   class: compliance
#   framework: digital_sovereignty
#   source: aac
#   domains: [sovereignty, data-residency]
#   coverage:
#     checks: 22
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.1
package digital_sovereignty.ai_sovereignty

import rego.v1

# Digital Sovereignty — AI/ML Sovereignty
# Ensures AI/ML workloads do not expose regulated data to foreign-controlled
# models, training pipelines, or inference infrastructure.
#
# Input schema:
#   input.approved_jurisdictions[]
#   input.ai_services[]
#     .service_id, .service_name, .service_type  — llm | ml_platform | mlops | data_labelling
#     .provider, .provider_hq_country
#     .deployment_type                — saas | self_hosted | on_prem | sovereign_cloud
#     .inference_location_country
#     .data_sent_for_inference        — bool
#     .data_used_for_training         — bool
#     .data_classification_processed
#     .opt_out_of_training.available  — bool
#     .opt_out_of_training.enabled    — bool
#     .data_retention_by_provider_days
#   input.ml_training
#     .training_data_location_country
#     .training_infrastructure_country
#     .training_data_classification
#     .data_leaves_jurisdiction_for_training — bool
#     .federated_learning_used        — bool
#   input.ml_models[]
#     .model_id, .model_name
#     .origin                         — internal | open_source | commercial | foreign_govt
#     .origin_country
#     .audited_for_backdoors          — bool
#     .model_weights_location_country
#     .inference_in_jurisdiction      — bool
#   input.ai_governance
#     .policy_documented              — bool
#     .approved_ai_services_list      — bool
#     .shadow_ai_controls             — bool  # prevent use of unapproved AI tools
#     .data_handling_procedures       — bool
#     .human_oversight_for_decisions  — bool
#   input.ai_output_controls
#     .outputs_reviewed_before_action — bool
#     .output_logging_enabled         — bool
#     .output_jurisdiction            — country where outputs are stored

# =============================================================================
# AI SERVICE SOVEREIGNTY
# =============================================================================

# NOTE (undefined trap): `not svc.field in list` is compiled with the field
# reference hoisted outside the negation, so an ABSENT field makes the whole
# body undefined and the check silently passes. Fields are therefore read with
# object.get() (absent -> "", which is never an approved jurisdiction) and
# compared against `approved`, which is [] when input.approved_jurisdictions is
# missing (fail closed).
approved := object.get(input, "approved_jurisdictions", [])

regulated_classes := {"sensitive", "restricted", "sovereign"}

# ai_services / ml_models are inventories of in-scope items: an absent
# inventory means nothing is in scope for these per-item checks.
ai_services := object.get(input, "ai_services", [])

ml_models := object.get(input, "ml_models", [])

# Regulated data must not be sent to foreign-controlled SaaS AI services
foreign_ai_offenders contains svc if {
	some svc in ai_services
	svc.deployment_type == "saas"
	not object.get(svc, "provider_hq_country", "") in approved
	object.get(svc, "data_classification_processed", "") in regulated_classes
	svc.data_sent_for_inference == true
}

default no_regulated_data_to_foreign_ai := false

no_regulated_data_to_foreign_ai if count(foreign_ai_offenders) == 0

# Any AI service processing regulated data must be opt-out of training
training_offenders contains svc if {
	some svc in ai_services
	object.get(svc, "data_classification_processed", "") in regulated_classes
	svc.data_used_for_training == true
	not object.get(object.get(svc, "opt_out_of_training", {}), "enabled", false) == true
}

default training_opt_out_enabled := false

training_opt_out_enabled if count(training_offenders) == 0

# Provider must not retain regulated data beyond session
retention_offenders contains svc if {
	some svc in ai_services
	object.get(svc, "data_classification_processed", "") in regulated_classes
	svc.data_retention_by_provider_days > 0
}

default no_long_term_ai_data_retention := false

no_long_term_ai_data_retention if count(retention_offenders) == 0

# AI inference for regulated data must occur in approved jurisdiction
inference_offenders contains svc if {
	some svc in ai_services
	object.get(svc, "data_classification_processed", "") in regulated_classes
	not object.get(svc, "inference_location_country", "") in approved
}

default inference_in_approved_jurisdiction := false

inference_in_approved_jurisdiction if count(inference_offenders) == 0

# =============================================================================
# ML TRAINING DATA SOVEREIGNTY
# =============================================================================

# Training data must remain in approved jurisdiction. Fail closed: the
# "stays in jurisdiction" flag must be explicitly false AND the data location
# must be approved (an absent flag is not evidence).
default training_data_in_jurisdiction := false

training_data_in_jurisdiction if {
	input.ml_training.data_leaves_jurisdiction_for_training == false
	input.ml_training.training_data_location_country in approved
}

# Training infrastructure must be in approved jurisdiction
default training_infra_in_jurisdiction := false

training_infra_in_jurisdiction if {
	input.ml_training.training_infrastructure_country in approved
}

# Sovereign/restricted data must use federated or on-prem training only
sovereign_data_not_centralised_for_training if {
	violations := [v |
		input.ml_training.training_data_classification in ["sovereign", "restricted"]
		not input.ml_training.federated_learning_used == true
		not input.ml_training.training_infrastructure_country in input.approved_jurisdictions
		v := true
	]
	count(violations) == 0
}

# =============================================================================
# MODEL PROVENANCE
# =============================================================================

# Models of foreign government origin must not be deployed
foreign_govt_offenders contains m if {
	some m in ml_models
	m.origin == "foreign_govt"
}

default no_foreign_govt_models := false

no_foreign_govt_models if count(foreign_govt_offenders) == 0

# Models from unapproved (or unknown) countries must be audited
unaudited_foreign_offenders contains m if {
	some m in ml_models
	not object.get(m, "origin_country", "") in approved
	not m.audited_for_backdoors == true
}

default foreign_models_audited := false

foreign_models_audited if count(unaudited_foreign_offenders) == 0

# Model weights must be stored in approved jurisdiction
weights_offenders contains m if {
	some m in ml_models
	not object.get(m, "model_weights_location_country", "") in approved
}

default model_weights_in_jurisdiction := false

model_weights_in_jurisdiction if count(weights_offenders) == 0

# =============================================================================
# AI GOVERNANCE
# =============================================================================

# AI policy must be documented
ai_governance_policy if {
	input.ai_governance.policy_documented == true
	input.ai_governance.approved_ai_services_list == true
	input.ai_governance.data_handling_procedures == true
}

# Shadow AI (unapproved tools) must be controlled
shadow_ai_controlled if {
	input.ai_governance.shadow_ai_controls == true
}

# Human oversight for automated decisions involving regulated data
default human_oversight_implemented := false

human_oversight_implemented if {
	input.ai_governance.human_oversight_for_decisions == true
}

# =============================================================================
# AI OUTPUT CONTROLS
# =============================================================================

# AI outputs must be logged
default ai_outputs_logged := false

ai_outputs_logged if {
	input.ai_output_controls.output_logging_enabled == true
}

# Output logs must be stored in approved jurisdiction
default ai_output_logs_in_jurisdiction := false

ai_output_logs_in_jurisdiction if {
	input.ai_output_controls.output_jurisdiction in approved
}

# =============================================================================
# AI BIAS AND FAIRNESS (AI-009, AI-010)
# =============================================================================
#   input.ai_bias_fairness
#     .bias_audit_policy_documented       — bool
#     .audit_frequency_days               — int
#     .last_audit_date                    — ISO8601 string
#     .audit_findings_documented          — bool
#     .remediation_process_documented     — bool
#   input.ai_fairness_controls
#     .fairness_metrics_defined           — bool
#     .fairness_thresholds_enforced       — bool
#     .disparate_impact_tested            — bool
#     .remediation_applied_when_breached  — bool
#     .fairness_monitoring_ongoing        — bool

# AI bias audit must be documented, current, and findings recorded (EU AI Act §4.2)
ai_bias_audit_conducted if {
	input.ai_bias_fairness.bias_audit_policy_documented == true
	input.ai_bias_fairness.audit_findings_documented == true
	input.ai_bias_fairness.remediation_process_documented == true
	max_age_ns := input.ai_bias_fairness.audit_frequency_days * 24 * 3600 * 1000000000
	audit_ns := time.parse_rfc3339_ns(input.ai_bias_fairness.last_audit_date)
	audit_ns >= time.now_ns() - max_age_ns
}

# Active fairness controls must be in place and monitored (GDPR Art. 13, EU AI Act §6)
ai_fairness_controls_implemented if {
	input.ai_fairness_controls.fairness_metrics_defined == true
	input.ai_fairness_controls.fairness_thresholds_enforced == true
	input.ai_fairness_controls.disparate_impact_tested == true
	input.ai_fairness_controls.remediation_applied_when_breached == true
	input.ai_fairness_controls.fairness_monitoring_ongoing == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	some svc in foreign_ai_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-001",
		"severity": "critical",
		"service_id": object.get(svc, "service_id", "unknown"),
		"description": concat("", ["Regulated data sent to foreign-controlled AI service: ", object.get(svc, "service_name", "unknown"), " (", object.get(svc, "provider_hq_country", "unknown"), ")"]),
		"remediation": "Use self-hosted, on-premises, or approved-jurisdiction AI service; anonymise data before sending",
	}
}

violations contains v if {
	some svc in training_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-002",
		"severity": "critical",
		"service_id": object.get(svc, "service_id", "unknown"),
		"description": concat("", ["Regulated data being used to train external AI model: ", object.get(svc, "service_name", "unknown")]),
		"remediation": "Enable training opt-out for this service or cease sending regulated data",
	}
}

violations contains v if {
	some svc in inference_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-003",
		"severity": "high",
		"service_id": object.get(svc, "service_id", "unknown"),
		"description": concat("", ["AI inference on regulated data occurring outside approved jurisdiction: ", object.get(svc, "inference_location_country", "unknown")]),
		"remediation": "Deploy AI inference infrastructure in approved jurisdiction",
	}
}

violations contains v if {
	not training_data_in_jurisdiction
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-004",
		"severity": "critical",
		"description": "ML training data leaves approved jurisdiction for training",
		"remediation": "Keep training data within jurisdiction; use federated learning if cross-border training required",
	}
}

violations contains v if {
	some m in foreign_govt_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-005",
		"severity": "critical",
		"model_id": object.get(m, "model_id", "unknown"),
		"description": concat("", ["Model of foreign government origin deployed: ", object.get(m, "model_name", "unknown")]),
		"remediation": "Remove foreign government-origin models; replace with audited open-source or domestically-developed models",
	}
}

violations contains v if {
	some m in unaudited_foreign_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-006",
		"severity": "high",
		"model_id": object.get(m, "model_id", "unknown"),
		"description": concat("", ["Foreign-origin (or unknown-origin) model deployed without backdoor/bias audit: ", object.get(m, "model_name", "unknown"), " (", object.get(m, "origin_country", "unknown"), ")"]),
		"remediation": "Conduct security audit of model weights and training provenance before deployment",
	}
}

violations contains v if {
	not ai_governance_policy
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-007",
		"severity": "high",
		"description": "No AI governance policy or approved services list documented",
		"remediation": "Document AI governance policy with approved service list and data handling procedures",
	}
}

violations contains v if {
	not shadow_ai_controlled
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-008",
		"severity": "high",
		"description": "No controls in place to prevent use of unapproved AI tools (shadow AI risk)",
		"remediation": "Implement technical controls (proxy, DLP, network filtering) to block unapproved AI services",
	}
}

violations contains v if {
	not ai_bias_audit_conducted
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-009",
		"severity": "high",
		"description": "AI bias and fairness audit not conducted, not current, or findings not documented (EU AI Act §4.2, GDPR Art. 22)",
		"remediation": "Conduct AI bias audit against protected attributes; document findings and remediation; repeat at required frequency",
	}
}

violations contains v if {
	not ai_fairness_controls_implemented
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-010",
		"severity": "high",
		"description": "AI fairness controls not fully implemented — metrics, thresholds, disparate impact testing, or ongoing monitoring missing (EU AI Act §6)",
		"remediation": "Define fairness metrics and thresholds; test for disparate impact; implement ongoing fairness monitoring with remediation triggers",
	}
}

# Controls that gate `compliant` and previously had no violation entry
# (compliant could be false with violation_count 0).
violations contains v if {
	some svc in retention_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-011",
		"severity": "high",
		"service_id": object.get(svc, "service_id", "unknown"),
		"description": concat("", ["AI provider retains regulated data beyond the session: ", object.get(svc, "service_name", "unknown")]),
		"remediation": "Require zero-retention terms or move the workload to an approved self-hosted service",
	}
}

violations contains v if {
	not training_infra_in_jurisdiction
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-012",
		"severity": "high",
		"description": "ML training infrastructure is not in an approved jurisdiction (or its location is not recorded)",
		"remediation": "Run training in an approved jurisdiction and record training_infrastructure_country",
	}
}

violations contains v if {
	some m in weights_offenders
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-013",
		"severity": "high",
		"model_id": object.get(m, "model_id", "unknown"),
		"description": concat("", ["Model weights not stored in an approved jurisdiction (or location not recorded): ", object.get(m, "model_name", "unknown")]),
		"remediation": "Store model weights in an approved jurisdiction and record model_weights_location_country",
	}
}

violations contains v if {
	not human_oversight_implemented
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-014",
		"severity": "high",
		"description": "No human oversight for automated decisions involving regulated data",
		"remediation": "Introduce human review for automated decisions that use regulated data",
	}
}

violations contains v if {
	not ai_outputs_logged
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-015",
		"severity": "medium",
		"description": "AI outputs are not logged",
		"remediation": "Enable output logging for AI services",
	}
}

violations contains v if {
	not ai_output_logs_in_jurisdiction
	v := {
		"domain": "ai_sovereignty",
		"control": "AI-016",
		"severity": "medium",
		"description": "AI output logs are not stored in an approved jurisdiction",
		"remediation": "Store AI output logs in an approved jurisdiction",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	no_regulated_data_to_foreign_ai
	training_opt_out_enabled
	no_long_term_ai_data_retention
	inference_in_approved_jurisdiction
	training_data_in_jurisdiction
	training_infra_in_jurisdiction
	no_foreign_govt_models
	foreign_models_audited
	model_weights_in_jurisdiction
	ai_governance_policy
	shadow_ai_controlled
	human_oversight_implemented
	ai_outputs_logged
	ai_output_logs_in_jurisdiction
	ai_bias_audit_conducted
	ai_fairness_controls_implemented
}

report := {
	"domain": "AI/ML Sovereignty",
	"compliant": compliant,
	"controls": {
		"AI-001_no_regulated_data_to_foreign_ai": no_regulated_data_to_foreign_ai,
		"AI-002_training_opt_out": training_opt_out_enabled,
		"AI-003_inference_in_jurisdiction": inference_in_approved_jurisdiction,
		"AI-004_training_data_in_jurisdiction": training_data_in_jurisdiction,
		"AI-005_no_foreign_govt_models": no_foreign_govt_models,
		"AI-006_foreign_models_audited": foreign_models_audited,
		"AI-007_governance_policy": ai_governance_policy,
		"AI-008_shadow_ai_controlled": shadow_ai_controlled,
		"AI-009_bias_audit_conducted": ai_bias_audit_conducted,
		"AI-010_fairness_controls_implemented": ai_fairness_controls_implemented,
		"AI-011_no_long_term_data_retention": no_long_term_ai_data_retention,
		"AI-012_training_infra_in_jurisdiction": training_infra_in_jurisdiction,
		"AI-013_model_weights_in_jurisdiction": model_weights_in_jurisdiction,
		"AI-014_human_oversight": human_oversight_implemented,
		"AI-015_outputs_logged": ai_outputs_logged,
		"AI-016_output_logs_in_jurisdiction": ai_output_logs_in_jurisdiction,
	},
	"service_summary": {
		"total_ai_services": count(ai_services),
		"saas_services": count([s | some s in ai_services; s.deployment_type == "saas"]),
		"foreign_saas": count([s | some s in ai_services; s.deployment_type == "saas"; not object.get(s, "provider_hq_country", "") in approved]),
	},
	"violations": violations,
	"violation_count": count(violations),
}

# Defaults for control rules — ensure report never collapses to {} on absent facts
default ai_bias_audit_conducted := false
default ai_fairness_controls_implemented := false
default ai_governance_policy := false
default shadow_ai_controlled := false
