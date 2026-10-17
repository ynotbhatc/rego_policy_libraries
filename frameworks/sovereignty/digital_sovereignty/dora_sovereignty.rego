# METADATA
# title: "Digital Sovereignty — DORA (Digital Operational Resilience Act)"
# custom:
#   class: compliance
#   framework: digital_sovereignty
#   source: aac
#   domains: [sovereignty, data-residency]
#   coverage:
#     checks: 26
#     cited: 14
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package digital_sovereignty.dora_sovereignty

import rego.v1

# Digital Sovereignty — DORA (Digital Operational Resilience Act)
# EU Regulation 2022/2554 — effective January 17, 2025
# Applies to: financial entities and their critical ICT service providers
# operating in the EU.
#
# Covers five DORA pillars:
#   I.   ICT Risk Management Framework (Art. 5–16)
#   II.  ICT-Related Incident Management (Art. 17–23)
#   III. Digital Operational Resilience Testing (Art. 24–27)
#   IV.  ICT Third-Party Risk Management (Art. 28–44)
#   V.   Concentration Risk (Art. 30)
#
# Input schema:
#   input.dora
#     .ict_risk_management_framework_documented     — bool (Art. 5.2)
#     .ict_risk_framework_reviewed_date             — ISO8601 string
#     .ict_risk_framework_review_frequency_days     — int
#     .ict_asset_register_maintained                — bool (Art. 8)
#     .ict_asset_register_reviewed_date             — ISO8601 string
#     .ict_asset_register_review_frequency_days     — int
#     .rto_defined                                  — bool (Art. 12)
#     .rto_hours                                    — int
#     .rpo_defined                                  — bool (Art. 12)
#     .rpo_hours                                    — int
#     .business_continuity_plan_documented          — bool (Art. 11)
#     .business_continuity_tested_date              — ISO8601 string
#     .business_continuity_test_frequency_days      — int
#     .major_incident_classification_defined        — bool (Art. 18)
#     .initial_notification_timeline_hours          — int (Art. 19: ≤4h)
#     .intermediate_report_timeline_hours           — int (Art. 19: ≤72h)
#     .digital_resilience_testing_conducted         — bool (Art. 25)
#     .digital_resilience_test_date                 — ISO8601 string
#     .digital_resilience_test_frequency_days       — int (max 365)
#     .tlpt_required                                — bool (significant entities — Art. 26)
#     .tlpt_conducted                               — bool
#     .tlpt_date                                    — ISO8601 string
#     .tlpt_frequency_years                         — int (max 3)
#     .critical_ict_providers_register_maintained   — bool (Art. 28)
#     .critical_ict_providers[]
#       .provider_id                                — string
#       .provider_name                              — string
#       .pct_critical_functions                     — int
#       .exit_strategy_documented                   — bool (Art. 28)
#       .contractual_requirements_met               — bool (Art. 30)
#     .concentration_risk_threshold_pct             — int (≤60 per DORA guidance)

# =============================================================================
# PILLAR I: ICT RISK MANAGEMENT
# =============================================================================

ict_risk_framework_documented if {
	input.dora.ict_risk_management_framework_documented == true
	reviewed_ns := time.parse_rfc3339_ns(input.dora.ict_risk_framework_reviewed_date)
	max_age_ns := input.dora.ict_risk_framework_review_frequency_days * 24 * 3600 * 1000000000
	reviewed_ns >= time.now_ns() - max_age_ns
}

ict_asset_register_current if {
	input.dora.ict_asset_register_maintained == true
	reviewed_ns := time.parse_rfc3339_ns(input.dora.ict_asset_register_reviewed_date)
	max_age_ns := input.dora.ict_asset_register_review_frequency_days * 24 * 3600 * 1000000000
	reviewed_ns >= time.now_ns() - max_age_ns
}

rto_rpo_defined if {
	input.dora.rto_defined == true
	input.dora.rpo_defined == true
}

business_continuity_current if {
	input.dora.business_continuity_plan_documented == true
	tested_ns := time.parse_rfc3339_ns(input.dora.business_continuity_tested_date)
	max_age_ns := input.dora.business_continuity_test_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

# =============================================================================
# PILLAR II: INCIDENT MANAGEMENT
# =============================================================================

major_incident_criteria_defined if {
	input.dora.major_incident_classification_defined == true
}

# Art. 19.3(a): initial notification within 4 hours of classification
initial_notification_compliant if {
	# JSON null sorts below every number in OPA, so an unknown timeline would
	# pass a bare `<=`; the value must be a real number.
	is_number(input.dora.initial_notification_timeline_hours)
	input.dora.initial_notification_timeline_hours <= 4
}

# Art. 19.3(b): intermediate report within 72 hours
intermediate_report_compliant if {
	is_number(input.dora.intermediate_report_timeline_hours)
	input.dora.intermediate_report_timeline_hours <= 72
}

# =============================================================================
# PILLAR III: RESILIENCE TESTING
# =============================================================================

digital_resilience_testing_current if {
	input.dora.digital_resilience_testing_conducted == true
	tested_ns := time.parse_rfc3339_ns(input.dora.digital_resilience_test_date)
	max_age_ns := input.dora.digital_resilience_test_frequency_days * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_ns
}

# Art. 26: TLPT required for significant entities — check only if applicable
tlpt_compliant if {
	input.dora.tlpt_required == false
}

tlpt_compliant if {
	input.dora.tlpt_required == true
	input.dora.tlpt_conducted == true
	tested_ns := time.parse_rfc3339_ns(input.dora.tlpt_date)
	max_age_years_ns := input.dora.tlpt_frequency_years * 365 * 24 * 3600 * 1000000000
	tested_ns >= time.now_ns() - max_age_years_ns
}

# =============================================================================
# PILLAR IV: ICT THIRD-PARTY RISK
# =============================================================================

critical_ict_register_maintained if {
	input.dora.critical_ict_providers_register_maintained == true
}

# The provider list is the evidence for DORA-011/012/013: when it is absent (or
# not a list) the controls cannot pass. An explicitly empty list means the entity
# has no critical ICT providers.
providers := object.get(object.get(input, "dora", {}), "critical_ict_providers", null)

# NOTE: `provider.field != true` is undefined when the field is ABSENT, which
# used to let a provider with no recorded exit strategy / contract pass.

# All critical ICT providers must have documented exit strategies (Art. 28)
default all_providers_have_exit_strategy := false

all_providers_have_exit_strategy if {
	is_array(providers)
	not some_provider_missing_exit_strategy
}

some_provider_missing_exit_strategy if {
	some provider in providers
	not provider.exit_strategy_documented == true
}

# All critical ICT providers must meet Art. 30 contractual requirements
default all_providers_meet_contractual_requirements := false

all_providers_meet_contractual_requirements if {
	is_array(providers)
	not some_provider_missing_contract
}

some_provider_missing_contract if {
	some provider in providers
	not provider.contractual_requirements_met == true
}

# =============================================================================
# PILLAR V: CONCENTRATION RISK
# =============================================================================

# Art. 30: no single ICT provider should handle an excessive share of
# critical functions. DORA guidance indicates concern above 60%.
concentration_threshold := object.get(object.get(input, "dora", {}), "concentration_risk_threshold_pct", null)

# Both the share and the threshold must be real numbers (null sorts below every
# number, so a null share used to pass the check and raise no violation).
pct_within_threshold(provider) if {
	is_number(provider.pct_critical_functions)
	is_number(concentration_threshold)
	provider.pct_critical_functions <= concentration_threshold
}

concentration_offenders contains provider if {
	some provider in providers
	not pct_within_threshold(provider)
}

concentration_risk_acceptable if {
	is_array(providers)
	count(concentration_offenders) == 0
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not ict_risk_framework_documented
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-001",
		"severity":     "critical",
		"description":  "ICT risk management framework not documented or not reviewed within required frequency (DORA Art. 5.2)",
		"remediation":  "Document and regularly review the ICT risk management framework; assign a named ICT risk owner",
	}
}

violations contains v if {
	not ict_asset_register_current
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-002",
		"severity":     "high",
		"description":  "ICT asset register not maintained or not reviewed within required frequency (DORA Art. 8)",
		"remediation":  "Maintain a current ICT asset register covering hardware, software, data, and third-party services; review on defined schedule",
	}
}

violations contains v if {
	not rto_rpo_defined
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-003",
		"severity":     "critical",
		"description":  "Recovery Time Objective (RTO) or Recovery Point Objective (RPO) not defined (DORA Art. 12)",
		"remediation":  "Define, document, and test RTO and RPO for all critical ICT systems; align with business impact analysis",
	}
}

violations contains v if {
	not business_continuity_current
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-004",
		"severity":     "critical",
		"description":  "Business continuity plan not documented or not tested within required frequency (DORA Art. 11)",
		"remediation":  "Document, test, and update the ICT business continuity plan on at least an annual basis; record test outcomes",
	}
}

violations contains v if {
	not major_incident_criteria_defined
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-005",
		"severity":     "high",
		"description":  "Major incident classification criteria not defined (DORA Art. 18)",
		"remediation":  "Define major incident classification thresholds covering impact, duration, geographic spread, and data loss; align with DORA Annex I",
	}
}

violations contains v if {
	not initial_notification_compliant
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-006",
		"severity":     "critical",
		"description":  concat("", [
			"Initial major incident notification timeline exceeds 4 hours or is unknown: ",
			sprintf("%v", [object.get(object.get(input, "dora", {}), "initial_notification_timeline_hours", "not recorded")]),
			"h (DORA Art. 19.3(a) requires ≤4h)",
		]),
		"remediation":  "Implement automated alerting to competent authority within 4 hours of major incident classification; test via tabletop exercises",
	}
}

violations contains v if {
	not intermediate_report_compliant
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-007",
		"severity":     "high",
		"description":  concat("", [
			"Intermediate incident report timeline exceeds 72 hours or is unknown: ",
			sprintf("%v", [object.get(object.get(input, "dora", {}), "intermediate_report_timeline_hours", "not recorded")]),
			"h (DORA Art. 19.3(b) requires ≤72h)",
		]),
		"remediation":  "Establish incident reporting workflow with intermediate report SLA of 72 hours including cause analysis and containment status",
	}
}

violations contains v if {
	not digital_resilience_testing_current
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-008",
		"severity":     "high",
		"description":  "Annual digital operational resilience testing not conducted or overdue (DORA Art. 25)",
		"remediation":  "Conduct annual basic digital resilience tests covering vulnerability assessments, scenario-based tests, and network security assessments",
	}
}

violations contains v if {
	not tlpt_compliant
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-009",
		"severity":     "critical",
		"description":  "Threat-Led Penetration Test (TLPT) required but not conducted within required frequency (DORA Art. 26)",
		"remediation":  "Engage a qualified TLPT provider to conduct threat-led penetration testing every 3 years; coordinate with competent authority",
	}
}

violations contains v if {
	not critical_ict_register_maintained
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-010",
		"severity":     "high",
		"description":  "Critical ICT third-party provider register not maintained (DORA Art. 28)",
		"remediation":  "Maintain a register of all critical ICT service providers; report to competent authority annually",
	}
}

violations contains v if {
	some provider in providers
	not provider.exit_strategy_documented == true
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-011",
		"severity":     "high",
		"description":  concat("", [
			"No documented exit strategy for critical ICT provider: ",
			object.get(provider, "provider_name", "unknown"),
			" (DORA Art. 28)",
		]),
		"remediation":  "Document a tested exit strategy for each critical ICT provider including data migration, service continuity, and transition timeline",
	}
}

violations contains v if {
	some provider in providers
	not provider.contractual_requirements_met == true
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-012",
		"severity":     "high",
		"description":  concat("", [
			"ICT provider contract does not meet DORA Art. 30 requirements: ",
			object.get(provider, "provider_name", "unknown"),
		]),
		"remediation":  "Update ICT service contracts to include Art. 30 requirements: audit rights, SLAs, incident notification, data location, and exit provisions",
	}
}

violations contains v if {
	some provider in concentration_offenders
	v := {
		"domain":       "dora_sovereignty",
		"control":      "DORA-013",
		"severity":     "high",
		"description":  concat("", [
			"ICT concentration risk: ",
			object.get(provider, "provider_name", "unknown"),
			" handles ",
			sprintf("%v", [object.get(provider, "pct_critical_functions", "unknown")]),
			"% of critical functions — exceeds (or cannot be verified against) threshold of ",
			sprintf("%v", [concentration_threshold]),
			"% (DORA Art. 30)",
		]),
		"remediation":  "Implement multi-provider strategy to reduce concentration; develop alternative sourcing plan for critical ICT functions",
	}
}

violations contains v if {
	not is_array(providers)
	some control in ["DORA-011", "DORA-012", "DORA-013"]
	v := {
		"domain":       "dora_sovereignty",
		"control":      control,
		"severity":     "high",
		"description":  "Evidence missing: dora.critical_ict_providers is not provided, so exit strategies, contracts and concentration risk cannot be verified (DORA Art. 28, 30)",
		"remediation":  "Provide the list of critical ICT third-party providers (an empty list if there are none)",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	ict_risk_framework_documented
	ict_asset_register_current
	rto_rpo_defined
	business_continuity_current
	major_incident_criteria_defined
	initial_notification_compliant
	intermediate_report_compliant
	digital_resilience_testing_current
	tlpt_compliant
	critical_ict_register_maintained
	all_providers_have_exit_strategy
	all_providers_meet_contractual_requirements
	concentration_risk_acceptable
}

report := {
	"domain":    "DORA — Digital Operational Resilience Act",
	"compliant": compliant,
	"controls": {
		"DORA-001_ict_risk_framework":          ict_risk_framework_documented,
		"DORA-002_ict_asset_register":          ict_asset_register_current,
		"DORA-003_rto_rpo_defined":             rto_rpo_defined,
		"DORA-004_business_continuity_tested":  business_continuity_current,
		"DORA-005_incident_classification":     major_incident_criteria_defined,
		"DORA-006_initial_notification_4h":     initial_notification_compliant,
		"DORA-007_intermediate_report_72h":     intermediate_report_compliant,
		"DORA-008_resilience_testing_annual":   digital_resilience_testing_current,
		"DORA-009_tlpt_compliant":              tlpt_compliant,
		"DORA-010_critical_ict_register":       critical_ict_register_maintained,
		"DORA-011_exit_strategies":             all_providers_have_exit_strategy,
		"DORA-012_contractual_requirements":    all_providers_meet_contractual_requirements,
		"DORA-013_concentration_risk":          concentration_risk_acceptable,
	},
	"violations":      violations,
	"violation_count": count(violations),
}

# Defaults for control rules — ensure report never collapses to {} on absent facts
default business_continuity_current := false
default concentration_risk_acceptable := false
default critical_ict_register_maintained := false
default digital_resilience_testing_current := false
default ict_asset_register_current := false
default ict_risk_framework_documented := false
default initial_notification_compliant := false
default intermediate_report_compliant := false
default major_incident_criteria_defined := false
default rto_rpo_defined := false
default tlpt_compliant := false
