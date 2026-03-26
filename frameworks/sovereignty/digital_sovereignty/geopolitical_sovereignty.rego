package digital_sovereignty.geopolitical_sovereignty

import rego.v1

# Digital Sovereignty — Geopolitical Event Triggers
# Ensures the organisation maintains a current geopolitical risk register
# and documented response procedures for events that could alter its
# sovereignty posture (sanctions, armed conflict, regulatory change,
# supply chain disruption, diplomatic incidents).
#
# Regulatory anchors: ENISA Digital Sovereignty recommendations,
# NIS2 Art. 21 (risk management measures), BSI C5 § 5.1 (governance),
# IRAP § 7 (risk management).
#
# Input schema:
#   input.geopolitical_risk
#     .risk_register_maintained                   — bool
#     .last_risk_review_date                      — ISO8601 string
#     .review_frequency_days                      — int
#     .designated_sovereign_risk_owner            — bool
#     .geopolitical_event_triggers[]
#       .trigger_id                               — string
#       .event_type                               — sanctions | conflict | regulatory_change |
#                                                   supply_chain_disruption | diplomatic_incident
#       .response_procedure_documented            — bool
#       .escalation_path_defined                  — bool
#       .activation_criteria_defined              — bool
#     .country_exit_procedures[]
#       .country                                  — country code
#       .data_egress_procedure_documented         — bool
#       .infrastructure_withdrawal_plan           — bool
#       .personnel_relocation_plan                — bool
#     .supply_chain_geopolitical_assessment
#       .conducted                                — bool
#       .critical_suppliers_mapped                — bool
#       .alternative_suppliers_identified         — bool
#       .last_assessment_date                     — ISO8601 string
#     .regulatory_change_monitoring
#       .process_documented                       — bool
#       .jurisdictions_monitored[]                — list of country codes
#       .notification_mechanism                   — bool
#   input.approved_jurisdictions[]

# =============================================================================
# RISK REGISTER AND GOVERNANCE
# =============================================================================

# Risk register must be maintained and reviewed within the required frequency
geopolitical_risk_register_current if {
	input.geopolitical_risk.risk_register_maintained == true
	input.geopolitical_risk.designated_sovereign_risk_owner == true
	max_age_ns := input.geopolitical_risk.review_frequency_days * 24 * 3600 * 1000000000
	review_ns := time.parse_rfc3339_ns(input.geopolitical_risk.last_risk_review_date)
	review_ns >= time.now_ns() - max_age_ns
}

# =============================================================================
# EVENT TRIGGER PROCEDURES
# =============================================================================

# All defined event trigger types must have documented procedures and
# activation criteria so the organisation can act without ambiguity
geopolitical_event_triggers_documented if {
	undocumented := [t |
		t := input.geopolitical_risk.geopolitical_event_triggers[_]
		not t.response_procedure_documented == true
	]
	count(undocumented) == 0
	no_criteria := [t |
		t := input.geopolitical_risk.geopolitical_event_triggers[_]
		not t.activation_criteria_defined == true
	]
	count(no_criteria) == 0
}

# =============================================================================
# COUNTRY EXIT PROCEDURES
# =============================================================================

# Every listed country must have a data egress + infrastructure withdrawal plan
country_exit_procedures_documented if {
	incomplete := [p |
		p := input.geopolitical_risk.country_exit_procedures[_]
		not p.data_egress_procedure_documented == true
	]
	count(incomplete) == 0
	no_infra_plan := [p |
		p := input.geopolitical_risk.country_exit_procedures[_]
		not p.infrastructure_withdrawal_plan == true
	]
	count(no_infra_plan) == 0
}

# =============================================================================
# SUPPLY CHAIN GEOPOLITICAL RISK
# =============================================================================

# Critical suppliers must be mapped with geopolitical alternatives identified
supply_chain_geopolitical_assessed if {
	input.geopolitical_risk.supply_chain_geopolitical_assessment.conducted == true
	input.geopolitical_risk.supply_chain_geopolitical_assessment.critical_suppliers_mapped == true
	input.geopolitical_risk.supply_chain_geopolitical_assessment.alternative_suppliers_identified == true
}

# =============================================================================
# REGULATORY CHANGE MONITORING
# =============================================================================

# A process must exist to monitor and notify on regulatory changes
# across all jurisdictions where data is stored or processed
regulatory_change_monitoring_active if {
	input.geopolitical_risk.regulatory_change_monitoring.process_documented == true
	input.geopolitical_risk.regulatory_change_monitoring.notification_mechanism == true
	count(input.geopolitical_risk.regulatory_change_monitoring.jurisdictions_monitored) > 0
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not geopolitical_risk_register_current
	v := {
		"domain": "geopolitical_sovereignty",
		"control": "GT-001",
		"severity": "high",
		"description": "Geopolitical risk register not maintained, not reviewed within required frequency, or no designated sovereign risk owner",
		"remediation": "Assign a sovereign risk owner, maintain a geopolitical risk register, and review it at least quarterly",
	}
}

violations contains v if {
	not geopolitical_event_triggers_documented
	t := input.geopolitical_risk.geopolitical_event_triggers[_]
	not t.response_procedure_documented == true
	v := {
		"domain": "geopolitical_sovereignty",
		"control": "GT-002",
		"severity": "high",
		"trigger_id": t.trigger_id,
		"description": concat("", ["Geopolitical event trigger has no documented response procedure: ", t.trigger_id, " (", t.event_type, ")"]),
		"remediation": "Document response procedure and activation criteria for each defined geopolitical event trigger",
	}
}

violations contains v if {
	not geopolitical_event_triggers_documented
	t := input.geopolitical_risk.geopolitical_event_triggers[_]
	not t.activation_criteria_defined == true
	v := {
		"domain": "geopolitical_sovereignty",
		"control": "GT-002",
		"severity": "high",
		"trigger_id": t.trigger_id,
		"description": concat("", ["Geopolitical event trigger has no activation criteria defined: ", t.trigger_id, " (", t.event_type, ")"]),
		"remediation": "Define clear activation criteria (e.g., sanctions designation, conflict outbreak) for each trigger type",
	}
}

violations contains v if {
	not country_exit_procedures_documented
	p := input.geopolitical_risk.country_exit_procedures[_]
	not p.data_egress_procedure_documented == true
	v := {
		"domain": "geopolitical_sovereignty",
		"control": "GT-003",
		"severity": "high",
		"description": concat("", ["No data egress procedure documented for country exit: ", p.country]),
		"remediation": "Document data egress and infrastructure withdrawal procedure for each country where operations exist",
	}
}

violations contains v if {
	not supply_chain_geopolitical_assessed
	v := {
		"domain": "geopolitical_sovereignty",
		"control": "GT-004",
		"severity": "medium",
		"description": "Supply chain geopolitical risk not assessed — critical suppliers not mapped or no alternative suppliers identified",
		"remediation": "Map all critical suppliers by country; identify geopolitical risk; qualify alternative suppliers in different jurisdictions",
	}
}

violations contains v if {
	not regulatory_change_monitoring_active
	v := {
		"domain": "geopolitical_sovereignty",
		"control": "GT-005",
		"severity": "medium",
		"description": "No active process to monitor regulatory changes across approved jurisdictions",
		"remediation": "Implement regulatory monitoring service or legal retainer covering all jurisdictions where data is processed",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	geopolitical_risk_register_current
	geopolitical_event_triggers_documented
	country_exit_procedures_documented
	supply_chain_geopolitical_assessed
	regulatory_change_monitoring_active
}

report := {
	"domain": "Geopolitical Sovereignty",
	"compliant": compliant,
	"controls": {
		"GT-001_risk_register_current": geopolitical_risk_register_current,
		"GT-002_event_triggers_documented": geopolitical_event_triggers_documented,
		"GT-003_country_exit_procedures": country_exit_procedures_documented,
		"GT-004_supply_chain_assessed": supply_chain_geopolitical_assessed,
		"GT-005_regulatory_monitoring": regulatory_change_monitoring_active,
	},
	"trigger_summary": {
		"total_triggers": count(input.geopolitical_risk.geopolitical_event_triggers),
		"triggers_documented": count([t | t := input.geopolitical_risk.geopolitical_event_triggers[_]; t.response_procedure_documented == true]),
		"country_exit_plans": count(input.geopolitical_risk.country_exit_procedures),
	},
	"violations": violations,
	"violation_count": count(violations),
}
