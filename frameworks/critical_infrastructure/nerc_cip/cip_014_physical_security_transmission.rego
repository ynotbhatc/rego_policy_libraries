package nerc_cip.cip_014

import rego.v1

# CIP-014-3: Physical Security of Transmission Stations and Substations
# Requirement: Identify and protect Transmission stations and Transmission
# substations, and their associated primary control centers, that if rendered
# inoperable or damaged as a result of a physical attack could result in
# widespread instability, uncontrolled separation, or cascading within an
# Interconnection.
#
# Note: CIP-014 focuses on physical attacks on TRANSMISSION infrastructure,
# distinct from CIP-006 which protects BES Cyber System physical access.
#
# NERC Standards Reference: CIP-014-3

# =============================================================================
# R1: Risk Assessment — Identify Applicable Transmission Stations
# =============================================================================

# R1.1 - Perform an initial and subsequent risk assessments of Transmission
# stations and substations to identify those that, if rendered inoperable or
# damaged, could result in widespread instability

risk_assessment_performed if {
	input.transmission_risk_assessment.performed == true
	input.transmission_risk_assessment.documented == true
	input.transmission_risk_assessment.methodology_documented == true
}

# Risk assessment must use a methodology that assesses potential for
# widespread instability, uncontrolled separation, or cascading
risk_assessment_methodology_adequate if {
	input.transmission_risk_assessment.methodology.power_flow_analysis == true
	input.transmission_risk_assessment.methodology.contingency_analysis == true
	input.transmission_risk_assessment.methodology.stability_impact_assessed == true
	input.transmission_risk_assessment.methodology.cascading_potential_assessed == true
}

# Re-perform the assessment within 30 calendar months of last assessment
risk_assessment_current if {
	last_assessment_ns := time.parse_rfc3339_ns(input.transmission_risk_assessment.last_assessment_date)
	assessment_age_days := (time.now_ns() - last_assessment_ns) / (24 * 60 * 60 * 1000000000)
	assessment_age_days <= 912 # 30 calendar months
}

# Update assessment within 60 days of qualifying changes to transmission topology
assessment_updated_after_changes if {
	every change in input.transmission_topology_changes {
		change.assessment_triggered == true
		update_age_days := (change.assessment_completion_date - change.change_date) / (24 * 60 * 60 * 1000000000)
		update_age_days <= 60
	}
}

# =============================================================================
# R2: Third-Party Verification of Risk Assessment
# =============================================================================

# R2 - Have an unaffiliated third party verify the risk assessment in R1
# Third party must have no affiliation with the Transmission Owner/Operator

third_party_verification_performed if {
	input.transmission_risk_assessment.third_party_verification.performed == true
	input.transmission_risk_assessment.third_party_verification.unaffiliated == true
	input.transmission_risk_assessment.third_party_verification.documented == true
	input.transmission_risk_assessment.third_party_verification.reviewer_qualifications_documented == true
}

# Third-party verification must occur within 90 days of completion of the
# initial risk assessment and within 60 days of updates
third_party_verification_timely if {
	input.transmission_risk_assessment.third_party_verification.timely == true
	last_verify_ns := time.parse_rfc3339_ns(input.transmission_risk_assessment.third_party_verification.last_verification_date)
	verify_age_days := (time.now_ns() - last_verify_ns) / (24 * 60 * 60 * 1000000000)
	verify_age_days <= 912 # aligned with assessment frequency
}

# Notify the RE (Reliability Coordinator) of verification completion
rc_notified_of_verification if {
	input.transmission_risk_assessment.third_party_verification.rc_notified == true
	input.transmission_risk_assessment.third_party_verification.rc_notification_date
}

# =============================================================================
# R3: Protect Applicable Transmission Stations
# =============================================================================

# R3 - Identify and implement physical security enhancements for
# applicable transmission stations identified in R1

applicable_stations_identified if {
	count(input.applicable_transmission_stations) > 0
	every station in input.applicable_transmission_stations {
		station.station_id
		station.station_name
		station.risk_assessment_reference
		station.impact_level
	}
}

# No applicable stations means no further requirements under CIP-014
no_applicable_stations if {
	count(input.applicable_transmission_stations) == 0
	input.transmission_risk_assessment.no_applicable_stations_documented == true
}

# Physical security plan in place for each applicable station
station_physical_security_plans if {
	no_applicable_stations
} else if {
	violations := [station |
		station := input.applicable_transmission_stations[_]
		not station_has_security_plan(station)
	]
	count(violations) == 0
}

station_has_security_plan(station) if {
	plan := input.station_security_plans[station.station_id]
	plan.documented == true
	plan.approved == true
	plan.physical_security_enhancements_defined == true
}

# =============================================================================
# R4: Physical Security Plan for Applicable Stations
# =============================================================================

# R4.1 - Develop, approve, and implement a physical security plan that covers
# the applicable Transmission stations identified in R1

physical_security_plans_developed if {
	no_applicable_stations
} else if {
	violations := [station |
		station := input.applicable_transmission_stations[_]
		not physical_security_plan_adequate(station)
	]
	count(violations) == 0
}

physical_security_plan_adequate(station) if {
	plan := input.station_security_plans[station.station_id]
	plan.documented == true
	plan.cip_senior_manager_approved == true
	plan.physical_threat_assessment_conducted == true
	plan.physical_security_enhancements.perimeter_controls == true
	plan.physical_security_enhancements.access_controls == true
	plan.physical_security_enhancements.monitoring_surveillance == true
	plan.physical_security_enhancements.deterrence_measures == true
}

# R4.2 - Threat assessment by a qualified subject matter expert
physical_threat_assessments_performed if {
	no_applicable_stations
} else if {
	violations := [station |
		station := input.applicable_transmission_stations[_]
		not threat_assessment_adequate(station)
	]
	count(violations) == 0
}

threat_assessment_adequate(station) if {
	plan := input.station_security_plans[station.station_id]
	plan.threat_assessment.performed == true
	plan.threat_assessment.qualified_expert_conducted == true
	plan.threat_assessment.documented == true
	plan.threat_assessment.attack_vectors_assessed == true
}

# R4.3 - Implement physical security plan within 12 months of completion of R2
plan_implementation_timely if {
	no_applicable_stations
} else if {
	violations := [station |
		station := input.applicable_transmission_stations[_]
		not plan_implemented_timely(station)
	]
	count(violations) == 0
}

plan_implemented_timely(station) if {
	plan := input.station_security_plans[station.station_id]
	plan.implementation_completed == true
	implementation_months := (plan.implementation_date - input.transmission_risk_assessment.third_party_verification.last_verification_date) / (30 * 24 * 60 * 60 * 1000000000)
	implementation_months <= 12
}

# =============================================================================
# R5: Physical Security Plan Review
# =============================================================================

# R5.1 - Review and, if necessary, update physical security plan within
# 36 calendar months of last review

security_plans_reviewed if {
	no_applicable_stations
} else if {
	violations := [station |
		station := input.applicable_transmission_stations[_]
		not plan_review_current(station)
	]
	count(violations) == 0
}

plan_review_current(station) if {
	plan := input.station_security_plans[station.station_id]
	plan.last_review_date
	review_age_days := (time.now_ns() - plan.last_review_date) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 1095 # 36 calendar months
}

# R5.2 - Update plan if changes to transmission topology affect applicable stations
plan_updated_after_topology_changes if {
	every change in input.transmission_topology_changes {
		change.security_plan_impact_assessed == true
		change.plans_updated_if_needed == true
	}
}

# =============================================================================
# R6: Third-Party Review of Physical Security Plan
# =============================================================================

# R6 - Have an unaffiliated third party with relevant expertise review
# the Physical Security Plan

physical_security_plan_third_party_reviewed if {
	no_applicable_stations
} else if {
	violations := [station |
		station := input.applicable_transmission_stations[_]
		not plan_third_party_reviewed(station)
	]
	count(violations) == 0
}

plan_third_party_reviewed(station) if {
	plan := input.station_security_plans[station.station_id]
	plan.third_party_review.performed == true
	plan.third_party_review.unaffiliated == true
	plan.third_party_review.relevant_expertise == true
	plan.third_party_review.documented == true
	# Review must occur within 60 days of plan completion
	review_age_days := (plan.third_party_review.date - plan.initial_completion_date) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 60
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not risk_assessment_performed
	v := {
		"standard": "CIP-014",
		"requirement": "R1",
		"severity": "high",
		"description": "Transmission station risk assessment not performed or not documented",
		"remediation": "Perform and document risk assessment to identify applicable Transmission stations",
	}
}

violations contains v if {
	not risk_assessment_current
	v := {
		"standard": "CIP-014",
		"requirement": "R1",
		"severity": "high",
		"description": "Transmission risk assessment not updated within 30 calendar months",
		"remediation": "Re-perform risk assessment within 30 calendar months of last assessment",
	}
}

violations contains v if {
	not third_party_verification_performed
	v := {
		"standard": "CIP-014",
		"requirement": "R2",
		"severity": "high",
		"description": "Unaffiliated third-party verification of risk assessment not performed",
		"remediation": "Engage unaffiliated third party to verify risk assessment within required timeframe",
	}
}

violations contains v if {
	not station_physical_security_plans
	v := {
		"standard": "CIP-014",
		"requirement": "R3",
		"severity": "critical",
		"description": "Physical security plan not in place for one or more applicable Transmission stations",
		"remediation": "Develop and implement physical security plans for all applicable Transmission stations",
	}
}

violations contains v if {
	not physical_security_plans_developed
	v := {
		"standard": "CIP-014",
		"requirement": "R4",
		"severity": "critical",
		"description": "Physical security plan does not meet R4 requirements for one or more applicable stations",
		"remediation": "Ensure plans include CIP Senior Manager approval, threat assessment, and required security controls",
	}
}

violations contains v if {
	not physical_threat_assessments_performed
	v := {
		"standard": "CIP-014",
		"requirement": "R4.2",
		"severity": "high",
		"description": "Physical threat assessment not performed by qualified subject matter expert",
		"remediation": "Conduct physical threat assessment by qualified security professional for each applicable station",
	}
}

violations contains v if {
	not security_plans_reviewed
	v := {
		"standard": "CIP-014",
		"requirement": "R5.1",
		"severity": "medium",
		"description": "Physical security plan not reviewed within 36 calendar months",
		"remediation": "Review and update physical security plans within every 36 calendar months",
	}
}

violations contains v if {
	not physical_security_plan_third_party_reviewed
	v := {
		"standard": "CIP-014",
		"requirement": "R6",
		"severity": "high",
		"description": "Physical security plan not reviewed by unaffiliated third party",
		"remediation": "Engage unaffiliated third party with physical security expertise to review security plan within 60 days of completion",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	no_applicable_stations # No applicable stations = fully compliant
}

compliant if {
	risk_assessment_performed
	risk_assessment_methodology_adequate
	risk_assessment_current
	third_party_verification_performed
	third_party_verification_timely
	rc_notified_of_verification
	applicable_stations_identified
	station_physical_security_plans
	physical_security_plans_developed
	physical_threat_assessments_performed
	plan_implementation_timely
	security_plans_reviewed
	plan_updated_after_topology_changes
	physical_security_plan_third_party_reviewed
}

report := {
	"standard": "CIP-014-3",
	"title": "Physical Security of Transmission Stations and Substations",
	"compliant": compliant,
	"requirements": {
		"R1_risk_assessment_performed": risk_assessment_performed,
		"R1_methodology_adequate": risk_assessment_methodology_adequate,
		"R1_assessment_current": risk_assessment_current,
		"R2_third_party_verification": third_party_verification_performed,
		"R2_verification_timely": third_party_verification_timely,
		"R2_rc_notified": rc_notified_of_verification,
		"R3_stations_identified": applicable_stations_identified,
		"R3_security_plans_in_place": station_physical_security_plans,
		"R4_security_plans_adequate": physical_security_plans_developed,
		"R4_2_threat_assessments": physical_threat_assessments_performed,
		"R4_3_implementation_timely": plan_implementation_timely,
		"R5_1_plans_reviewed": security_plans_reviewed,
		"R5_2_updated_after_changes": plan_updated_after_topology_changes,
		"R6_third_party_review": physical_security_plan_third_party_reviewed,
	},
	"station_summary": {
		"total_applicable_stations": count(input.applicable_transmission_stations),
		"stations_with_plans": count([s | s := input.applicable_transmission_stations[_]; input.station_security_plans[s.station_id].documented == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
