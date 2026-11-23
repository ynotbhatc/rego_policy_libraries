# METADATA
# title: "CIP-014-3: Physical Security of Transmission Stations and Substations"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 26
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_014

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default applicable_stations_identified := false

default physical_security_plan_third_party_reviewed := false

default physical_security_plans_developed := false

default physical_threat_assessments_performed := false

default plan_implementation_timely := false

default plan_updated_after_topology_changes := false

default rc_notified_of_verification := false

default risk_assessment_current := false

default risk_assessment_methodology_adequate := false

default risk_assessment_performed := false

default security_plans_reviewed := false

default station_physical_security_plans := false

default third_party_verification_performed := false

default third_party_verification_timely := false

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
# (mandatory and enforceable in the United States; CIP-014-4 is approved with an
# effective date of 2028-10-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-014-3.pdf
#
# Requirements of CIP-014-3 and the checks that read them:
#   R1  risk assessment; 1.1 subsequent assessments every 30 calendar months (60
#       where none was identified; the 60-month cycle is not implemented), 1.2
#       primary control center
#   R2  unaffiliated third party verification; 2.2 within 90 calendar days
#   R3  notify the Transmission Operator of the control center (not implemented)
#   R4  evaluation of potential threats and vulnerabilities (4.1-4.3)
#   R5  physical security plan (5.1-5.4), developed within 120 calendar days of
#       R2 and executed to its own timeline
#   R6  unaffiliated third party review of the R4 evaluation and R5 plan; 6.2
#       within 90 calendar days of completing the plan
#
# Reassessment after a topology change, the 36 calendar month plan review and
# the plan update after topology changes are not in CIP-014-3; they are kept as
# supporting checks and say so. The 12-month implementation window is this
# library's reading of "executed according to the timeline" in R5.

# =============================================================================
# R1: Risk Assessment — Identify Applicable Transmission Stations
# =============================================================================

# R1 - Perform an initial and subsequent risk assessments of Transmission
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

# -----------------------------------------------------------------------------
# Dated evidence
# -----------------------------------------------------------------------------

# Date normaliser: RFC 3339 strings or epoch nanoseconds; anything else is
# undefined, so the caller fails closed.
date_ns(v) := n if {
	is_string(v)
	n := time.parse_rfc3339_ns(v)
}

date_ns(v) := v if is_number(v)

# Evaluation clock. Tests pin it with `with time.now_ns as <ns>`.
now_ns := time.now_ns()

ns_per_day := 86400000000000

# Age in days of a dated record. Undefined when the date is absent, not a date,
# or later than the evaluation time: an activity dated in the future has not
# happened yet and is not evidence that it was done.
age_days(v) := (now_ns - date_ns(v)) / ns_per_day if date_ns(v) <= now_ns

# Days from start to end. Undefined when either date is absent or not a date,
# or when the end date is later than the evaluation time.
days_between(start, end) := (date_ns(end) - date_ns(start)) / ns_per_day if date_ns(end) <= now_ns

# Why a dated record cannot be used: "future", or "missing" when it is absent,
# of the wrong type or not RFC 3339. Undefined for a usable date.
date_problem(v) := "future" if date_ns(v) > now_ns

date_problem(v) := "missing" if not date_ns(v)

# R1.1 - Re-perform the assessment within 30 calendar months of last assessment
risk_assessment_current if {
	age_days(input.transmission_risk_assessment.last_assessment_date) <= 912 # 30 calendar months
}

# R1 (supporting) - Update assessment within 60 days of qualifying changes to
# transmission topology; not a part of CIP-014-3
default assessment_updated_after_changes := false

assessment_updated_after_changes if {
	every change in input.transmission_topology_changes {
		change.assessment_triggered == true
		days_between(change.change_date, change.assessment_completion_date) <= 60
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

# R2.2 - Third-party verification completed within 90 calendar days following
# the completion of the R1 risk assessment (the `timely` flag), and no older than
# the 30-month assessment cycle
third_party_verification_timely if {
	input.transmission_risk_assessment.third_party_verification.timely == true
	age_days(input.transmission_risk_assessment.third_party_verification.last_verification_date) <= 912
}

# Not gating, not a CIP-014-3 part: notification of verification completion.
# (R3 of the standard is notifying the Transmission Operator that controls the
# primary control center, within seven calendar days of completing R2.)
rc_notified_of_verification if {
	input.transmission_risk_assessment.third_party_verification.rc_notified == true
	input.transmission_risk_assessment.third_party_verification.rc_notification_date
}

# =============================================================================
# R1 and R5: Applicable Transmission Stations and their security plans
# =============================================================================

# R1 - Stations identified by the risk assessment

applicable_stations_identified if {
	count(object.get(input, ["applicable_transmission_stations"], [])) > 0
	every station in input.applicable_transmission_stations {
		station.station_id
		station.station_name
		station.risk_assessment_reference
		station.impact_level
	}
}

# No applicable stations means no further requirements under CIP-014
no_applicable_stations if {
	count(object.get(input, ["applicable_transmission_stations"], [])) == 0
	input.transmission_risk_assessment.no_applicable_stations_documented == true
}

# R5 - Physical security plan in place for each applicable station
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
# R4 and R5: Threat evaluation and Physical Security Plan
# =============================================================================

# R5 - Develop, approve, and implement a physical security plan that covers
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

# R4 - Evaluation of the potential threats and vulnerabilities of a physical
# attack on each station
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

# R5 - Plan executed according to its timeline (Part 5.3), read here as within
# 12 months of completing R2
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

	# An implementation dated after the evaluation time has not been completed.
	days_between(input.transmission_risk_assessment.third_party_verification.last_verification_date, plan.implementation_date) / 30 <= 12
}

# =============================================================================
# R5 (supporting): Physical Security Plan Review
# =============================================================================

# R5 (supporting) - Review and, if necessary, update physical security plan
# within 36 calendar months of last review; CIP-014-3 sets no review interval
# (Part 5.4 requires provisions to evaluate evolving physical threats)

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
	age_days(plan.last_review_date) <= 1095 # 36 calendar months
}

# R5 (supporting, not gating) - Update plan if changes to transmission topology
# affect applicable stations
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

	# R6.2 - Review completed within 90 calendar days of completing the security
	# plan (earlier releases used 60). A review dated after the evaluation time
	# has not been completed.
	days_between(plan.initial_completion_date, plan.third_party_review.date) <= 90
}

# Dated evidence the recency checks read.
dated_evidence contains {
	"requirement": "R1.1",
	"path": "transmission_risk_assessment.last_assessment_date",
	"value": object.get(input, ["transmission_risk_assessment", "last_assessment_date"], null),
}

dated_evidence contains {
	"requirement": "R2.2",
	"path": "transmission_risk_assessment.third_party_verification.last_verification_date",
	"value": object.get(input, ["transmission_risk_assessment", "third_party_verification", "last_verification_date"], null),
}

dated_evidence contains {
	"requirement": "R5",
	"path": sprintf("station_security_plans[%v].last_review_date", [station.station_id]),
	"value": object.get(input, ["station_security_plans", station.station_id, "last_review_date"], null),
} if {
	some station in input.applicable_transmission_stations
}

dated_evidence contains {
	"requirement": "R5",
	"path": sprintf("station_security_plans[%v].implementation_date", [station.station_id]),
	"value": object.get(input, ["station_security_plans", station.station_id, "implementation_date"], null),
} if {
	some station in input.applicable_transmission_stations
	input.station_security_plans[station.station_id].implementation_completed == true
}

dated_evidence contains {
	"requirement": "R6.2",
	"path": sprintf("station_security_plans[%v].%s", [station.station_id, field.name]),
	"value": field.value,
} if {
	some station in input.applicable_transmission_stations
	plan := input.station_security_plans[station.station_id]
	plan.third_party_review.performed == true
	some field in [
		{"name": "initial_completion_date", "value": object.get(plan, "initial_completion_date", null)},
		{"name": "third_party_review.date", "value": object.get(plan, ["third_party_review", "date"], null)},
	]
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
		"requirement": "R1.1",
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
		"requirement": "R5",
		"severity": "critical",
		"description": "Physical security plan not in place for one or more applicable Transmission stations",
		"remediation": "Develop and implement physical security plans for all applicable Transmission stations",
	}
}

violations contains v if {
	not physical_security_plans_developed
	v := {
		"standard": "CIP-014",
		"requirement": "R5",
		"severity": "critical",
		"description": "Physical security plan does not meet R5 requirements for one or more applicable stations",
		"remediation": "Ensure plans include CIP Senior Manager approval, threat assessment, and required security controls",
	}
}

violations contains v if {
	not physical_threat_assessments_performed
	v := {
		"standard": "CIP-014",
		"requirement": "R4",
		"severity": "high",
		"description": "Physical threat assessment not performed by qualified subject matter expert",
		"remediation": "Conduct physical threat assessment by qualified security professional for each applicable station",
	}
}

violations contains v if {
	not security_plans_reviewed
	v := {
		"standard": "CIP-014",
		"requirement": "R5",
		"severity": "medium",
		"description": "Physical security plan not reviewed within 36 calendar months (R5 supporting check: CIP-014-3 sets no review interval)",
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
		"remediation": "Engage unaffiliated third party with physical security expertise to review security plan within 90 calendar days of completion",
	}
}

violations contains v if {
	not assessment_updated_after_changes
	v := {
		"standard": "CIP-014",
		"requirement": "R1",
		"severity": "medium",
		"description": "Transmission risk assessment not updated within 60 days of a qualifying topology change (R1 supporting check, not a part of CIP-014-3)",
		"remediation": "Re-perform the risk assessment within 60 days of any qualifying change to transmission topology",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-014",
		"requirement": e.requirement,
		"severity": "medium",
		"description": sprintf("evidence missing — input.%s not collected or not an RFC 3339 date", [e.path]),
		"remediation": sprintf("Collect input.%s as an RFC 3339 timestamp", [e.path]),
	}
}

violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "future"
	v := {
		"standard": "CIP-014",
		"requirement": e.requirement,
		"severity": "high",
		"description": sprintf("input.%s (%v) is later than the evaluation time — a future date is not evidence of a completed activity", [e.path, e.value]),
		"remediation": sprintf("Record in input.%s the date the activity was actually completed", [e.path]),
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	no_applicable_stations # No applicable stations = fully compliant
	assessment_updated_after_changes
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
		"R1_1_assessment_current": risk_assessment_current,
		"R1_stations_identified": applicable_stations_identified,
		"R1_supporting_assessment_updated_after_changes": assessment_updated_after_changes,
		"R2_third_party_verification": third_party_verification_performed,
		"R2_2_verification_timely": third_party_verification_timely,
		"R2_supporting_rc_notified": rc_notified_of_verification,
		"R4_threat_assessments": physical_threat_assessments_performed,
		"R5_security_plans_in_place": station_physical_security_plans,
		"R5_security_plans_adequate": physical_security_plans_developed,
		"R5_implementation_timely": plan_implementation_timely,
		"R5_supporting_plans_reviewed": security_plans_reviewed,
		"R5_supporting_updated_after_changes": plan_updated_after_topology_changes,
		"R6_third_party_review": physical_security_plan_third_party_reviewed,
	},
	"station_summary": {
		"total_applicable_stations": count(object.get(input, ["applicable_transmission_stations"], [])),
		"stations_with_plans": count([s | s := input.applicable_transmission_stations[_]; input.station_security_plans[s.station_id].documented == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
