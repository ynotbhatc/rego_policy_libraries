# METADATA
# title: "CIP-008-6: Incident Reporting and Response Planning"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 32
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package nerc_cip.cip_008

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default incident_classification_process := false

default incident_handling_processes_defined := false

default incident_response_plan_current := false

default incident_response_plan_documented := false

default incident_response_roles_defined := false

default incident_response_team_trained := false

default incident_response_test_documented := false

default incident_response_testing_performed := false

default incident_triggered_plan_updates := false

default lessons_learned_incorporated := false

default nerc_notification_timely := false

default nerc_reporting_process_defined := false

default plan_communicated_to_personnel := false

default reportable_incident_identification := false

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

# The incident response team roster must have been supplied.
ir_team_present if {
	is_array(input.incident_response_team)
	count(input.incident_response_team) > 0
}

# CIP-008-6: Incident Reporting and Response Planning
# Requirement: Maintain the ability to identify, classify, respond to, and
# report Cyber Security Incidents related to BES Cyber Systems.
#
# NERC Standards Reference: CIP-008-6
# (mandatory and enforceable in the United States; CIP-008-7.1 is approved with
# an effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-008-6.pdf
#
# Requirement parts of CIP-008-6 and the checks that read them:
#   R1  response plan: 1.1 identify, classify and respond, 1.2 reportability and
#       attempts to compromise (1.2.3 notification per R4), 1.3 roles and
#       responsibilities, 1.4 incident handling procedures
#   R2  implementation and testing: 2.1 test every 15 calendar months, 2.2 use
#       the plan (not implemented), 2.3 retain records
#   R3  plan maintenance: 3.1 within 90 days of a test or incident (lessons
#       learned, update, notify), 3.2 within 60 days of a change (not implemented)
#   R4  notification to E-ISAC and NCCIC: 4.1 attributes (not implemented),
#       4.2 one hour after determination, 4.3 updates (not implemented)
#
# CIP-008-6 has no periodic plan review and no training requirement (training on
# incident response is CIP-004-7 R2 Part 2.1.8). Both checks are kept as
# supporting checks and say so. The standard has four requirements; there is no R5.

# =============================================================================
# R1: Cyber Security Incident Response Plan
# =============================================================================

# R1 - One or more documented Cyber Security Incident response plans
incident_response_plan_documented if {
	input.incident_response_plan.documented == true
	input.incident_response_plan.approved == true
}

# R1.3 - Roles and responsibilities of incident response groups or individuals
incident_response_roles_defined if {
	input.incident_response_plan.roles_and_responsibilities.defined == true
	input.incident_response_plan.roles_and_responsibilities.primary_lead.designated == true
	input.incident_response_plan.roles_and_responsibilities.backup_lead.designated == true
	input.incident_response_plan.roles_and_responsibilities.contact_list_current == true
}

# R1.4 - Incident handling procedures (with Part 1.1: identify, classify, respond)
incident_handling_processes_defined if {
	input.incident_response_plan.processes.incident_classification_criteria == true
	input.incident_response_plan.processes.identification_procedures == true
	input.incident_response_plan.processes.containment_procedures == true
	input.incident_response_plan.processes.eradication_procedures == true
	input.incident_response_plan.processes.recovery_procedures == true
	input.incident_response_plan.processes.post_incident_review == true
}

# R1.2 - Processes to determine reportability and to provide notification per
# R4 (Part 1.2.3)
nerc_reporting_process_defined if {
	input.incident_response_plan.reporting.nerc_notification_process == true
	input.incident_response_plan.reporting.e_isac_notification == true
	input.incident_response_plan.reporting.reporting_timeframe_defined == true
	input.incident_response_plan.reporting.reportable_incident_criteria_defined == true
}

# R1.2 - Criteria for attempts to compromise (1.2.1) and for Reportable Cyber
# Security Incidents (1.2.2)
incident_classification_process if {
	input.incident_response_plan.classification.reportable_criteria_defined == true
	input.incident_response_plan.classification.compromised_or_disrupted_operations.defined == true
	input.incident_response_plan.classification.attempted_compromise.defined == true
}

# =============================================================================
# R3: Plan Review, Update and Communication
# =============================================================================

# R3 (supporting) - Plan reviewed within 15 calendar months. CIP-008-6 has no
# periodic review; R3 maintenance is event-driven (Parts 3.1 and 3.2).
incident_response_plan_current if {
	age_days(input.incident_response_plan.last_review_date) <= 455
}

# R3.1 - Within 90 days after an actual Reportable Incident, update the plan
# Applicability must be declared (decisions 2026-10-19): R3.1 applies only when a
# Reportable Cyber Security Incident has occurred. `reportable_cyber_incidents: false`
# (or an empty list) declares none; an absent key is "applicability not determined".
incident_triggered_plan_updates if {
	input.reportable_cyber_incidents == false
}

incident_triggered_plan_updates if {
	is_array(input.reportable_cyber_incidents)
	every incident in input.reportable_cyber_incidents {
		incident.plan_review_triggered == true

		# A review dated after the evaluation time has not been completed.
		days_between(incident.incident_date, incident.plan_review_completion_date) <= 90
	}
}

# R3.1 - Notify each person or group with a defined role of the plan updates
# (Part 3.1.3)
plan_communicated_to_personnel if {
	ir_team_present
	violations := [member |
		member := input.incident_response_team[_]
		not member.plan_communicated == true
	]
	count(violations) == 0
}

# =============================================================================
# R2: Incident Response Testing
# =============================================================================

# R2.1 - Test the plan at least once every 15 calendar months
# (actual events or tabletop exercise count)
incident_response_testing_performed if {
	age_days(input.incident_response_testing.last_test_date) <= 455
}

# R2.1 / R2.3 - Test must be documented and the records retained
incident_response_test_documented if {
	input.incident_response_testing.test_documented == true
	input.incident_response_testing.test_type # actual_incident or exercise
	input.incident_response_testing.participants_documented == true
	input.incident_response_testing.lessons_learned_captured == true
}

# R3.1 - Document lessons learned (3.1.1) and update the plan (3.1.2) after tests
# and actual incidents
lessons_learned_incorporated if {
	input.incident_response_testing.lessons_learned.reviewed == true
	input.incident_response_testing.lessons_learned.plan_updated_if_needed == true
}

# =============================================================================
# R1 (supporting): Incident Response Team Training — not a CIP-008-6 requirement;
# the training obligation is CIP-004-7 R2 Part 2.1.8
# =============================================================================

incident_response_team_trained if {
	ir_team_present
	violations := [member |
		member := input.incident_response_team[_]
		not incident_response_training_current(member)
	]
	count(violations) == 0
}

incident_response_training_current(member) if {
	member.training.completed == true
	age_days(member.training.completion_date) <= 455 # 15 calendar months
}

# =============================================================================
# R1 Part 1.2 and R4: Reportable Incident Identification and Notification
# =============================================================================

# R1.2 - Ability to determine if an incident is reportable
reportable_incident_identification if {
	input.incident_identification.criteria_documented == true
	input.incident_identification.decision_process_documented == true
}

# R4.2 - Notification to E-ISAC (and NCCIC) for Reportable Cyber Security
# Incidents within one hour of the determination
nerc_notification_timely if {
	input.reportable_cyber_incidents == false
}

nerc_notification_timely if {
	is_array(input.reportable_cyber_incidents)
	violations := [incident |
		incident := input.reportable_cyber_incidents[_]
		not notification_within_1_hour(incident)
	]
	count(violations) == 0
}

notification_within_1_hour(incident) if {
	incident.nerc_notification.sent == true

	# A notification timed after the evaluation time has not been sent.
	days_between(incident.reportable_determination_time, incident.nerc_notification.sent_time) * 24 <= 1
}

# Dated evidence the recency checks read.
dated_evidence contains {
	"requirement": "R3",
	"path": "incident_response_plan.last_review_date",
	"value": object.get(input, ["incident_response_plan", "last_review_date"], null),
}

dated_evidence contains {
	"requirement": "R2.1",
	"path": "incident_response_testing.last_test_date",
	"value": object.get(input, ["incident_response_testing", "last_test_date"], null),
}

dated_evidence contains {
	"requirement": "R1",
	"path": sprintf("incident_response_team[%v].training.completion_date", [object.get(member, "member_id", i)]),
	"value": object.get(member, ["training", "completion_date"], null),
} if {
	some i, member in input.incident_response_team
	member.training.completed == true
}

dated_evidence contains {
	"requirement": "R3.1",
	"path": sprintf("reportable_cyber_incidents[%v].%s", [object.get(incident, "incident_id", i), field]),
	"value": object.get(incident, field, null),
} if {
	some i, incident in input.reportable_cyber_incidents
	incident.plan_review_triggered == true
	some field in ["incident_date", "plan_review_completion_date"]
}

dated_evidence contains {
	"requirement": "R4.2",
	"path": sprintf("reportable_cyber_incidents[%v].%s", [object.get(incident, "incident_id", i), field.name]),
	"value": field.value,
} if {
	some i, incident in input.reportable_cyber_incidents
	incident.nerc_notification.sent == true
	some field in [
		{"name": "reportable_determination_time", "value": object.get(incident, "reportable_determination_time", null)},
		{"name": "nerc_notification.sent_time", "value": object.get(incident, ["nerc_notification", "sent_time"], null)},
	]
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not incident_response_plan_documented
	v := {
		"standard": "CIP-008",
		"requirement": "R1",
		"severity": "high",
		"description": "Cyber Security Incident Response Plan not documented or approved",
		"remediation": "Create and maintain a documented Cyber Security Incident Response Plan",
	}
}

violations contains v if {
	not incident_response_roles_defined
	v := {
		"standard": "CIP-008",
		"requirement": "R1.3",
		"severity": "high",
		"description": "Incident response roles and responsibilities not clearly defined",
		"remediation": "Define roles, designate primary and backup leads, maintain current contact list",
	}
}

violations contains v if {
	not incident_handling_processes_defined
	v := {
		"standard": "CIP-008",
		"requirement": "R1.4",
		"severity": "high",
		"description": "Incident handling processes not fully defined (classification, containment, eradication, recovery)",
		"remediation": "Document complete incident handling procedures for all phases of incident response",
	}
}

violations contains v if {
	not nerc_reporting_process_defined
	v := {
		"standard": "CIP-008",
		"requirement": "R1.2",
		"severity": "high",
		"description": "Process for reporting Cyber Security Incidents to NERC E-ISAC not documented",
		"remediation": "Document NERC/E-ISAC notification process including timeframes and reportable criteria",
	}
}

violations contains v if {
	not incident_response_plan_current
	v := {
		"standard": "CIP-008",
		"requirement": "R3",
		"severity": "medium",
		"description": "Incident Response Plan not reviewed within 15 calendar months (R3 supporting check: CIP-008-6 has no periodic review)",
		"remediation": "Review, update, and communicate the Incident Response Plan within 15 calendar months",
	}
}

violations contains v if {
	not incident_response_testing_performed
	v := {
		"standard": "CIP-008",
		"requirement": "R2.1",
		"severity": "high",
		"description": "Incident Response Plan not tested within 15 calendar months",
		"remediation": "Perform tabletop exercise or actual incident test at least every 15 calendar months",
	}
}

violations contains v if {
	not incident_response_team_trained
	v := {
		"standard": "CIP-008",
		"requirement": "R1",
		"severity": "high",
		"description": "One or more incident response team members lack current training (R1 supporting check; the training requirement is CIP-004-7 R2)",
		"remediation": "Provide incident response training to all team members within 15 calendar months",
	}
}

violations contains v if {
	not incident_triggered_plan_updates
	is_array(input.reportable_cyber_incidents)
	v := {
		"standard": "CIP-008",
		"requirement": "R3.1",
		"severity": "high",
		"description": "Incident Response Plan not reviewed and updated within 90 days of a Reportable Cyber Security Incident",
		"remediation": "Complete the post-incident plan review and update within 90 days of the incident",
	}
}

incidents_declared if input.reportable_cyber_incidents == false

incidents_declared if is_array(input.reportable_cyber_incidents)

violations contains v if {
	not incidents_declared
	v := {
		"standard": "CIP-008",
		"requirement": "R3.1",
		"severity": "high",
		"description": "CIP-008 R3.1/R4.2: applicability not determined — reportable_cyber_incidents not declared",
		"remediation": "Declare reportable_cyber_incidents as a list of incidents, or false when none occurred",
	}
}

violations contains v if {
	not nerc_notification_timely
	is_array(input.reportable_cyber_incidents)
	v := {
		"standard": "CIP-008",
		"requirement": "R4.2",
		"severity": "critical",
		"description": "NERC E-ISAC not notified within 1 hour of reportable incident determination",
		"remediation": "Implement 1-hour notification procedure to NERC E-ISAC for reportable incidents",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not incident_classification_process
	v := {
		"standard": "CIP-008",
		"requirement": "R1.2",
		"severity": "medium",
		"description": "CIP-008 R1.2: incident classification process requirement not met",
		"remediation": "Satisfy and evidence the incident classification process requirement (CIP-008 R1.2)",
	}
}

violations contains v if {
	not plan_communicated_to_personnel
	v := {
		"standard": "CIP-008",
		"requirement": "R3.1",
		"severity": "medium",
		"description": "CIP-008 R3.1: plan communicated to personnel requirement not met",
		"remediation": "Satisfy and evidence the plan communicated to personnel requirement (CIP-008 R3.1)",
	}
}

violations contains v if {
	not incident_response_test_documented
	v := {
		"standard": "CIP-008",
		"requirement": "R2.1",
		"severity": "medium",
		"description": "CIP-008 R2.1: incident response test documented requirement not met",
		"remediation": "Satisfy and evidence the incident response test documented requirement (CIP-008 R2.1)",
	}
}

violations contains v if {
	not lessons_learned_incorporated
	v := {
		"standard": "CIP-008",
		"requirement": "R3.1",
		"severity": "medium",
		"description": "CIP-008 R3.1: lessons learned incorporated requirement not met",
		"remediation": "Satisfy and evidence the lessons learned incorporated requirement (CIP-008 R3.1)",
	}
}

violations contains v if {
	not reportable_incident_identification
	v := {
		"standard": "CIP-008",
		"requirement": "R1.2",
		"severity": "medium",
		"description": "CIP-008 R1.2: reportable incident identification requirement not met",
		"remediation": "Satisfy and evidence the reportable incident identification requirement (CIP-008 R1.2)",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-008",
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
		"standard": "CIP-008",
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
	incident_response_plan_documented
	incident_response_roles_defined
	incident_handling_processes_defined
	nerc_reporting_process_defined
	incident_classification_process
	incident_response_plan_current
	plan_communicated_to_personnel
	incident_response_testing_performed
	incident_response_test_documented
	lessons_learned_incorporated
	incident_response_team_trained
	reportable_incident_identification
	incident_triggered_plan_updates
	nerc_notification_timely
}

report := {
	"standard": "CIP-008-6",
	"title": "Incident Reporting and Response Planning",
	"compliant": compliant,
	"requirements": {
		"R1_plan_documented": incident_response_plan_documented,
		"R1_2_nerc_reporting_process": nerc_reporting_process_defined,
		"R1_2_classification_process": incident_classification_process,
		"R1_2_reportable_identification": reportable_incident_identification,
		"R1_3_roles_defined": incident_response_roles_defined,
		"R1_4_handling_processes": incident_handling_processes_defined,
		"R1_supporting_team_trained": incident_response_team_trained,
		"R2_1_testing_performed": incident_response_testing_performed,
		"R2_1_test_documented": incident_response_test_documented,
		"R3_1_post_incident_updates": incident_triggered_plan_updates,
		"R3_1_plan_communicated": plan_communicated_to_personnel,
		"R3_1_lessons_learned": lessons_learned_incorporated,
		"R3_supporting_plan_current": incident_response_plan_current,
		"R4_2_nerc_notification_timely": nerc_notification_timely,
	},
	"team_summary": {
		"total_ir_team_members": count(object.get(input, ["incident_response_team"], [])),
		"trained_members": count([m | m := input.incident_response_team[_]; m.training.completed == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
