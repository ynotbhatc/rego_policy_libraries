package nerc_cip.cip_008

import rego.v1

# CIP-008-6: Incident Reporting and Response Planning
# Requirement: Maintain the ability to identify, classify, respond to, and
# report Cyber Security Incidents related to BES Cyber Systems.
#
# NERC Standards Reference: CIP-008-6

# =============================================================================
# R1: Cyber Security Incident Response Plan
# =============================================================================

# R1.1 - One or more documented Cyber Security Incident response plans
incident_response_plan_documented if {
	input.incident_response_plan.documented == true
	input.incident_response_plan.approved == true
}

# R1.2 - Plan must include roles and responsibilities
incident_response_roles_defined if {
	input.incident_response_plan.roles_and_responsibilities.defined == true
	input.incident_response_plan.roles_and_responsibilities.primary_lead.designated == true
	input.incident_response_plan.roles_and_responsibilities.backup_lead.designated == true
	input.incident_response_plan.roles_and_responsibilities.contact_list_current == true
}

# R1.3 - Plan must include incident handling processes
incident_handling_processes_defined if {
	input.incident_response_plan.processes.incident_classification_criteria == true
	input.incident_response_plan.processes.identification_procedures == true
	input.incident_response_plan.processes.containment_procedures == true
	input.incident_response_plan.processes.eradication_procedures == true
	input.incident_response_plan.processes.recovery_procedures == true
	input.incident_response_plan.processes.post_incident_review == true
}

# R1.4 - Plan must include process for reporting Cyber Security Incidents to NERC
nerc_reporting_process_defined if {
	input.incident_response_plan.reporting.nerc_notification_process == true
	input.incident_response_plan.reporting.e_isac_notification == true
	input.incident_response_plan.reporting.reporting_timeframe_defined == true
	input.incident_response_plan.reporting.reportable_incident_criteria_defined == true
}

# R1.5 - Process to identify and classify Reportable Cyber Security Incidents
incident_classification_process if {
	input.incident_response_plan.classification.reportable_criteria_defined == true
	input.incident_response_plan.classification.compromised_or_disrupted_operations.defined == true
	input.incident_response_plan.classification.attempted_compromise.defined == true
}

# =============================================================================
# R2: Plan Review and Communication
# =============================================================================

# R2.1 - Review, update, and communicate the plan within 15 calendar months
incident_response_plan_current if {
	last_review_ns := time.parse_rfc3339_ns(input.incident_response_plan.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# R2.2 - Within 90 days after an actual Reportable Incident, update the plan
incident_triggered_plan_updates if {
	every incident in input.reportable_cyber_incidents {
		incident.plan_review_triggered == true
		update_age_days := (incident.plan_review_completion_date - incident.incident_date) / (24 * 60 * 60 * 1000000000)
		update_age_days <= 90
	}
}

# R2.3 - Communicate plan to personnel with incident response roles
plan_communicated_to_personnel if {
	violations := [member |
		member := input.incident_response_team[_]
		not member.plan_communicated == true
	]
	count(violations) == 0
}

# =============================================================================
# R3: Incident Response Testing
# =============================================================================

# R3.1 - Test the plan at least once every 15 calendar months
# (actual events or tabletop exercise count)
incident_response_testing_performed if {
	last_test_ns := time.parse_rfc3339_ns(input.incident_response_testing.last_test_date)
	test_age_days := (time.now_ns() - last_test_ns) / (24 * 60 * 60 * 1000000000)
	test_age_days <= 455
}

# Test must be documented
incident_response_test_documented if {
	input.incident_response_testing.test_documented == true
	input.incident_response_testing.test_type # actual_incident or exercise
	input.incident_response_testing.participants_documented == true
	input.incident_response_testing.lessons_learned_captured == true
}

# R3.2 - Update the plan based on lessons learned from tests and actual incidents
lessons_learned_incorporated if {
	input.incident_response_testing.lessons_learned.reviewed == true
	input.incident_response_testing.lessons_learned.plan_updated_if_needed == true
}

# =============================================================================
# R4: Incident Response Team Training
# =============================================================================

incident_response_team_trained if {
	violations := [member |
		member := input.incident_response_team[_]
		not incident_response_training_current(member)
	]
	count(violations) == 0
}

incident_response_training_current(member) if {
	member.training.completed == true
	training_age_days := (time.now_ns() - member.training.completion_date) / (24 * 60 * 60 * 1000000000)
	training_age_days <= 455 # 15 calendar months
}

# =============================================================================
# R5: Reportable Incident Identification and Notification
# =============================================================================

# Ability to determine if an incident is reportable
reportable_incident_identification if {
	input.incident_identification.criteria_documented == true
	input.incident_identification.decision_process_documented == true
}

# Notification to NERC E-ISAC for Reportable Cyber Security Incidents
# within 1 hour of determination that an incident is reportable
nerc_notification_timely if {
	violations := [incident |
		incident := input.reportable_cyber_incidents[_]
		not notification_within_1_hour(incident)
	]
	count(violations) == 0
}

notification_within_1_hour(incident) if {
	incident.nerc_notification.sent == true
	notification_hours := (incident.nerc_notification.sent_time - incident.reportable_determination_time) / (3600 * 1000000000)
	notification_hours <= 1
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
		"requirement": "R1.2",
		"severity": "high",
		"description": "Incident response roles and responsibilities not clearly defined",
		"remediation": "Define roles, designate primary and backup leads, maintain current contact list",
	}
}

violations contains v if {
	not incident_handling_processes_defined
	v := {
		"standard": "CIP-008",
		"requirement": "R1.3",
		"severity": "high",
		"description": "Incident handling processes not fully defined (classification, containment, eradication, recovery)",
		"remediation": "Document complete incident handling procedures for all phases of incident response",
	}
}

violations contains v if {
	not nerc_reporting_process_defined
	v := {
		"standard": "CIP-008",
		"requirement": "R1.4",
		"severity": "high",
		"description": "Process for reporting Cyber Security Incidents to NERC E-ISAC not documented",
		"remediation": "Document NERC/E-ISAC notification process including timeframes and reportable criteria",
	}
}

violations contains v if {
	not incident_response_plan_current
	v := {
		"standard": "CIP-008",
		"requirement": "R2.1",
		"severity": "medium",
		"description": "Incident Response Plan not reviewed within 15 calendar months",
		"remediation": "Review, update, and communicate the Incident Response Plan within 15 calendar months",
	}
}

violations contains v if {
	not incident_response_testing_performed
	v := {
		"standard": "CIP-008",
		"requirement": "R3.1",
		"severity": "high",
		"description": "Incident Response Plan not tested within 15 calendar months",
		"remediation": "Perform tabletop exercise or actual incident test at least every 15 calendar months",
	}
}

violations contains v if {
	not incident_response_team_trained
	v := {
		"standard": "CIP-008",
		"requirement": "R4",
		"severity": "high",
		"description": "One or more incident response team members lack current training",
		"remediation": "Provide incident response training to all team members within 15 calendar months",
	}
}

violations contains v if {
	not nerc_notification_timely
	v := {
		"standard": "CIP-008",
		"requirement": "R5",
		"severity": "critical",
		"description": "NERC E-ISAC not notified within 1 hour of reportable incident determination",
		"remediation": "Implement 1-hour notification procedure to NERC E-ISAC for reportable incidents",
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
}

report := {
	"standard": "CIP-008-6",
	"title": "Incident Reporting and Response Planning",
	"compliant": compliant,
	"requirements": {
		"R1_plan_documented": incident_response_plan_documented,
		"R1_2_roles_defined": incident_response_roles_defined,
		"R1_3_handling_processes": incident_handling_processes_defined,
		"R1_4_nerc_reporting_process": nerc_reporting_process_defined,
		"R1_5_classification_process": incident_classification_process,
		"R2_1_plan_current": incident_response_plan_current,
		"R2_2_post_incident_updates": incident_triggered_plan_updates,
		"R2_3_plan_communicated": plan_communicated_to_personnel,
		"R3_1_testing_performed": incident_response_testing_performed,
		"R3_1_test_documented": incident_response_test_documented,
		"R3_2_lessons_learned": lessons_learned_incorporated,
		"R4_team_trained": incident_response_team_trained,
		"R5_reportable_identification": reportable_incident_identification,
		"R5_nerc_notification_timely": nerc_notification_timely,
	},
	"team_summary": {
		"total_ir_team_members": count(input.incident_response_team),
		"trained_members": count([m | m := input.incident_response_team[_]; m.training.completed == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
