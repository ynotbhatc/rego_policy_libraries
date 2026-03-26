package nerc_cip.cip_009

import rego.v1

# CIP-009-6: Recovery Plans for BES Cyber Systems
# Requirement: Recovery plans for BES Cyber Systems to support the
# continued stability, operability, and reliability of the Bulk Electric System.
#
# NERC Standards Reference: CIP-009-6

# =============================================================================
# R1: Recovery Plans
# =============================================================================

# R1 - One or more documented recovery plans that collectively include:

# R1.1 - Conditions for activating the plans
recovery_plan_activation_criteria if {
	input.recovery_plans.activation_criteria_documented == true
	input.recovery_plans.decision_authority_identified == true
}

# R1.2 - Roles and responsibilities of individuals
recovery_plan_roles_defined if {
	input.recovery_plans.roles_and_responsibilities.defined == true
	input.recovery_plans.roles_and_responsibilities.primary_lead.designated == true
	input.recovery_plans.roles_and_responsibilities.contact_list_current == true
}

# R1.3 - One or more processes for the backup and storage of information
# required to recover BES Cyber System functionality
backup_processes_documented if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not backup_procedures_adequate(system)
	]
	count(violations) == 0
}

backup_procedures_adequate(system) if {
	backup := input.backup_procedures[system.system_id]
	backup.procedures_documented == true
	backup.backup_schedule_defined == true
	backup.backup_frequency_appropriate == true
	backup.backup_testing_performed == true
	backup.offsite_storage_implemented == true
	backup.backup_integrity_verification == true
}

# R1.4 - One or more processes to preserve and storage of logs
log_preservation_process if {
	input.recovery_plans.log_preservation.process_documented == true
	input.recovery_plans.log_preservation.forensic_preservation_addressed == true
}

# R1.5 - One or more processes to reestablish network connectivity
network_reconnection_process if {
	input.recovery_plans.network_reconnection.process_documented == true
	input.recovery_plans.network_reconnection.validation_steps_defined == true
	input.recovery_plans.network_reconnection.security_verification == true
}

# Each system must have a recovery plan
recovery_plans_documented if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not recovery_plan_exists(system)
	]
	count(violations) == 0
}

recovery_plan_exists(system) if {
	plan := input.recovery_plans[system.system_id]
	plan.documented == true
	plan.procedures_defined == true
	plan.contact_information_current == true
	plan.recovery_time_objectives_defined == true
}

# =============================================================================
# R2: Plan Review and Communication
# =============================================================================

# R2.1 - Review and update recovery plans within 15 calendar months
recovery_plans_current if {
	violations := [plan |
		plan := input.recovery_plans[_]
		not recovery_plan_current(plan)
	]
	count(violations) == 0
}

recovery_plan_current(plan) if {
	plan_age_days := (time.now_ns() - plan.last_review_date) / (24 * 60 * 60 * 1000000000)
	plan_age_days <= 455
}

# R2.2 - After qualifying event, update plan within 90 days
post_event_plan_updates if {
	every event in input.qualifying_recovery_events {
		event.plan_review_triggered == true
		update_age_days := (event.plan_review_completion_date - event.event_date) / (24 * 60 * 60 * 1000000000)
		update_age_days <= 90
	}
}

# R2.3 - Communicate the plans to personnel with recovery roles
plans_communicated if {
	violations := [member |
		member := input.recovery_team[_]
		not member.plan_communicated == true
	]
	count(violations) == 0
}

# =============================================================================
# R3: Recovery Plan Testing
# =============================================================================

# R3.1 - Test the recovery plan(s) at least once every 15 calendar months
recovery_testing_performed if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not recovery_testing_current(system)
	]
	count(violations) == 0
}

recovery_testing_current(system) if {
	testing := input.recovery_testing[system.system_id]
	testing.last_test_date
	test_age_days := (time.now_ns() - testing.last_test_date) / (24 * 60 * 60 * 1000000000)
	test_age_days <= 455
	testing.test_documented == true
	testing.issues_resolved == true
}

# R3.2 - Test each backup and storage process at least once every 15 calendar months
backup_testing_performed if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not backup_test_current(system)
	]
	count(violations) == 0
}

backup_test_current(system) if {
	backup := input.backup_procedures[system.system_id]
	backup_test_age_days := (time.now_ns() - backup.last_test_date) / (24 * 60 * 60 * 1000000000)
	backup_test_age_days <= 455
	backup.test_documented == true
	backup.restoration_verified == true
}

# R3.3 - Test each activation criteria to ensure viability
activation_criteria_tested if {
	input.recovery_plans.activation_criteria_tested == true
	last_test_ns := time.parse_rfc3339_ns(input.recovery_plans.last_activation_test_date)
	test_age_days := (time.now_ns() - last_test_ns) / (24 * 60 * 60 * 1000000000)
	test_age_days <= 455
}

# =============================================================================
# R4: Incident Response Coordination
# =============================================================================

# Recovery plans aligned with incident response plans
recovery_ir_coordination if {
	input.recovery_plans.incident_response_coordination.aligned == true
	input.recovery_plans.incident_response_coordination.handoff_procedures_documented == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not recovery_plans_documented
	v := {
		"standard": "CIP-009",
		"requirement": "R1",
		"severity": "high",
		"description": "Recovery plans not documented for one or more High/Medium Impact BES Cyber Systems",
		"remediation": "Develop recovery plans for all applicable BES Cyber Systems",
	}
}

violations contains v if {
	not backup_processes_documented
	v := {
		"standard": "CIP-009",
		"requirement": "R1.3",
		"severity": "high",
		"description": "Backup procedures not documented or missing required elements for some systems",
		"remediation": "Document backup procedures with schedule, offsite storage, and integrity verification",
	}
}

violations contains v if {
	not recovery_plan_activation_criteria
	v := {
		"standard": "CIP-009",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "Recovery plan activation criteria not documented",
		"remediation": "Document criteria and decision authority for activating recovery plans",
	}
}

violations contains v if {
	not recovery_plans_current
	v := {
		"standard": "CIP-009",
		"requirement": "R2.1",
		"severity": "medium",
		"description": "One or more recovery plans not reviewed within 15 calendar months",
		"remediation": "Review, update, and communicate all recovery plans within 15 calendar months",
	}
}

violations contains v if {
	not recovery_testing_performed
	v := {
		"standard": "CIP-009",
		"requirement": "R3.1",
		"severity": "high",
		"description": "Recovery plan not tested within 15 calendar months for one or more systems",
		"remediation": "Test recovery plans at least every 15 calendar months per documented test plan",
	}
}

violations contains v if {
	not backup_testing_performed
	v := {
		"standard": "CIP-009",
		"requirement": "R3.2",
		"severity": "high",
		"description": "Backup restoration not tested within 15 calendar months for some systems",
		"remediation": "Test backup restoration for all applicable systems within 15 calendar months",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	recovery_plans_documented
	recovery_plan_activation_criteria
	recovery_plan_roles_defined
	backup_processes_documented
	log_preservation_process
	network_reconnection_process
	recovery_plans_current
	plans_communicated
	recovery_testing_performed
	backup_testing_performed
	activation_criteria_tested
}

report := {
	"standard": "CIP-009-6",
	"title": "Recovery Plans for BES Cyber Systems",
	"compliant": compliant,
	"requirements": {
		"R1_plans_documented": recovery_plans_documented,
		"R1_1_activation_criteria": recovery_plan_activation_criteria,
		"R1_2_roles_defined": recovery_plan_roles_defined,
		"R1_3_backup_processes": backup_processes_documented,
		"R1_4_log_preservation": log_preservation_process,
		"R1_5_network_reconnection": network_reconnection_process,
		"R2_1_plans_current": recovery_plans_current,
		"R2_2_post_event_updates": post_event_plan_updates,
		"R2_3_plans_communicated": plans_communicated,
		"R3_1_recovery_tested": recovery_testing_performed,
		"R3_2_backup_tested": backup_testing_performed,
		"R3_3_activation_criteria_tested": activation_criteria_tested,
	},
	"violations": violations,
	"violation_count": count(violations),
}
