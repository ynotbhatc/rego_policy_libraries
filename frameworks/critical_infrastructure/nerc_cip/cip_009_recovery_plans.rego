# METADATA
# title: "CIP-009-6: Recovery Plans for BES Cyber Systems"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 25
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_009

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default activation_criteria_tested := false

default backup_processes_documented := false

default backup_testing_performed := false

default log_preservation_process := false

default network_reconnection_process := false

default plans_communicated := false

default post_event_plan_updates := false

default recovery_plan_activation_criteria := false

default recovery_plan_roles_defined := false

default recovery_plans_current := false

default recovery_plans_documented := false

default recovery_testing_performed := false

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

# Per-system requirements need the BES Cyber System inventory to have been collected.
bes_inventory_present if is_array(input.bes_cyber_systems)

# CIP-009-6: Recovery Plans for BES Cyber Systems
# Requirement: Recovery plans for BES Cyber Systems to support the
# continued stability, operability, and reliability of the Bulk Electric System.
#
# NERC Standards Reference: CIP-009-6
# (mandatory and enforceable in the United States; CIP-009-7.1 is approved with
# an effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-009-6.pdf
#
# Requirement parts of CIP-009-6 and the checks that read them:
#   R1  recovery plan: 1.1 activation conditions, 1.2 roles, 1.3 backup and
#       storage, 1.4 verification of backups (inside the 1.3 check), 1.5 data
#       preservation
#   R2  implementation and testing: 2.1 plan test every 15 calendar months, 2.2
#       test of recovery information every 15 calendar months, 2.3 operational
#       exercise every 36 calendar months (not implemented)
#   R3  plan review, update and communication: 3.1 within 90 days of a test or
#       recovery, 3.2 within 60 days of a change (not implemented)
#
# CIP-009-6 has no periodic plan review, no network reconnection part and no
# activation-criteria test. Those checks are kept as supporting checks and say so.

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
	bes_inventory_present
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

# R1.5 - One or more processes to preserve data for determining the cause of a
# Cyber Security Incident that triggers activation of the plan
log_preservation_process if {
	input.recovery_plans.log_preservation.process_documented == true
	input.recovery_plans.log_preservation.forensic_preservation_addressed == true
}

# R1 (supporting) - Process to reestablish network connectivity; not a numbered
# part of CIP-009-6
network_reconnection_process if {
	input.recovery_plans.network_reconnection.process_documented == true
	input.recovery_plans.network_reconnection.validation_steps_defined == true
	input.recovery_plans.network_reconnection.security_verification == true
}

# Each system must have a recovery plan
recovery_plans_documented if {
	bes_inventory_present
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
# R3: Plan Review, Update and Communication
# =============================================================================

# R3 (supporting) - Recovery plans reviewed within 15 calendar months. CIP-009-6
# has no periodic review; R3 is event-driven (Parts 3.1 and 3.2).
recovery_plans_current if {
	bes_inventory_present

	# input.recovery_plans also holds scalar plan-wide settings, so review currency
	# is judged per high/medium system plan, not over every value in the object.
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not recovery_plan_current(input.recovery_plans[system.system_id])
	]
	count(violations) == 0
}

recovery_plan_current(plan) if {
	age_days(plan.last_review_date) <= 455
}

# R3.1 - After a recovery plan test or actual recovery, update the plan within
# 90 days. Applicability must be declared: `qualifying_recovery_events: false`
# (or an empty list) states that none occurred; an absent key is "applicability
# not determined" and fails closed.
post_event_plan_updates if {
	input.qualifying_recovery_events == false
}

post_event_plan_updates if {
	is_array(input.qualifying_recovery_events)
	every event in input.qualifying_recovery_events {
		event.plan_review_triggered == true

		# A review dated after the evaluation time has not been completed.
		days_between(event.event_date, event.plan_review_completion_date) <= 90
	}
}

recovery_events_undeclared if object.get(input, "qualifying_recovery_events", null) == null

# R3.1 - Notify each person or group with a defined role of the plan updates
# (Part 3.1.3)
plans_communicated if {
	is_array(input.recovery_team)
	count(input.recovery_team) > 0
	violations := [member |
		member := input.recovery_team[_]
		not member.plan_communicated == true
	]
	count(violations) == 0
}

# =============================================================================
# R2: Recovery Plan Testing
# =============================================================================

# R2.1 - Test the recovery plan(s) at least once every 15 calendar months
recovery_testing_performed if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not recovery_testing_current(system)
	]
	count(violations) == 0
}

recovery_testing_current(system) if {
	testing := input.recovery_testing[system.system_id]
	age_days(testing.last_test_date) <= 455
	testing.test_documented == true
	testing.issues_resolved == true
}

# R2.2 - Test a representative sample of the information used to recover BES
# Cyber System functionality at least once every 15 calendar months
backup_testing_performed if {
	bes_inventory_present
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not backup_test_current(system)
	]
	count(violations) == 0
}

backup_test_current(system) if {
	backup := input.backup_procedures[system.system_id]
	age_days(backup.last_test_date) <= 455
	backup.test_documented == true
	backup.restoration_verified == true
}

# R2 (supporting) - Activation criteria tested; not a numbered part of CIP-009-6
# (Part 2.3 is the 36 calendar month operational exercise)
activation_criteria_tested if {
	input.recovery_plans.activation_criteria_tested == true
	age_days(input.recovery_plans.last_activation_test_date) <= 455
}

# Dated evidence the recency checks read.
dated_evidence contains {"requirement": "R2", "path": "recovery_plans.last_activation_test_date", "value": object.get(input, ["recovery_plans", "last_activation_test_date"], null)}

dated_evidence contains {"requirement": e.requirement, "path": sprintf("%s[%v].%s", [e.collection, system.system_id, e.field]), "value": object.get(input, [e.collection, system.system_id, e.field], null)} if {
	some system in input.bes_cyber_systems
	system.impact_categorization in ["high", "medium"]
	some e in [
		{"requirement": "R3", "collection": "recovery_plans", "field": "last_review_date"},
		{"requirement": "R2.1", "collection": "recovery_testing", "field": "last_test_date"},
		{"requirement": "R2.2", "collection": "backup_procedures", "field": "last_test_date"},
	]
}

dated_evidence contains {"requirement": "R3.1", "path": sprintf("qualifying_recovery_events[%v].%s", [object.get(event, "event_id", i), field]), "value": object.get(event, field, null)} if {
	some i, event in input.qualifying_recovery_events
	event.plan_review_triggered == true
	some field in ["event_date", "plan_review_completion_date"]
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
		"requirement": "R3",
		"severity": "medium",
		"description": "One or more recovery plans not reviewed within 15 calendar months (R3 supporting check: CIP-009-6 has no periodic review)",
		"remediation": "Review, update, and communicate all recovery plans within 15 calendar months",
	}
}

violations contains v if {
	recovery_events_undeclared
	v := {
		"standard": "CIP-009",
		"requirement": "R3.1",
		"severity": "medium",
		"description": "CIP-009 R3.1: applicability not determined — qualifying_recovery_events not declared",
		"remediation": "Declare qualifying_recovery_events as a list of recovery plan tests and actual recoveries, or set it to false when none occurred",
	}
}

violations contains v if {
	not recovery_events_undeclared
	not post_event_plan_updates
	v := {
		"standard": "CIP-009",
		"requirement": "R3.1",
		"severity": "medium",
		"description": "Recovery plan not reviewed and updated within 90 days after a qualifying event",
		"remediation": "Complete the post-event plan review and update within 90 days",
	}
}

violations contains v if {
	not recovery_testing_performed
	v := {
		"standard": "CIP-009",
		"requirement": "R2.1",
		"severity": "high",
		"description": "Recovery plan not tested within 15 calendar months for one or more systems",
		"remediation": "Test recovery plans at least every 15 calendar months per documented test plan",
	}
}

violations contains v if {
	not backup_testing_performed
	v := {
		"standard": "CIP-009",
		"requirement": "R2.2",
		"severity": "high",
		"description": "Backup restoration not tested within 15 calendar months for some systems",
		"remediation": "Test backup restoration for all applicable systems within 15 calendar months",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not recovery_plan_roles_defined
	v := {
		"standard": "CIP-009",
		"requirement": "R1.2",
		"severity": "medium",
		"description": "CIP-009 R1.2: recovery plan roles defined requirement not met",
		"remediation": "Satisfy and evidence the recovery plan roles defined requirement (CIP-009 R1.2)",
	}
}

violations contains v if {
	not log_preservation_process
	v := {
		"standard": "CIP-009",
		"requirement": "R1.5",
		"severity": "medium",
		"description": "CIP-009 R1.5: log preservation process requirement not met",
		"remediation": "Satisfy and evidence the log preservation process requirement (CIP-009 R1.5)",
	}
}

violations contains v if {
	not network_reconnection_process
	v := {
		"standard": "CIP-009",
		"requirement": "R1",
		"severity": "medium",
		"description": "CIP-009 R1: network reconnection process requirement not met",
		"remediation": "Satisfy and evidence the network reconnection process requirement (CIP-009 R1)",
	}
}

violations contains v if {
	not plans_communicated
	v := {
		"standard": "CIP-009",
		"requirement": "R3.1",
		"severity": "medium",
		"description": "CIP-009 R3.1: plans communicated requirement not met",
		"remediation": "Satisfy and evidence the plans communicated requirement (CIP-009 R3.1)",
	}
}

violations contains v if {
	not activation_criteria_tested
	v := {
		"standard": "CIP-009",
		"requirement": "R2",
		"severity": "medium",
		"description": "CIP-009 R2: activation criteria tested requirement not met",
		"remediation": "Satisfy and evidence the activation criteria tested requirement (CIP-009 R2)",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-009",
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
		"standard": "CIP-009",
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
	post_event_plan_updates
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
		"R1_5_log_preservation": log_preservation_process,
		"R1_supporting_network_reconnection": network_reconnection_process,
		"R2_1_recovery_tested": recovery_testing_performed,
		"R2_2_backup_tested": backup_testing_performed,
		"R2_supporting_activation_criteria_tested": activation_criteria_tested,
		"R3_1_post_event_updates": post_event_plan_updates,
		"R3_1_plans_communicated": plans_communicated,
		"R3_supporting_plans_current": recovery_plans_current,
	},
	"violations": violations,
	"violation_count": count(violations),
}
