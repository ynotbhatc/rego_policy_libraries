package nerc_cip.cip_004

import rego.v1

# CIP-004-6: Personnel & Training
# Requirement: Minimize the risk against compromise of BES Cyber Systems from
# personnel who have authorized electronic or authorized unescorted physical
# access to BES Cyber Systems by requiring appropriate training and personnel
# risk assessments.
#
# NERC Standards Reference: CIP-004-6

# =============================================================================
# R1: Security Awareness
# =============================================================================

# R1 - Provide security awareness that, at a minimum, is reinforced quarterly
security_awareness_program if {
	input.security_awareness.program_documented == true
	input.security_awareness.quarterly_reinforcement == true
	input.security_awareness.methods_documented == true # newsletters, email, posters, etc.
}

security_awareness_current if {
	last_ns := time.parse_rfc3339_ns(input.security_awareness.last_reinforcement_date)
	age_days := (time.now_ns() - last_ns) / (24 * 60 * 60 * 1000000000)
	age_days <= 92 # roughly 1 quarter
}

# =============================================================================
# R2: Cyber Security Training
# =============================================================================

# R2 - Provide initial and ongoing cybersecurity training to personnel with
# authorized electronic or unescorted physical access to BES Cyber Systems

cyber_security_training_program if {
	input.cyber_security_training.program_documented == true
	input.cyber_security_training.content.bes_cyber_system_overview == true
	input.cyber_security_training.content.security_controls_overview == true
	input.cyber_security_training.content.physical_security == true
	input.cyber_security_training.content.electronic_security == true
	input.cyber_security_training.content.incident_response == true
	input.cyber_security_training.content.acceptable_use == true
}

# All personnel with access must complete training before access is granted
# and at least annually thereafter
training_completed_for_all_authorized_personnel if {
	violations := [person |
		person := input.personnel[_]
		requires_cybersecurity_training(person)
		not training_current(person)
	]
	count(violations) == 0
}

requires_cybersecurity_training(person) if {
	person.access_level in ["authorized_electronic_access", "authorized_unescorted_physical_access", "authorized_cyber_asset_access"]
}

training_current(person) if {
	person.cyber_security_training.initial_completed == true
	training_age_days := (time.now_ns() - person.cyber_security_training.last_completion_date) / (24 * 60 * 60 * 1000000000)
	training_age_days <= 365 # annual
}

# Initial training before access is granted
initial_training_before_access(person) if {
	person.cyber_security_training.completed_before_access == true
}

# Training records maintained
training_records_maintained if {
	every person in input.personnel {
		person.cyber_security_training.record_maintained == true
	}
}

# =============================================================================
# R3: Personnel Risk Assessment (PRA)
# =============================================================================

# R3 - Conduct Personnel Risk Assessments for all personnel with authorized
# electronic or authorized unescorted physical access

personnel_risk_assessments_current if {
	violations := [person |
		person := input.personnel[_]
		requires_risk_assessment(person)
		not risk_assessment_current(person)
	]
	count(violations) == 0
}

requires_risk_assessment(person) if {
	person.access_level in ["authorized_electronic_access", "authorized_unescorted_physical_access", "authorized_cyber_asset_access"]
}

risk_assessment_current(person) if {
	person.risk_assessment.completed == true
	assessment_age_days := (time.now_ns() - person.risk_assessment.completion_date) / (24 * 60 * 60 * 1000000000)
	assessment_age_days <= 2555 # 7 years
}

# PRA must include criminal history check and 7-year look-back
risk_assessment_complete(person) if {
	person.risk_assessment.criminal_history_check == true
	person.risk_assessment.seven_year_lookback == true
	person.risk_assessment.conducted_by_qualified_entity == true
	person.risk_assessment.documented == true
}

# PRA must be performed before granting access (except for emergencies)
pra_before_access_granted if {
	violations := [person |
		person := input.personnel[_]
		requires_risk_assessment(person)
		person.risk_assessment.completed_before_access_granted == false
		not person.emergency_access_exception == true
	]
	count(violations) == 0
}

# =============================================================================
# R4: Access Management
# =============================================================================

# R4 - Verify that individuals with authorized electronic or authorized
# unescorted physical access have authorization based on job function

access_authorization_documented if {
	violations := [person |
		person := input.personnel[_]
		person.access_level in ["authorized_electronic_access", "authorized_unescorted_physical_access"]
		not person.access_authorization.documented == true
	]
	count(violations) == 0
}

access_based_on_need_to_know if {
	violations := [person |
		person := input.personnel[_]
		person.access_level in ["authorized_electronic_access", "authorized_unescorted_physical_access"]
		not person.access_authorization.need_to_know_verified == true
	]
	count(violations) == 0
}

# R4.2 - Review access authorizations at least every 15 calendar months
access_authorization_reviewed if {
	violations := [person |
		person := input.personnel[_]
		person.access_level in ["authorized_electronic_access", "authorized_unescorted_physical_access"]
		review_age_days := (time.now_ns() - person.access_authorization.last_review_date) / (24 * 60 * 60 * 1000000000)
		review_age_days > 455
	]
	count(violations) == 0
}

# =============================================================================
# R5: Access Revocation
# =============================================================================

# R5 - Revoke or change access no later than 24 hours after termination
# or change in job function requiring revocation

access_revoked_timely_on_termination if {
	violations := [person |
		person := input.personnel[_]
		person.employment_status == "terminated"
		not access_revoked_within_24h(person)
	]
	count(violations) == 0
}

access_revoked_within_24h(person) if {
	person.access_revocation.completed == true
	revocation_hours := (person.access_revocation.completion_date - person.termination_date) / (3600 * 1000000000)
	revocation_hours <= 24
}

# Shared accounts disabled upon individual departure
shared_accounts_managed if {
	violations := [person |
		person := input.personnel[_]
		person.employment_status == "terminated"
		person.had_shared_account_access == true
		not person.shared_account.password_changed == true
	]
	count(violations) == 0
}

# Change in job function: remove access no longer needed within 24 hours
access_changed_on_role_change if {
	violations := [change |
		change := input.personnel_role_changes[_]
		change.access_reduction_required == true
		not role_change_access_updated_timely(change)
	]
	count(violations) == 0
}

role_change_access_updated_timely(change) if {
	change.access_updated == true
	update_hours := (change.access_update_date - change.role_change_date) / (3600 * 1000000000)
	update_hours <= 24
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not security_awareness_program
	v := {
		"standard": "CIP-004",
		"requirement": "R1",
		"severity": "medium",
		"description": "Security awareness program not documented or quarterly reinforcement not established",
		"remediation": "Implement quarterly security awareness reinforcement (newsletters, email, training, etc.)",
	}
}

violations contains v if {
	not security_awareness_current
	v := {
		"standard": "CIP-004",
		"requirement": "R1",
		"severity": "medium",
		"description": "Security awareness has not been reinforced within the past quarter (92 days)",
		"remediation": "Provide security awareness reinforcement within every calendar quarter",
	}
}

violations contains v if {
	not cyber_security_training_program
	v := {
		"standard": "CIP-004",
		"requirement": "R2",
		"severity": "high",
		"description": "Cyber security training program not documented or missing required content areas",
		"remediation": "Establish documented training program covering all required content areas",
	}
}

violations contains v if {
	not training_completed_for_all_authorized_personnel
	v := {
		"standard": "CIP-004",
		"requirement": "R2",
		"severity": "high",
		"description": "One or more authorized personnel have not completed current cyber security training",
		"remediation": "Ensure all authorized personnel complete training before access and annually thereafter",
	}
}

violations contains v if {
	not personnel_risk_assessments_current
	v := {
		"standard": "CIP-004",
		"requirement": "R3",
		"severity": "critical",
		"description": "Personnel risk assessments not current for one or more authorized personnel",
		"remediation": "Complete PRAs for all personnel with BES Cyber System access (7-year validity)",
	}
}

violations contains v if {
	not pra_before_access_granted
	v := {
		"standard": "CIP-004",
		"requirement": "R3",
		"severity": "critical",
		"description": "Access granted to personnel before PRA was completed",
		"remediation": "Ensure PRA is completed before granting any BES Cyber System access",
	}
}

violations contains v if {
	not access_authorization_reviewed
	v := {
		"standard": "CIP-004",
		"requirement": "R4",
		"severity": "high",
		"description": "Access authorizations not reviewed within 15 calendar months",
		"remediation": "Review and reauthorize access for all personnel within every 15 calendar months",
	}
}

violations contains v if {
	not access_revoked_timely_on_termination
	v := {
		"standard": "CIP-004",
		"requirement": "R5",
		"severity": "critical",
		"description": "Access not revoked within 24 hours of termination for one or more personnel",
		"remediation": "Implement automated access revocation process triggered by HR termination events",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	security_awareness_program
	security_awareness_current
	cyber_security_training_program
	training_completed_for_all_authorized_personnel
	training_records_maintained
	personnel_risk_assessments_current
	pra_before_access_granted
	access_authorization_documented
	access_based_on_need_to_know
	access_authorization_reviewed
	access_revoked_timely_on_termination
	shared_accounts_managed
}

report := {
	"standard": "CIP-004-6",
	"title": "Personnel & Training",
	"compliant": compliant,
	"requirements": {
		"R1_security_awareness_program": security_awareness_program,
		"R1_awareness_current": security_awareness_current,
		"R2_training_program": cyber_security_training_program,
		"R2_training_completed": training_completed_for_all_authorized_personnel,
		"R2_records_maintained": training_records_maintained,
		"R3_pra_current": personnel_risk_assessments_current,
		"R3_pra_before_access": pra_before_access_granted,
		"R4_access_authorized": access_authorization_documented,
		"R4_need_to_know_verified": access_based_on_need_to_know,
		"R4_access_reviewed": access_authorization_reviewed,
		"R5_revocation_timely": access_revoked_timely_on_termination,
		"R5_shared_accounts_managed": shared_accounts_managed,
	},
	"personnel_summary": {
		"total_personnel": count(input.personnel),
		"authorized_electronic": count([p | p := input.personnel[_]; p.access_level == "authorized_electronic_access"]),
		"authorized_physical": count([p | p := input.personnel[_]; p.access_level == "authorized_unescorted_physical_access"]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
