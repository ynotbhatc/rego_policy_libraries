# METADATA
# title: "CIP-004-7: Personnel & Training"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 26
#     cited: 7
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_004

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default access_authorization_documented := false

default access_authorization_reviewed := false

default access_based_on_need_to_know := false

default access_revoked_timely_on_termination := false

default bcsi_access_authorized := false

default bcsi_access_program_documented := false

default bcsi_access_removed_on_termination := false

default bcsi_access_verified := false

default cyber_security_training_program := false

default personnel_risk_assessments_current := false

default pra_before_access_granted := false

default security_awareness_current := false

default security_awareness_program := false

default shared_accounts_managed := false

default training_completed_for_all_authorized_personnel := false

default training_records_maintained := false

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

# No roster is no evidence: every per-person check below requires one.
personnel_roster_present if {
	is_array(input.personnel)
	count(input.personnel) > 0
}

# CIP-004-7: Personnel & Training
# Requirement: Minimize the risk against compromise of BES Cyber Systems from
# personnel who have authorized electronic or authorized unescorted physical
# access to BES Cyber Systems by requiring appropriate training and personnel
# risk assessments.
#
# NERC Standards Reference: CIP-004-7 (FERC Docket No. RD21-6-000; mandatory and
# enforceable in the United States from 2024-01-01, replacing CIP-004-6;
# CIP-004-8 is approved with an effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-004-7.pdf
#
# Requirement parts and the checks that read them:
#   R1  1.1 quarterly security awareness reinforcement
#   R2  2.1 training content, 2.2 before access (not evaluated), 2.3 every 15 calendar months
#   R3  personnel risk assessment; 3.5 within the last seven years
#   R4  4.1 authorization based on need, 4.2 quarterly record check (not
#       implemented), 4.3 15 calendar month verification of electronic access
#   R5  5.1 removal within 24 hours of a termination action, 5.2 transfers (not
#       gating), 5.3 non-shared accounts within 30 days (not implemented),
#       5.4 shared account passwords
#   R6  provisioned access to BCSI: 6.1 authorize, 6.2 verify every 15 calendar
#       months, 6.3 remove on termination (new in CIP-004-7)

# =============================================================================
# R1: Security Awareness
# =============================================================================

# R1.1 - Security awareness that, at least once each calendar quarter, reinforces
# cyber security practices
security_awareness_program if {
	input.security_awareness.program_documented == true
	input.security_awareness.quarterly_reinforcement == true
	input.security_awareness.methods_documented == true # newsletters, email, posters, etc.
}

security_awareness_current if {
	age_days(input.security_awareness.last_reinforcement_date) <= 92 # roughly 1 quarter
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

# R2.3 - All personnel with access must complete the training at least once
# every 15 calendar months (earlier releases used 365 days)
training_completed_for_all_authorized_personnel if {
	personnel_roster_present
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
	age_days(person.cyber_security_training.last_completion_date) <= 455 # 15 calendar months
}

# R2.2 (not evaluated) - Initial training before access is granted
initial_training_before_access(person) if {
	person.cyber_security_training.completed_before_access == true
}

# R2 - Training records maintained (evidence for Measure M2)
training_records_maintained if {
	personnel_roster_present
	every person in input.personnel {
		person.cyber_security_training.record_maintained == true
	}
}

# =============================================================================
# R3: Personnel Risk Assessment (PRA)
# =============================================================================

# R3 - Conduct Personnel Risk Assessments for all personnel with authorized
# electronic or authorized unescorted physical access; R3.5 - completed within
# the last seven years

personnel_risk_assessments_current if {
	personnel_roster_present
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

# DATA_SOURCES.md documents flat risk_assessment_completed / risk_assessment_date;
# the older nested risk_assessment.completed / completion_date form is also accepted.
risk_assessment_current(person) if {
	person.risk_assessment_completed == true
	risk_assessment_age_ok(person.risk_assessment_date)
}

risk_assessment_current(person) if {
	person.risk_assessment.completed == true
	risk_assessment_age_ok(person.risk_assessment.completion_date)
}

risk_assessment_age_ok(assessed) if {
	age_days(assessed) <= 2555 # 7 years
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
	personnel_roster_present
	violations := [person |
		person := input.personnel[_]
		requires_risk_assessment(person)

		# Missing completed_before_access_granted is not a pass.
		not person.risk_assessment.completed_before_access_granted == true
		not person.emergency_access_exception == true
	]
	count(violations) == 0
}

# =============================================================================
# R4: Access Management
# =============================================================================

# R4.1 - Authorize electronic access (4.1.1) and unescorted physical access
# (4.1.2) based on need

requires_access_authorization(person) if {
	person.access_level in ["authorized_electronic_access", "authorized_unescorted_physical_access", "authorized_cyber_asset_access"]
}

access_authorization_documented if {
	personnel_roster_present
	violations := [person |
		person := input.personnel[_]
		requires_access_authorization(person)
		not person.access_authorization.documented == true
	]
	count(violations) == 0
}

access_based_on_need_to_know if {
	personnel_roster_present
	violations := [person |
		person := input.personnel[_]
		requires_access_authorization(person)
		not person.access_authorization.need_to_know_verified == true
	]
	count(violations) == 0
}

# R4.3 - Verify access privileges at least once every 15 calendar months. (Part
# 4.2 is the quarterly authorization record check, which is not implemented.)
access_review_current(person) if {
	age_days(person.access_authorization.last_review_date) <= 455
}

access_authorization_reviewed if {
	personnel_roster_present
	violations := [person |
		person := input.personnel[_]
		requires_access_authorization(person)

		# A missing or unparseable last_review_date is not current.
		not access_review_current(person)
	]
	count(violations) == 0
}

# =============================================================================
# R5: Access Revocation
# =============================================================================

# R5.1 - Complete the removal of the ability for unescorted physical access and
# Interactive Remote Access within 24 hours of a termination action

access_revoked_timely_on_termination if {
	personnel_roster_present
	violations := [person |
		person := input.personnel[_]
		person.employment_status == "terminated"
		not access_revoked_within_24h(person)
	]
	count(violations) == 0
}

access_revoked_within_24h(person) if {
	person.access_revocation.completed == true

	# A revocation dated after the evaluation time has not been completed.
	days_between(person.termination_date, person.access_revocation.completion_date) <= 1
}

# R5.4 - Change passwords for shared accounts known to the user after a
# termination action
shared_accounts_managed if {
	personnel_roster_present
	violations := [person |
		person := input.personnel[_]
		person.employment_status == "terminated"
		person.had_shared_account_access == true
		not person.shared_account.password_changed == true
	]
	count(violations) == 0
}

# R5.2 (not gating) - Reassignments or transfers: revoke access no longer needed
# by the end of the next calendar day (read here as 24 hours)
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
	days_between(change.role_change_date, change.access_update_date) <= 1
}

# =============================================================================
# R6: Access Management for BES Cyber System Information (new in CIP-004-7)
# =============================================================================

# R6 - Documented access management program(s) to authorize, verify, and revoke
# provisioned access to BCSI. CIP-004-7 moved BCSI access here from CIP-004-6
# Parts 4.1.3, 4.4 and 5.3 and from CIP-011.
#
# Facts: input.bcsi_access.program_documented and input.bcsi_access.provisioned,
# one entry per individual with provisioned access to BCSI. An empty list states
# that nobody has provisioned access; an absent list is evidence missing.
bcsi_access_program_documented if input.bcsi_access.program_documented == true

bcsi_provisioned_collected if is_array(input.bcsi_access.provisioned)

# A termination action that has taken effect. A termination dated after the
# evaluation time is planned, not effective: the entry is still active.
bcsi_terminated(entry) if date_ns(entry.termination_date) <= now_ns

# R6.1 - Prior to provisioning, authorize based on need (6.1.1 electronic access
# to electronic BCSI, 6.1.2 physical access to physical BCSI), except for CIP
# Exceptional Circumstances
bcsi_access_authorized if {
	bcsi_provisioned_collected
	every entry in input.bcsi_access.provisioned {
		bcsi_entry_authorized(entry)
	}
}

bcsi_entry_authorized(entry) if entry.authorized_before_provisioning == true

bcsi_entry_authorized(entry) if entry.cip_exceptional_circumstance == true

# R6.2 - Verify at least once every 15 calendar months that every individual with
# provisioned access has an authorization record (6.2.1) and still needs the
# access (6.2.2)
bcsi_access_verified if {
	bcsi_provisioned_collected
	every entry in input.bcsi_access.provisioned {
		bcsi_entry_verified(entry)
	}
}

bcsi_entry_verified(entry) if bcsi_terminated(entry)

bcsi_entry_verified(entry) if {
	entry.authorization_record == true
	entry.need_verified == true
	age_days(entry.last_verification_date) <= 455
}

# R6.3 - For termination actions, remove the ability to use provisioned access to
# BCSI by the end of the next calendar day following the effective date of the
# termination action. Calendar days are taken in UTC.
bcsi_access_removed_on_termination if {
	bcsi_provisioned_collected
	every entry in input.bcsi_access.provisioned {
		bcsi_entry_removal_timely(entry)
	}
}

bcsi_removal_deadline_ns(entry) := (floor(date_ns(entry.termination_date) / ns_per_day) + 2) * ns_per_day

bcsi_entry_removal_timely(entry) if not "termination_date" in object.keys(entry)

# Still inside the window (this also covers a planned, future termination).
bcsi_entry_removal_timely(entry) if now_ns < bcsi_removal_deadline_ns(entry)

bcsi_entry_removal_timely(entry) if {
	removed_ns := date_ns(entry.access_removed_date)
	removed_ns <= now_ns
	removed_ns < bcsi_removal_deadline_ns(entry)
}


# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not security_awareness_program
	v := {
		"standard": "CIP-004",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "Security awareness program not documented or quarterly reinforcement not established",
		"remediation": "Implement quarterly security awareness reinforcement (newsletters, email, training, etc.)",
	}
}

violations contains v if {
	not security_awareness_current
	v := {
		"standard": "CIP-004",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "Security awareness has not been reinforced within the past quarter (92 days)",
		"remediation": "Provide security awareness reinforcement within every calendar quarter",
	}
}

violations contains v if {
	not cyber_security_training_program
	v := {
		"standard": "CIP-004",
		"requirement": "R2.1",
		"severity": "high",
		"description": "Cyber security training program not documented or missing required content areas",
		"remediation": "Establish documented training program covering all required content areas",
	}
}

violations contains v if {
	not training_completed_for_all_authorized_personnel
	v := {
		"standard": "CIP-004",
		"requirement": "R2.3",
		"severity": "high",
		"description": "One or more authorized personnel have not completed current cyber security training",
		"remediation": "Ensure all authorized personnel complete training before access and at least once every 15 calendar months",
	}
}

violations contains v if {
	not personnel_risk_assessments_current
	v := {
		"standard": "CIP-004",
		"requirement": "R3.5",
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
		"requirement": "R4.3",
		"severity": "high",
		"description": "Access authorizations not reviewed within 15 calendar months",
		"remediation": "Review and reauthorize access for all personnel within every 15 calendar months",
	}
}

violations contains v if {
	not access_revoked_timely_on_termination
	v := {
		"standard": "CIP-004",
		"requirement": "R5.1",
		"severity": "critical",
		"description": "Access not revoked within 24 hours of termination for one or more personnel",
		"remediation": "Implement automated access revocation process triggered by HR termination events",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not training_records_maintained
	v := {
		"standard": "CIP-004",
		"requirement": "R2",
		"severity": "medium",
		"description": "CIP-004 R2: training records maintained requirement not met",
		"remediation": "Satisfy and evidence the training records maintained requirement (CIP-004 R2)",
	}
}

violations contains v if {
	not access_authorization_documented
	v := {
		"standard": "CIP-004",
		"requirement": "R4.1",
		"severity": "medium",
		"description": "CIP-004 R4.1: access authorization documented requirement not met",
		"remediation": "Satisfy and evidence the access authorization documented requirement (CIP-004 R4.1)",
	}
}

violations contains v if {
	not access_based_on_need_to_know
	v := {
		"standard": "CIP-004",
		"requirement": "R4.1",
		"severity": "medium",
		"description": "CIP-004 R4.1: access based on need to know requirement not met",
		"remediation": "Satisfy and evidence the access based on need to know requirement (CIP-004 R4.1)",
	}
}

violations contains v if {
	not shared_accounts_managed
	v := {
		"standard": "CIP-004",
		"requirement": "R5.4",
		"severity": "medium",
		"description": "CIP-004 R5.4: shared accounts managed requirement not met",
		"remediation": "Satisfy and evidence the shared accounts managed requirement (CIP-004 R5.4)",
	}
}

# R6 (CIP-004-7): provisioned access to BES Cyber System Information.
violations contains v if {
	not bcsi_access_program_documented
	v := {
		"standard": "CIP-004",
		"requirement": "R6",
		"severity": "high",
		"description": "Access management program for provisioned access to BCSI not documented (R6)",
		"remediation": "Document the program used to authorize, verify and revoke provisioned access to BCSI",
	}
}

violations contains v if {
	not bcsi_provisioned_collected
	v := {
		"standard": "CIP-004",
		"requirement": "R6",
		"severity": "high",
		"description": "evidence missing — input.bcsi_access.provisioned not collected (list of individuals with provisioned access to BCSI; an empty list when there are none)",
		"remediation": "Collect the list of individuals with provisioned electronic or physical access to BCSI",
	}
}

violations contains v if {
	some i, entry in input.bcsi_access.provisioned
	not bcsi_entry_authorized(entry)
	v := {
		"standard": "CIP-004",
		"requirement": "R6.1",
		"severity": "high",
		"description": sprintf("Access to BCSI provisioned for %v without prior authorization based on need (R6.1)", [person_label(i, entry)]),
		"remediation": "Authorize provisioned access to BCSI based on need before provisioning it",
	}
}

violations contains v if {
	some i, entry in input.bcsi_access.provisioned
	not bcsi_entry_verified(entry)
	v := {
		"standard": "CIP-004",
		"requirement": "R6.2",
		"severity": "high",
		"description": sprintf("Provisioned access to BCSI for %v not verified within 15 calendar months (authorization record and continued need, R6.2)", [person_label(i, entry)]),
		"remediation": "Verify at least once every 15 calendar months that each individual has an authorization record and still needs the access",
	}
}

violations contains v if {
	some i, entry in input.bcsi_access.provisioned
	not bcsi_entry_removal_timely(entry)
	v := {
		"standard": "CIP-004",
		"requirement": "R6.3",
		"severity": "critical",
		"description": sprintf("Provisioned access to BCSI for %v not removed by the end of the next calendar day after the termination action (R6.3)", [person_label(i, entry)]),
		"remediation": "Remove the individual's ability to use provisioned access to BCSI by the end of the next calendar day following the effective date of the termination action",
	}
}

# Dated evidence the recency checks read (one entry per date actually used).
person_label(i, person) := object.get(person, "person_id", sprintf("%d", [i]))

dated_evidence contains {"requirement": "R1.1", "path": "security_awareness.last_reinforcement_date", "value": object.get(input, ["security_awareness", "last_reinforcement_date"], null)}

dated_evidence contains {"requirement": "R2.3", "path": sprintf("personnel[%v].cyber_security_training.last_completion_date", [person_label(i, person)]), "value": object.get(person, ["cyber_security_training", "last_completion_date"], null)} if {
	some i, person in input.personnel
	requires_cybersecurity_training(person)
	person.cyber_security_training.initial_completed == true
}

dated_evidence contains {"requirement": "R3.5", "path": sprintf("personnel[%v].risk_assessment_date", [person_label(i, person)]), "value": object.get(person, "risk_assessment_date", null)} if {
	some i, person in input.personnel
	requires_risk_assessment(person)
	person.risk_assessment_completed == true
}

dated_evidence contains {"requirement": "R3.5", "path": sprintf("personnel[%v].risk_assessment.completion_date", [person_label(i, person)]), "value": object.get(person, ["risk_assessment", "completion_date"], null)} if {
	some i, person in input.personnel
	requires_risk_assessment(person)
	person.risk_assessment.completed == true
}

dated_evidence contains {"requirement": "R4.3", "path": sprintf("personnel[%v].access_authorization.last_review_date", [person_label(i, person)]), "value": object.get(person, ["access_authorization", "last_review_date"], null)} if {
	some i, person in input.personnel
	requires_access_authorization(person)
}

dated_evidence contains {"requirement": "R5.1", "path": sprintf("personnel[%v].%s", [person_label(i, person), field.name]), "value": field.value} if {
	some i, person in input.personnel
	person.employment_status == "terminated"
	person.access_revocation.completed == true
	some field in [
		{"name": "termination_date", "value": object.get(person, "termination_date", null)},
		{"name": "access_revocation.completion_date", "value": object.get(person, ["access_revocation", "completion_date"], null)},
	]
}

dated_evidence contains {"requirement": "R6.2", "path": sprintf("bcsi_access.provisioned[%v].last_verification_date", [person_label(i, entry)]), "value": object.get(entry, "last_verification_date", null)} if {
	some i, entry in input.bcsi_access.provisioned
	not bcsi_terminated(entry)
}

dated_evidence contains {"requirement": "R6.3", "path": sprintf("bcsi_access.provisioned[%v].access_removed_date", [person_label(i, entry)]), "value": entry.access_removed_date} if {
	some i, entry in input.bcsi_access.provisioned
	"access_removed_date" in object.keys(entry)
}

# A recorded termination date that is not a date leaves Part 6.3 undecidable.
violations contains v if {
	some i, entry in input.bcsi_access.provisioned
	"termination_date" in object.keys(entry)
	not date_ns(entry.termination_date)
	v := {
		"standard": "CIP-004",
		"requirement": "R6.3",
		"severity": "medium",
		"description": sprintf("evidence missing — input.bcsi_access.provisioned[%v].termination_date not an RFC 3339 date", [person_label(i, entry)]),
		"remediation": "Record the effective date of the termination action as an RFC 3339 timestamp",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-004",
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
		"standard": "CIP-004",
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
	bcsi_access_program_documented
	bcsi_access_authorized
	bcsi_access_verified
	bcsi_access_removed_on_termination
}

report := {
	"standard": "CIP-004-7",
	"title": "Personnel & Training",
	"compliant": compliant,
	"requirements": {
		"R1_1_security_awareness_program": security_awareness_program,
		"R1_1_awareness_current": security_awareness_current,
		"R2_1_training_program": cyber_security_training_program,
		"R2_3_training_completed": training_completed_for_all_authorized_personnel,
		"R2_records_maintained": training_records_maintained,
		"R3_5_pra_current": personnel_risk_assessments_current,
		"R3_pra_before_access": pra_before_access_granted,
		"R4_1_access_authorized": access_authorization_documented,
		"R4_1_need_to_know_verified": access_based_on_need_to_know,
		"R4_3_access_reviewed": access_authorization_reviewed,
		"R5_1_revocation_timely": access_revoked_timely_on_termination,
		"R5_4_shared_accounts_managed": shared_accounts_managed,
		"R6_bcsi_program_documented": bcsi_access_program_documented,
		"R6_1_bcsi_access_authorized": bcsi_access_authorized,
		"R6_2_bcsi_access_verified": bcsi_access_verified,
		"R6_3_bcsi_access_removed_on_termination": bcsi_access_removed_on_termination,
	},
	"personnel_summary": {
		"total_personnel": count(object.get(input, ["personnel"], [])),
		"authorized_electronic": count([p | p := input.personnel[_]; p.access_level == "authorized_electronic_access"]),
		"authorized_physical": count([p | p := input.personnel[_]; p.access_level == "authorized_unescorted_physical_access"]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
