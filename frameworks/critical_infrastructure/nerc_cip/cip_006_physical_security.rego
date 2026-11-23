# METADATA
# title: "CIP-006-6: Physical Security of BES Cyber Systems"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 25
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.cip_006

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default eacms_physically_protected := false

default pacs_physically_protected := false

default physical_access_alerting_configured := false

default physical_access_authorization_reviewed := false

default physical_access_controls_implemented := false

default physical_access_monitoring_enabled := false

default physical_security_perimeters_defined := false

default physical_security_plan_current := false

default pca_physically_protected := false

default physical_security_plan_documented := false

default standalone_assets_protected := false

default visitor_control_program_established := false

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

# CIP-006-6: Physical Security of BES Cyber Systems
# Requirement: Manage physical access to BES Cyber Systems by specifying
# a physical security plan in support of protecting BES Cyber Systems
# against compromise that could lead to misoperation or instability.
#
# NERC Standards Reference: CIP-006-6
# (mandatory and enforceable in the United States; CIP-006-7.1 is approved with
# an effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-006-6.pdf
#
# Requirement parts of CIP-006-6 and the checks that read them:
#   R1  physical security plan: 1.1 operational or procedural controls, 1.2 at
#       least one physical access control into each PSP, 1.3 two or more controls
#       for high impact (not implemented), 1.4 monitoring, 1.5 alarm or alert,
#       1.6 and 1.7 PACS monitoring and alerting, 1.8 entry logging, 1.9 90-day
#       log retention, 1.10 cabling (not implemented)
#   R2  visitor control program: 2.1 escort, 2.2 logging, 2.3 90-day retention
#   R3  PACS maintenance and testing every 24 calendar months (not implemented)
#
# CIP-006-6 has no plan review interval and no access authorization review (that
# is CIP-004-7 R4). Both checks are kept as supporting checks and say so.

# =============================================================================
# R1: Physical Security Plan
# =============================================================================

# R1 - Create and maintain a documented Physical Security Plan
physical_security_plan_documented if {
	input.physical_security_plan.documented == true
	input.physical_security_plan.approved == true
	input.physical_security_plan.scope_defined == true
	input.physical_security_plan.psps_identified == true
}

physical_security_plan_current if {
	# R1 (supporting): CIP-006-6 sets no review interval for the plan.
	age_days(input.physical_security_plan.last_review_date) <= 455 # 15 calendar months
}

# =============================================================================
# R1 - Physical Security Perimeters (PSPs) Defined (the basis for Parts 1.2-1.9)
# =============================================================================

physical_security_perimeters_defined if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not physical_security_perimeter_defined(system)
	]
	count(violations) == 0
}

physical_security_perimeter_defined(system) if {
	psp := input.physical_security_perimeters[system.system_id]
	psp.boundary_defined == true
	psp.access_points_identified == true
	psp.controls_documented == true
}

# =============================================================================
# R1.2 - Physical Access Controls at Each PSP
# =============================================================================

physical_access_controls_implemented if {
	violations := [control |
		control := input.physical_access_controls[_]
		not physical_access_control_adequate(control)
	]
	count(violations) == 0
}

physical_access_control_adequate(control) if {
	control.authentication_required == true
	control.authorization_verified == true
	control.monitoring_enabled == true
	control.logging_enabled == true
	control.visitor_escort_required == true
}

# =============================================================================
# R2 - Visitor Control Program (2.1 escort, 2.2 logging)
# =============================================================================

visitor_control_program_established if {
	input.visitor_control_program.documented == true
	input.visitor_control_program.escort_procedures == true
	input.visitor_control_program.access_logging == true
	input.visitor_control_program.identification_required == true
	input.visitor_control_program.visitor_log_maintained == true
}

# =============================================================================
# R1.4 - Physical Access Monitoring (with Part 1.9, 90-day retention) and
# R1.5 - Alerting
# =============================================================================

physical_access_monitoring_enabled if {
	every location in input.physical_locations {
		location.monitoring.enabled == true
		location.monitoring.recording_enabled == true
		location.monitoring.retention_adequate == true
		is_number(location.monitoring.retention_days)
		location.monitoring.retention_days >= 90
	}
}

# R1.5 - Alarm or alert in response to detected unauthorized access
physical_access_alerting_configured if {
	input.physical_access_alerting.enabled == true
	input.physical_access_alerting.unauthorized_attempt_alert == true
	input.physical_access_alerting.after_hours_alert == true
	input.physical_access_alerting.response_procedures_documented == true
}

# =============================================================================
# R1.1 - Operational or procedural controls to restrict physical access:
# Non-Networked (Standalone) Cyber Assets
# =============================================================================

# An explicit `false` declares that the entity has no standalone assets.
standalone_assets_protected if {
	input.standalone_bes_cyber_assets == false
}

standalone_assets_protected if {
	is_array(input.standalone_bes_cyber_assets)

	# Judge only high/medium assets; a low impact asset is out of scope.
	every asset in [a | some a in input.standalone_bes_cyber_assets; a.impact_categorization in ["high", "medium"]] {
		asset.physical_protection_documented == true
		asset.access_controlled == true
	}
}

# =============================================================================
# R1 Parts 1.2 and 1.6: Physical protection of EACMS, PCA and PACS
# =============================================================================

# R1.2 - Electronic Access Control or Monitoring Systems inside a PSP
eacms_physically_protected if {
	every eacm in input.electronic_access_control_systems {
		eacm.physical_protection.in_psp == true
		eacm.physical_protection.access_controlled == true
	}
}

# R1.6 - Physical Access Control Systems protected against and monitored for
# unauthorized physical access
pacs_physically_protected if {
	every pac in input.physical_access_control_systems {
		pac.physical_protection.access_controlled == true
		pac.physical_protection.tampering_detection == true
	}
}

# R1.2 - Protected Cyber Assets inside a PSP
pca_physically_protected if {
	input.protected_cyber_assets == false
}

pca_physically_protected if {
	every pca in input.protected_cyber_assets {
		pca.physical_protection.in_psp == true
		pca.physical_protection.access_logged == true
	}
}

# =============================================================================
# R1 (supporting): Physical Access Reviews
# =============================================================================

# Not gating, not a CIP-006-6 part: quarterly review of the plan and access
# controls. (R3 of the standard is PACS maintenance and testing.)
quarterly_review_performed if {
	age_days(input.physical_security_plan.last_quarterly_review_date) <= 92
}

# R1.2 (supporting) - Physical access authorization reviewed at least every 15
# calendar months. The review obligation itself is CIP-004-7 R4; here it is
# evidence that entry is limited to individuals with authorized access.
physical_access_review_current(person) if {
	age_days(person.physical_access_authorization.last_review_date) <= 455
}

dated_evidence contains {"requirement": "R1", "path": "physical_security_plan.last_review_date", "value": object.get(input, ["physical_security_plan", "last_review_date"], null)}

dated_evidence contains {"requirement": "R1.2", "path": sprintf("personnel[%v].physical_access_authorization.last_review_date", [object.get(person, "person_id", i)]), "value": object.get(person, ["physical_access_authorization", "last_review_date"], null)} if {
	some i, person in input.personnel
	person.access_level == "authorized_unescorted_physical_access"
}

physical_access_authorization_reviewed if {
	# No roster is no evidence.
	is_array(input.personnel)
	count(input.personnel) > 0
	violations := [person |
		person := input.personnel[_]
		person.access_level == "authorized_unescorted_physical_access"

		# A missing or unparseable last_review_date is not current.
		not physical_access_review_current(person)
	]
	count(violations) == 0
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not physical_security_plan_documented
	v := {
		"standard": "CIP-006",
		"requirement": "R1",
		"severity": "high",
		"description": "Physical Security Plan not documented or approved",
		"remediation": "Create and maintain a documented Physical Security Plan with all required elements",
	}
}

violations contains v if {
	not physical_security_plan_current
	v := {
		"standard": "CIP-006",
		"requirement": "R1",
		"severity": "medium",
		"description": "Physical Security Plan not reviewed within 15 calendar months (R1 supporting check: CIP-006-6 sets no review interval)",
		"remediation": "Review and update Physical Security Plan within every 15 calendar months",
	}
}

violations contains v if {
	not physical_security_perimeters_defined
	v := {
		"standard": "CIP-006",
		"requirement": "R1",
		"severity": "critical",
		"description": "Physical Security Perimeters not defined for all High/Medium Impact BES Cyber Systems",
		"remediation": "Define PSP boundaries and document access points for all applicable systems",
	}
}

violations contains v if {
	not physical_access_controls_implemented
	v := {
		"standard": "CIP-006",
		"requirement": "R1.2",
		"severity": "critical",
		"description": "Physical access controls inadequate at one or more Physical Security Perimeters",
		"remediation": "Implement authentication, authorization, monitoring, and logging at all PSP access points",
	}
}

violations contains v if {
	not visitor_control_program_established
	v := {
		"standard": "CIP-006",
		"requirement": "R2",
		"severity": "high",
		"description": "Visitor control program not documented or missing required elements",
		"remediation": "Establish visitor control program with escort procedures, identification, and logging",
	}
}

violations contains v if {
	not physical_access_monitoring_enabled
	v := {
		"standard": "CIP-006",
		"requirement": "R1.4",
		"severity": "high",
		"description": "Physical access monitoring not enabled (Part 1.4) or recording retention inadequate (Part 1.9) (less than 90 days)",
		"remediation": "Enable physical access monitoring with at least 90-day recording retention",
	}
}

violations contains v if {
	not physical_access_authorization_reviewed
	v := {
		"standard": "CIP-006",
		"requirement": "R1.2",
		"severity": "high",
		"description": "Physical access authorizations not reviewed within 15 calendar months (R1.2 supporting check; the review itself is CIP-004-7 R4)",
		"remediation": "Review and reauthorize physical access for all personnel within 15 calendar months",
	}
}

violations contains v if {
	not physical_access_alerting_configured
	v := {
		"standard": "CIP-006",
		"requirement": "R1.5",
		"severity": "high",
		"description": "Physical access alerting (unauthorized attempts, after-hours) not configured",
		"remediation": "Enable alerting for unauthorized and after-hours physical access with documented response procedures",
	}
}

violations contains v if {
	not eacms_physically_protected
	v := {
		"standard": "CIP-006",
		"requirement": "R1.2",
		"severity": "high",
		"description": "EACMS not physically protected within a PSP with access control",
		"remediation": "Place every EACMS in a PSP and control access to it",
	}
}

violations contains v if {
	not pacs_physically_protected
	v := {
		"standard": "CIP-006",
		"requirement": "R1.6",
		"severity": "high",
		"description": "PACS not physically protected (access control and tamper detection)",
		"remediation": "Control access to every PACS and enable tamper detection",
	}
}

violations contains v if {
	not pca_physically_protected
	v := {
		"standard": "CIP-006",
		"requirement": "R1.2",
		"severity": "high",
		"description": "Protected Cyber Assets not physically protected within a PSP with access logging",
		"remediation": "Place every PCA in a PSP and log access",
	}
}

violations contains v if {
	not standalone_assets_protected
	v := {
		"standard": "CIP-006",
		"requirement": "R1.1",
		"severity": "high",
		"description": "Standalone (non-networked) high/medium BES Cyber Assets lack documented physical protection",
		"remediation": "Document physical protection and access control for each standalone asset, or declare standalone_bes_cyber_assets as false",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-006",
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
		"standard": "CIP-006",
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
	physical_security_plan_documented
	physical_security_plan_current
	physical_security_perimeters_defined
	physical_access_controls_implemented
	visitor_control_program_established
	physical_access_monitoring_enabled
	physical_access_alerting_configured
	eacms_physically_protected
	pacs_physically_protected
	pca_physically_protected
	standalone_assets_protected
	physical_access_authorization_reviewed
}

report := {
	"standard": "CIP-006-6",
	"title": "Physical Security of BES Cyber Systems",
	"compliant": compliant,
	"requirements": {
		"R1_plan_documented": physical_security_plan_documented,
		"R1_plan_current": physical_security_plan_current,
		"R1_psps_defined": physical_security_perimeters_defined,
		"R1_1_standalone_protected": standalone_assets_protected,
		"R1_2_access_controls": physical_access_controls_implemented,
		"R1_2_eacms_protected": eacms_physically_protected,
		"R1_2_pca_protected": pca_physically_protected,
		"R1_2_access_authorization_reviewed": physical_access_authorization_reviewed,
		"R1_4_monitoring_enabled": physical_access_monitoring_enabled,
		"R1_5_alerting_configured": physical_access_alerting_configured,
		"R1_6_pacs_protected": pacs_physically_protected,
		"R2_visitor_management": visitor_control_program_established,
	},
	"violations": violations,
	"violation_count": count(violations),
}
