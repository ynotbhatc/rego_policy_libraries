package nerc_cip.cip_006

import rego.v1

# CIP-006-6: Physical Security of BES Cyber Systems
# Requirement: Manage physical access to BES Cyber Systems by specifying
# a physical security plan in support of protecting BES Cyber Systems
# against compromise that could lead to misoperation or instability.
#
# NERC Standards Reference: CIP-006-6

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
	last_review_ns := time.parse_rfc3339_ns(input.physical_security_plan.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455 # 15 calendar months
}

# =============================================================================
# R1.1 - Physical Security Perimeters (PSPs) Defined
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
# R1.3 - Visitor Management
# =============================================================================

visitor_control_program_established if {
	input.visitor_control_program.documented == true
	input.visitor_control_program.escort_procedures == true
	input.visitor_control_program.access_logging == true
	input.visitor_control_program.identification_required == true
	input.visitor_control_program.visitor_log_maintained == true
}

visitor_log_reviewed if {
	last_review_ns := time.parse_rfc3339_ns(input.visitor_control_program.last_log_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 90
}

# =============================================================================
# R1.4 - Physical Access Monitoring and Alerting
# =============================================================================

physical_access_monitoring_enabled if {
	every location in input.physical_locations {
		location.monitoring.enabled == true
		location.monitoring.recording_enabled == true
		location.monitoring.retention_adequate == true
		location.monitoring.retention_days >= 90
	}
}

# Alerting for unauthorized physical access attempts
physical_access_alerting_configured if {
	input.physical_access_alerting.enabled == true
	input.physical_access_alerting.unauthorized_attempt_alert == true
	input.physical_access_alerting.after_hours_alert == true
	input.physical_access_alerting.response_procedures_documented == true
}

# =============================================================================
# R1.5 - Protection of Non-Networked (Standalone) Cyber Assets
# =============================================================================

standalone_assets_protected if {
	every asset in input.standalone_bes_cyber_assets {
		asset.impact_categorization in ["high", "medium"]
		asset.physical_protection_documented == true
		asset.access_controlled == true
	}
}

# =============================================================================
# R2: Physical Access Controls for EACMS, PACS, and PCA
# =============================================================================

# Electronic Access Control or Monitoring Systems must also be physically protected
eacms_physically_protected if {
	every eacm in input.electronic_access_control_systems {
		eacm.physical_protection.in_psp == true
		eacm.physical_protection.access_controlled == true
	}
}

# Physical Access Control Systems physically protected
pacs_physically_protected if {
	every pac in input.physical_access_control_systems {
		pac.physical_protection.access_controlled == true
		pac.physical_protection.tampering_detection == true
	}
}

# Protected Cyber Assets physically protected
pca_physically_protected if {
	every pca in input.protected_cyber_assets {
		pca.physical_protection.in_psp == true
		pca.physical_protection.access_logged == true
	}
}

# =============================================================================
# R3: Physical Access Reviews
# =============================================================================

# R3 - Perform quarterly reviews of Physical Security Plan and access controls
quarterly_review_performed if {
	last_review_ns := time.parse_rfc3339_ns(input.physical_security_plan.last_quarterly_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 92
}

# Physical access authorization reviewed at least every 15 calendar months
physical_access_authorization_reviewed if {
	violations := [person |
		person := input.personnel[_]
		person.access_level == "authorized_unescorted_physical_access"
		review_age_days := (time.now_ns() - person.physical_access_authorization.last_review_date) / (24 * 60 * 60 * 1000000000)
		review_age_days > 455
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
		"description": "Physical Security Plan not reviewed within 15 calendar months",
		"remediation": "Review and update Physical Security Plan within every 15 calendar months",
	}
}

violations contains v if {
	not physical_security_perimeters_defined
	v := {
		"standard": "CIP-006",
		"requirement": "R1.1",
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
		"requirement": "R1.3",
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
		"description": "Physical access monitoring not enabled or recording retention inadequate (less than 90 days)",
		"remediation": "Enable physical access monitoring with at least 90-day recording retention",
	}
}

violations contains v if {
	not physical_access_authorization_reviewed
	v := {
		"standard": "CIP-006",
		"requirement": "R3",
		"severity": "high",
		"description": "Physical access authorizations not reviewed within 15 calendar months",
		"remediation": "Review and reauthorize physical access for all personnel within 15 calendar months",
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
	physical_access_authorization_reviewed
}

report := {
	"standard": "CIP-006-6",
	"title": "Physical Security of BES Cyber Systems",
	"compliant": compliant,
	"requirements": {
		"R1_plan_documented": physical_security_plan_documented,
		"R1_plan_current": physical_security_plan_current,
		"R1_1_psps_defined": physical_security_perimeters_defined,
		"R1_2_access_controls": physical_access_controls_implemented,
		"R1_3_visitor_management": visitor_control_program_established,
		"R1_4_monitoring_enabled": physical_access_monitoring_enabled,
		"R1_alerting_configured": physical_access_alerting_configured,
		"R2_eacms_protected": eacms_physically_protected,
		"R2_pacs_protected": pacs_physically_protected,
		"R3_access_authorization_reviewed": physical_access_authorization_reviewed,
	},
	"violations": violations,
	"violation_count": count(violations),
}
