package nerc_cip.cip_010

import rego.v1

# CIP-010-4: Configuration Change Management and Vulnerability Assessments
# Requirement: Prevent and detect unauthorized changes to BES Cyber Systems
# by specifying configuration change management and vulnerability assessment
# requirements.
#
# NERC Standards Reference: CIP-010-4

# =============================================================================
# R1: Configuration Change Management
# =============================================================================

# R1.1 - Establish documented configuration change management process
change_management_process_documented if {
	input.configuration_change_management.process_documented == true
	input.configuration_change_management.approval_process_defined == true
	input.configuration_change_management.testing_requirements_defined == true
	input.configuration_change_management.rollback_procedures_defined == true
}

# R1.2 - Maintain baseline configurations for each applicable BES Cyber System
baseline_configurations_established if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not baseline_configuration_exists(system)
	]
	count(violations) == 0
}

baseline_configuration_exists(system) if {
	baseline := input.baseline_configurations[system.system_id]
	baseline.documented == true
	baseline.current == true
	baseline.authorized == true
	baseline.change_controlled == true
	# Baseline must include: OS/firmware, commercially available software, custom software,
	# logical network accessible ports, security patches
	baseline.includes_os_firmware == true
	baseline.includes_commercial_software == true
	baseline.includes_logical_ports == true
	baseline.includes_security_patches == true
}

# R1.3 - Authorize and document changes to baseline before implementation
configuration_changes_authorized if {
	violations := [change |
		change := input.configuration_changes[_]
		not change_control_adequate(change)
	]
	count(violations) == 0
}

change_control_adequate(change) if {
	change.approval_required == true
	change.approval_documented == true
	change.testing_performed == true
	change.implementation_documented == true
	change.rollback_plan_defined == true
	change.post_implementation_baseline_update == true
}

# R1.4 - Monitor for unauthorized changes to baseline configuration
unauthorized_change_monitoring if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		sys_monitoring := input.configuration_monitoring[system.system_id]
		sys_monitoring.enabled == true
		sys_monitoring.change_detection == true
		sys_monitoring.alerting_configured == true
		sys_monitoring.baseline_comparison == true
	}
}

# R1.5 - Monitor for active vulnerability announcements
active_vulnerability_monitoring if {
	input.vulnerability_monitoring.ics_cert_monitoring == true
	input.vulnerability_monitoring.vendor_advisories_monitored == true
	input.vulnerability_monitoring.response_process_documented == true
}

# R1.6 - Verify software integrity on all BES Cyber System components
software_integrity_verification if {
	input.software_integrity.verification_process_documented == true
	input.software_integrity.hash_verification == true
	input.software_integrity.vendor_verification == true
}

# =============================================================================
# R2: Configuration Monitoring
# =============================================================================

# R2 - Monitor for unauthorized changes at least every 35 days
configuration_monitoring_timely if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		sys_monitoring := input.configuration_monitoring[system.system_id]
		sys_monitoring.last_review_date
		review_age_days := (time.now_ns() - sys_monitoring.last_review_date) / (24 * 60 * 60 * 1000000000)
		review_age_days <= 35
	}
}

# =============================================================================
# R3: Vulnerability Assessments
# =============================================================================

# R3.1 - Conduct vulnerability assessments at least every 15 calendar months
vulnerability_assessments_performed if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
		not vulnerability_assessment_current(system)
	]
	count(violations) == 0
}

vulnerability_assessment_current(system) if {
	assessment := input.vulnerability_assessments[system.system_id]
	assessment_age_days := (time.now_ns() - assessment.completion_date) / (24 * 60 * 60 * 1000000000)
	assessment_age_days <= 455 # 15 calendar months
	assessment.documented == true
	assessment.remediation_plan_exists == true
}

# R3.2 - Vulnerability assessment must address identified vulnerabilities
vulnerability_remediation_tracked if {
	every assessment in input.vulnerability_assessments {
		assessment.vulnerabilities_tracked == true
		assessment.remediation_status_documented == true
		assessment.risk_accepted_documented_if_not_remediated == true
	}
}

# R3.3 - Where possible, perform authenticated scanning
authenticated_scanning_used if {
	every system in input.bes_cyber_systems {
		system.impact_categorization in ["high", "medium"]
		sys_scan := input.vulnerability_assessments[system.system_id]
		sys_scan.authenticated_scan_used == true
	}
}

# R3.4 - Perform active vulnerability assessment after each major change
post_change_assessment if {
	violations := [change |
		change := input.configuration_changes[_]
		change.is_major_change == true
		not change.post_change_vulnerability_assessment_performed == true
	]
	count(violations) == 0
}

# =============================================================================
# R4: Transient Cyber Assets (TCA) Configuration
# =============================================================================

# Transient Cyber Assets connected to High/Medium Impact BES Cyber Systems
transient_asset_config_managed if {
	input.transient_cyber_assets.config_management.policy_documented == true
	input.transient_cyber_assets.config_management.inventory_maintained == true
	input.transient_cyber_assets.config_management.security_controls_applied == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not change_management_process_documented
	v := {
		"standard": "CIP-010",
		"requirement": "R1",
		"severity": "high",
		"description": "Configuration change management process not documented",
		"remediation": "Document change management process with approval, testing, and rollback requirements",
	}
}

violations contains v if {
	not baseline_configurations_established
	v := {
		"standard": "CIP-010",
		"requirement": "R1.2",
		"severity": "critical",
		"description": "Baseline configurations not established for one or more High/Medium Impact BES Cyber Systems",
		"remediation": "Establish and maintain baseline configurations including OS, software, ports, and patches",
	}
}

violations contains v if {
	not configuration_changes_authorized
	v := {
		"standard": "CIP-010",
		"requirement": "R1.3",
		"severity": "critical",
		"description": "Unauthorized configuration changes detected or change control process inadequate",
		"remediation": "Implement change control requiring authorization, testing, documentation, and baseline update",
	}
}

violations contains v if {
	not unauthorized_change_monitoring
	v := {
		"standard": "CIP-010",
		"requirement": "R1.4",
		"severity": "high",
		"description": "Unauthorized change monitoring not implemented for all applicable systems",
		"remediation": "Implement continuous monitoring comparing current configuration to authorized baseline",
	}
}

violations contains v if {
	not configuration_monitoring_timely
	v := {
		"standard": "CIP-010",
		"requirement": "R2",
		"severity": "high",
		"description": "Configuration monitoring review not performed within 35 days for some systems",
		"remediation": "Perform configuration monitoring review at least every 35 days",
	}
}

violations contains v if {
	not vulnerability_assessments_performed
	v := {
		"standard": "CIP-010",
		"requirement": "R3.1",
		"severity": "high",
		"description": "Vulnerability assessments not performed within 15 calendar months for some systems",
		"remediation": "Conduct vulnerability assessments at least every 15 calendar months",
	}
}

violations contains v if {
	not vulnerability_remediation_tracked
	v := {
		"standard": "CIP-010",
		"requirement": "R3.2",
		"severity": "high",
		"description": "Identified vulnerabilities not being tracked and remediated",
		"remediation": "Track all identified vulnerabilities with remediation status; document accepted risks",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	change_management_process_documented
	baseline_configurations_established
	configuration_changes_authorized
	unauthorized_change_monitoring
	active_vulnerability_monitoring
	software_integrity_verification
	configuration_monitoring_timely
	vulnerability_assessments_performed
	vulnerability_remediation_tracked
	post_change_assessment
	transient_asset_config_managed
}

report := {
	"standard": "CIP-010-4",
	"title": "Configuration Change Management and Vulnerability Assessments",
	"compliant": compliant,
	"requirements": {
		"R1_change_management_process": change_management_process_documented,
		"R1_2_baselines_established": baseline_configurations_established,
		"R1_3_changes_authorized": configuration_changes_authorized,
		"R1_4_unauthorized_change_monitoring": unauthorized_change_monitoring,
		"R1_5_vulnerability_monitoring": active_vulnerability_monitoring,
		"R1_6_software_integrity": software_integrity_verification,
		"R2_monitoring_timely": configuration_monitoring_timely,
		"R3_1_vulnerability_assessments": vulnerability_assessments_performed,
		"R3_2_remediation_tracked": vulnerability_remediation_tracked,
		"R3_3_authenticated_scanning": authenticated_scanning_used,
		"R3_4_post_change_assessment": post_change_assessment,
		"R4_transient_asset_config": transient_asset_config_managed,
	},
	"violations": violations,
	"violation_count": count(violations),
}
