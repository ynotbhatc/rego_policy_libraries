package nerc_cip.cip_012

import rego.v1

# CIP-012-1: Communications Between Control Centers
# Requirement: Protect the confidentiality and integrity of Real-time Assessment
# and Real-time monitoring data transmitted between Control Centers.
#
# Applicability: High Impact BES Cyber Systems in Control Centers and their
# associated EACMS, PACS, and PCAs.
#
# NERC Standards Reference: CIP-012-1

# =============================================================================
# R1: Control Center Communication Identification
# =============================================================================

# R1 - Identify all communications links that transfer Real-time Assessment
# or Real-time monitoring data between Control Centers

control_center_communications_identified if {
	input.control_center_communications.inventory_maintained == true
	input.control_center_communications.criticality_assessed == true
	input.control_center_communications.protection_requirements_defined == true
	count(input.control_center_communications.links) > 0
}

# All communication links must have their data types classified
communication_data_classified if {
	every link in input.control_center_communications.links {
		link.data_types_identified == true
		link.real_time_assessment_data_flag
		link.real_time_monitoring_data_flag
	}
}

# =============================================================================
# R2: Communication Protection Implementation
# =============================================================================

# R2.1 - Implement one or more documented methods that are designed to
# deter, detect, or prevent unauthorized modification of Real-time Assessment
# data and Real-time monitoring data

communication_protection_implemented if {
	violations := [link |
		link := input.control_center_communications.links[_]
		not communication_protection_adequate(link)
	]
	count(violations) == 0
}

communication_protection_adequate(link) if {
	link.encryption_enabled == true
	link.authentication_implemented == true
	link.integrity_protection == true
	link.availability_protection == true
}

# Encryption requirements for communication links
communication_encryption if {
	every link in input.control_center_communications.links {
		link.encryption.algorithm_documented == true
		link.encryption.key_management_documented == true
		link.encryption.minimum_strength_adequate == true # at least AES-128
	}
}

# Authentication for control center to control center links
communication_authentication if {
	every link in input.control_center_communications.links {
		link.authentication.method_documented == true
		link.authentication.bidirectional == true
	}
}

# =============================================================================
# R3: Communication Monitoring
# =============================================================================

# Monitor real-time communication links for unauthorized activity
communication_monitoring_enabled if {
	input.communication_monitoring.enabled == true
	input.communication_monitoring.logging_implemented == true
	input.communication_monitoring.anomaly_detection == true
	input.communication_monitoring.alerting_configured == true
}

# Review communication link logs regularly
communication_log_review if {
	last_review_ns := time.parse_rfc3339_ns(input.communication_monitoring.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 35 # align with CIP-007 review frequency
}

# =============================================================================
# R4: Communication Contingency and Redundancy
# =============================================================================

# Contingency plans for loss of primary communication links
communication_contingency_plans_established if {
	input.communication_contingency.plans_documented == true
	input.communication_contingency.backup_communications == true
	input.communication_contingency.testing_performed == true
	input.communication_contingency.recovery_procedures == true
}

# Backup communication links with equivalent protection
backup_communication_protected if {
	not input.communication_contingency.backup_links_exist
} else if {
	every link in input.communication_contingency.backup_links {
		link.same_protection_level == true
		link.encryption_enabled == true
		link.authentication_implemented == true
	}
}

# =============================================================================
# R5: Plan Review
# =============================================================================

# Review communication security plan at least every 15 calendar months
communication_plan_current if {
	last_review_ns := time.parse_rfc3339_ns(input.control_center_communications.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# Test communication protection methods
communication_protection_tested if {
	last_test_ns := time.parse_rfc3339_ns(input.control_center_communications.last_test_date)
	test_age_days := (time.now_ns() - last_test_ns) / (24 * 60 * 60 * 1000000000)
	test_age_days <= 455
	input.control_center_communications.test_documented == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not control_center_communications_identified
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "high",
		"description": "Control Center communications links not identified or inventory not maintained",
		"remediation": "Identify and document all communication links transferring real-time data between Control Centers",
	}
}

violations contains v if {
	not communication_data_classified
	v := {
		"standard": "CIP-012",
		"requirement": "R1",
		"severity": "medium",
		"description": "Data types on communication links not classified (real-time assessment vs monitoring)",
		"remediation": "Classify data types on all inter-Control Center communication links",
	}
}

violations contains v if {
	not communication_protection_implemented
	v := {
		"standard": "CIP-012",
		"requirement": "R2",
		"severity": "critical",
		"description": "One or more Control Center communication links lack adequate encryption and integrity protection",
		"remediation": "Implement encryption, authentication, and integrity protection on all applicable communication links",
	}
}

violations contains v if {
	not communication_monitoring_enabled
	v := {
		"standard": "CIP-012",
		"requirement": "R3",
		"severity": "high",
		"description": "Communication link monitoring not enabled or alerting not configured",
		"remediation": "Implement monitoring, logging, and anomaly detection for all Control Center communication links",
	}
}

violations contains v if {
	not communication_contingency_plans_established
	v := {
		"standard": "CIP-012",
		"requirement": "R4",
		"severity": "medium",
		"description": "Communication contingency plans not documented or backup communications not established",
		"remediation": "Establish contingency plans with backup communication methods and tested recovery procedures",
	}
}

violations contains v if {
	not communication_plan_current
	v := {
		"standard": "CIP-012",
		"requirement": "R5",
		"severity": "medium",
		"description": "Communication security plan not reviewed within 15 calendar months",
		"remediation": "Review and update communication security plan within 15 calendar months",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	control_center_communications_identified
	communication_data_classified
	communication_protection_implemented
	communication_encryption
	communication_authentication
	communication_monitoring_enabled
	communication_contingency_plans_established
	backup_communication_protected
	communication_plan_current
	communication_protection_tested
}

report := {
	"standard": "CIP-012-1",
	"title": "Communications Between Control Centers",
	"compliant": compliant,
	"requirements": {
		"R1_communications_identified": control_center_communications_identified,
		"R1_data_classified": communication_data_classified,
		"R2_protection_implemented": communication_protection_implemented,
		"R2_encryption": communication_encryption,
		"R2_authentication": communication_authentication,
		"R3_monitoring_enabled": communication_monitoring_enabled,
		"R3_log_review": communication_log_review,
		"R4_contingency_plans": communication_contingency_plans_established,
		"R4_backup_protected": backup_communication_protected,
		"R5_plan_current": communication_plan_current,
		"R5_protection_tested": communication_protection_tested,
	},
	"link_summary": {
		"total_links": count(input.control_center_communications.links),
		"protected_links": count([l | l := input.control_center_communications.links[_]; l.encryption_enabled == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
