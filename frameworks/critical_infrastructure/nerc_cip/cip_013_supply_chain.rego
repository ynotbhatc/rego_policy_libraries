package nerc_cip.cip_013

import rego.v1

# CIP-013-2: Supply Chain Risk Management
# Requirement: Mitigate cyber security risks in the supply chain for industrial
# control system hardware, software, and computing and networking services
# associated with BES Cyber Systems.
#
# NERC Standards Reference: CIP-013-2

# =============================================================================
# R1: Supply Chain Cyber Security Risk Management Plan
# =============================================================================

# R1.1 - One or more documented plans that include a process to identify and
# assess cyber security risks in the supply chain

supply_chain_cyber_security_plan_implemented if {
	input.supply_chain_plan.documented == true
	input.supply_chain_plan.approved == true
	input.supply_chain_plan.current == true
	input.supply_chain_plan.cip_senior_manager_approved == true
	input.supply_chain_plan.vendor_requirements_defined == true
}

# R1.2.1 - Notification from vendors about identified security vulnerabilities
vendor_vulnerability_notification_process if {
	input.supply_chain_plan.processes.vendor_vulnerability_notification == true
	input.supply_chain_plan.processes.notification_response_procedures == true
}

# R1.2.2 - Notification from vendors of vendor-identified incidents related to
# delivered products and services
vendor_incident_notification_process if {
	input.supply_chain_plan.processes.vendor_incident_notification == true
	input.supply_chain_plan.processes.incident_escalation_procedures == true
}

# R1.2.3 - Verification of software integrity and authenticity of all
# software and patches provided by vendors
software_authenticity_verification_process if {
	input.supply_chain_plan.processes.software_integrity_verification == true
	input.supply_chain_plan.processes.hash_or_signature_verification == true
	input.supply_chain_plan.processes.vendor_provided_verification_method == true
}

# R1.2.4 - Coordination of responses to vendor-identified incidents
incident_coordination_process if {
	input.supply_chain_plan.processes.vendor_incident_coordination == true
	input.supply_chain_plan.processes.information_sharing_agreements == true
}

# R1.2.5 - Verification that remote access sessions by vendors are monitored,
# logged, and controlled
vendor_remote_access_controlled if {
	input.supply_chain_plan.processes.vendor_remote_access_policy == true
	input.supply_chain_plan.processes.vendor_remote_access_monitoring == true
	input.supply_chain_plan.processes.vendor_remote_access_logging == true
	input.supply_chain_plan.processes.vendor_remote_access_control == true
}

# =============================================================================
# R2: Vendor Risk Assessments
# =============================================================================

vendor_risk_assessments_performed if {
	violations := [vendor |
		vendor := input.vendors[_]
		vendor.criticality_level in ["high", "medium"]
		not vendor_risk_assessment_current(vendor)
	]
	count(violations) == 0
}

vendor_risk_assessment_current(vendor) if {
	assessment := input.vendor_risk_assessments[vendor.vendor_id]
	assessment.completed == true
	assessment_age_days := (time.now_ns() - assessment.completion_date) / (24 * 60 * 60 * 1000000000)
	assessment_age_days <= 1095 # 3 years
	assessment.risks_identified == true
	assessment.mitigation_plan_exists == true
}

# Vendor risk assessment covers supply chain factors
vendor_assessment_comprehensive(vendor) if {
	assessment := input.vendor_risk_assessments[vendor.vendor_id]
	assessment.covers.vulnerability_disclosure_capability == true
	assessment.covers.incident_response_capability == true
	assessment.covers.software_development_practices == true
	assessment.covers.third_party_dependencies == true
}

# =============================================================================
# R3: Plan Implementation and Vendor Engagement
# =============================================================================

# Procurement controls in vendor contracts
vendor_contracts_include_security_requirements if {
	violations := [vendor |
		vendor := input.vendors[_]
		vendor.criticality_level in ["high", "medium"]
		not vendor_contract_adequate(vendor)
	]
	count(violations) == 0
}

vendor_contract_adequate(vendor) if {
	contract := input.vendor_contracts[vendor.vendor_id]
	contract.security_requirements_included == true
	contract.vulnerability_notification_clause == true
	contract.incident_notification_clause == true
	contract.software_integrity_requirements == true
	contract.right_to_audit_clause == true
}

# =============================================================================
# R4: Supply Chain Monitoring
# =============================================================================

supply_chain_monitoring_implemented if {
	input.supply_chain_monitoring.enabled == true
	input.supply_chain_monitoring.threat_intelligence == true
	input.supply_chain_monitoring.vulnerability_tracking == true
	input.supply_chain_monitoring.incident_detection == true
}

# Monitor vendor security notifications and bulletins
vendor_notification_monitoring if {
	input.supply_chain_monitoring.vendor_bulletin_monitoring == true
	input.supply_chain_monitoring.ics_cert_advisory_monitoring == true
	input.supply_chain_monitoring.response_process_documented == true
}

# =============================================================================
# R5: Plan Review
# =============================================================================

# Review the supply chain cyber security risk management plan within
# 15 calendar months of the last review and after triggered events
supply_chain_plan_review_current if {
	last_review_ns := time.parse_rfc3339_ns(input.supply_chain_plan.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# CIP Senior Manager must approve the plan
cip_senior_manager_approved if {
	input.supply_chain_plan.cip_senior_manager_approved == true
	approval_ns := time.parse_rfc3339_ns(input.supply_chain_plan.approval_date)
	approval_age_days := (time.now_ns() - approval_ns) / (24 * 60 * 60 * 1000000000)
	approval_age_days <= 455
}

# =============================================================================
# R6: Incident Response Coordination with Vendors
# =============================================================================

incident_response_coordination_established if {
	input.supply_chain_incident_response.procedures_documented == true
	input.supply_chain_incident_response.vendor_contacts_current == true
	input.supply_chain_incident_response.information_sharing_agreements == true
	input.supply_chain_incident_response.coordination_tested == true
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not supply_chain_cyber_security_plan_implemented
	v := {
		"standard": "CIP-013",
		"requirement": "R1",
		"severity": "high",
		"description": "Supply chain cyber security risk management plan not documented or not CIP Senior Manager approved",
		"remediation": "Develop and obtain CIP Senior Manager approval for supply chain cyber security risk management plan",
	}
}

violations contains v if {
	not vendor_vulnerability_notification_process
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.1",
		"severity": "high",
		"description": "Process for receiving vendor vulnerability notifications not documented",
		"remediation": "Establish process for vendors to notify of security vulnerabilities in supplied products",
	}
}

violations contains v if {
	not software_authenticity_verification_process
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.3",
		"severity": "critical",
		"description": "Software integrity and authenticity verification process not established",
		"remediation": "Implement software hash/signature verification for all vendor-provided software and patches",
	}
}

violations contains v if {
	not vendor_remote_access_controlled
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.5",
		"severity": "critical",
		"description": "Vendor remote access not adequately monitored, logged, and controlled",
		"remediation": "Implement vendor remote access controls with monitoring, logging, and active session management",
	}
}

violations contains v if {
	not vendor_risk_assessments_performed
	v := {
		"standard": "CIP-013",
		"requirement": "R2",
		"severity": "high",
		"description": "Vendor risk assessments not current for one or more high/medium criticality vendors",
		"remediation": "Conduct comprehensive vendor risk assessments within 3 years for all critical vendors",
	}
}

violations contains v if {
	not vendor_contracts_include_security_requirements
	v := {
		"standard": "CIP-013",
		"requirement": "R3",
		"severity": "high",
		"description": "Vendor contracts missing required security requirements for critical vendors",
		"remediation": "Include security requirements, vulnerability/incident notification clauses, and audit rights in vendor contracts",
	}
}

violations contains v if {
	not supply_chain_plan_review_current
	v := {
		"standard": "CIP-013",
		"requirement": "R5",
		"severity": "medium",
		"description": "Supply chain cyber security risk management plan not reviewed within 15 calendar months",
		"remediation": "Review and update supply chain plan within 15 calendar months; obtain CIP Senior Manager re-approval",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	supply_chain_cyber_security_plan_implemented
	vendor_vulnerability_notification_process
	vendor_incident_notification_process
	software_authenticity_verification_process
	incident_coordination_process
	vendor_remote_access_controlled
	vendor_risk_assessments_performed
	vendor_contracts_include_security_requirements
	supply_chain_monitoring_implemented
	vendor_notification_monitoring
	supply_chain_plan_review_current
	cip_senior_manager_approved
	incident_response_coordination_established
}

report := {
	"standard": "CIP-013-2",
	"title": "Supply Chain Risk Management",
	"compliant": compliant,
	"requirements": {
		"R1_plan_implemented": supply_chain_cyber_security_plan_implemented,
		"R1_2_1_vuln_notification": vendor_vulnerability_notification_process,
		"R1_2_2_incident_notification": vendor_incident_notification_process,
		"R1_2_3_software_authenticity": software_authenticity_verification_process,
		"R1_2_4_incident_coordination": incident_coordination_process,
		"R1_2_5_vendor_remote_access": vendor_remote_access_controlled,
		"R2_vendor_risk_assessments": vendor_risk_assessments_performed,
		"R3_vendor_contracts": vendor_contracts_include_security_requirements,
		"R4_supply_chain_monitoring": supply_chain_monitoring_implemented,
		"R5_plan_review_current": supply_chain_plan_review_current,
		"R5_senior_manager_approved": cip_senior_manager_approved,
		"R6_ir_coordination": incident_response_coordination_established,
	},
	"vendor_summary": {
		"total_vendors": count(input.vendors),
		"critical_vendors": count([v | v := input.vendors[_]; v.criticality_level in ["high", "medium"]]),
		"assessed_vendors": count([v | v := input.vendors[_]; input.vendor_risk_assessments[v.vendor_id].completed == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
