# METADATA
# title: "CIP-013-2: Supply Chain Risk Management"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 29
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package nerc_cip.cip_013

import rego.v1

# fail-closed: these booleans are referenced by the report and must be false, not undefined, without facts
default cip_senior_manager_approved := false

default incident_coordination_process := false

default incident_response_coordination_established := false

default software_authenticity_verification_process := false

default supply_chain_cyber_security_plan_implemented := false

default supply_chain_monitoring_implemented := false

default supply_chain_plan_review_current := false

default vendor_contracts_include_security_requirements := false

default vendor_incident_notification_process := false

default vendor_remote_access_controlled := false

default vendor_risk_assessments_performed := false

default vendor_vulnerability_notification_process := false

# CIP-013-2: Supply Chain Risk Management
# Requirement: Mitigate cyber security risks in the supply chain for industrial
# control system hardware, software, and computing and networking services
# associated with BES Cyber Systems.
#
# NERC Standards Reference: CIP-013-2
# (mandatory and enforceable in the United States; CIP-013-3 is approved with an
# effective date of 2028-07-01).
# Source: https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-013-2.pdf
#
# CIP-013-2 has three requirements:
#   R1  supply chain cyber security risk management plan: 1.1 identify and assess
#       risks in planning and procurement; 1.2.1 vendor incident notification,
#       1.2.2 coordination of responses, 1.2.3 notification when vendor access
#       should end (not implemented), 1.2.4 disclosure of known vulnerabilities,
#       1.2.5 software integrity and authenticity, 1.2.6 controls for
#       vendor-initiated remote access
#   R2  implement the plan
#   R3  review and CIP Senior Manager approval at least once every 15 calendar months
# There is no R4, R5 or R6.

# =============================================================================
# R1: Supply Chain Cyber Security Risk Management Plan
# =============================================================================

# R1 - One or more documented plans that include a process to identify and
# assess cyber security risks in the supply chain

supply_chain_cyber_security_plan_implemented if {
	input.supply_chain_plan.documented == true
	input.supply_chain_plan.approved == true
	input.supply_chain_plan.current == true
	input.supply_chain_plan.cip_senior_manager_approved == true
	input.supply_chain_plan.vendor_requirements_defined == true
}

# R1.2.4 - Disclosure by vendors of known vulnerabilities
vendor_vulnerability_notification_process if {
	input.supply_chain_plan.processes.vendor_vulnerability_notification == true
	input.supply_chain_plan.processes.notification_response_procedures == true
}

# R1.2.1 - Notification from vendors of vendor-identified incidents related to
# delivered products and services
vendor_incident_notification_process if {
	input.supply_chain_plan.processes.vendor_incident_notification == true
	input.supply_chain_plan.processes.incident_escalation_procedures == true
}

# R1.2.5 - Verification of software integrity and authenticity of all
# software and patches provided by vendors
software_authenticity_verification_process if {
	input.supply_chain_plan.processes.software_integrity_verification == true
	input.supply_chain_plan.processes.hash_or_signature_verification == true
	input.supply_chain_plan.processes.vendor_provided_verification_method == true
}

# R1.2.2 - Coordination of responses to vendor-identified incidents
incident_coordination_process if {
	input.supply_chain_plan.processes.vendor_incident_coordination == true
	input.supply_chain_plan.processes.information_sharing_agreements == true
}

# R1.2.6 - Coordination of controls for vendor-initiated remote access
vendor_remote_access_controlled if {
	input.supply_chain_plan.processes.vendor_remote_access_policy == true
	input.supply_chain_plan.processes.vendor_remote_access_monitoring == true
	input.supply_chain_plan.processes.vendor_remote_access_logging == true
	input.supply_chain_plan.processes.vendor_remote_access_control == true
}

# =============================================================================
# R1 Part 1.1: Vendor Risk Assessments
# =============================================================================

vendor_risk_assessments_performed if {
	violations := [vendor |
		vendor := input.vendors[_]
		vendor.criticality_level in ["high", "medium"]
		not vendor_risk_assessment_current(vendor)
	]
	count(violations) == 0
}

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

vendor_risk_assessment_current(vendor) if {
	assessment := input.vendor_risk_assessments[vendor.vendor_id]
	assessment.completed == true
	age_days(assessment.completion_date) <= 1095 # 3 years
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

# Every high/medium criticality vendor's assessment covers all four supply chain
# factors (decisions 2026-10-19: wired into compliant and violations).
default vendor_assessments_comprehensive := false

vendor_assessments_comprehensive if {
	is_array(input.vendors)
	violations := [vendor |
		vendor := input.vendors[_]
		vendor.criticality_level in ["high", "medium"]
		not vendor_assessment_comprehensive(vendor)
	]
	count(violations) == 0
}

# =============================================================================
# R2: Plan Implementation and Vendor Engagement
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
# R2 (supporting): Supply Chain Monitoring — implementation evidence, not a
# numbered part of CIP-013-2
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
# R3: Plan Review and Approval
# =============================================================================

# Review the supply chain cyber security risk management plan within
# 15 calendar months of the last review and after triggered events
supply_chain_plan_review_current if {
	age_days(input.supply_chain_plan.last_review_date) <= 455
}

# CIP Senior Manager must approve the plan
cip_senior_manager_approved if {
	input.supply_chain_plan.cip_senior_manager_approved == true
	age_days(input.supply_chain_plan.approval_date) <= 455
}

# Dated evidence the recency checks read.
dated_evidence contains {
	"requirement": "R3",
	"path": "supply_chain_plan.last_review_date",
	"value": object.get(input, ["supply_chain_plan", "last_review_date"], null),
}

dated_evidence contains {
	"requirement": "R3",
	"path": "supply_chain_plan.approval_date",
	"value": object.get(input, ["supply_chain_plan", "approval_date"], null),
}

dated_evidence contains {
	"requirement": "R1.1",
	"path": sprintf("vendor_risk_assessments[%v].completion_date", [vendor.vendor_id]),
	"value": object.get(input, ["vendor_risk_assessments", vendor.vendor_id, "completion_date"], null),
} if {
	some vendor in input.vendors
	vendor.criticality_level in ["high", "medium"]
	input.vendor_risk_assessments[vendor.vendor_id].completed == true
}

# =============================================================================
# R1 Part 1.2.2: Incident Response Coordination with Vendors
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
		"requirement": "R1.2.4",
		"severity": "high",
		"description": "Process for receiving vendor vulnerability notifications not documented",
		"remediation": "Establish process for vendors to notify of security vulnerabilities in supplied products",
	}
}

violations contains v if {
	not software_authenticity_verification_process
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.5",
		"severity": "critical",
		"description": "Software integrity and authenticity verification process not established",
		"remediation": "Implement software hash/signature verification for all vendor-provided software and patches",
	}
}

violations contains v if {
	not vendor_remote_access_controlled
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.6",
		"severity": "critical",
		"description": "Vendor remote access not adequately monitored, logged, and controlled",
		"remediation": "Implement vendor remote access controls with monitoring, logging, and active session management",
	}
}

violations contains v if {
	not vendor_risk_assessments_performed
	v := {
		"standard": "CIP-013",
		"requirement": "R1.1",
		"severity": "high",
		"description": "Vendor risk assessments not current for one or more high/medium criticality vendors",
		"remediation": "Conduct comprehensive vendor risk assessments within 3 years for all critical vendors",
	}
}

violations contains v if {
	not vendor_contracts_include_security_requirements
	v := {
		"standard": "CIP-013",
		"requirement": "R2",
		"severity": "high",
		"description": "Vendor contracts missing required security requirements for critical vendors",
		"remediation": "Include security requirements, vulnerability/incident notification clauses, and audit rights in vendor contracts",
	}
}

violations contains v if {
	not supply_chain_plan_review_current
	v := {
		"standard": "CIP-013",
		"requirement": "R3",
		"severity": "medium",
		"description": "Supply chain cyber security risk management plan not reviewed within 15 calendar months",
		"remediation": "Review and update supply chain plan within 15 calendar months; obtain CIP Senior Manager re-approval",
	}
}

violations contains v if {
	not vendor_assessments_comprehensive
	v := {
		"standard": "CIP-013",
		"requirement": "R1.1",
		"severity": "medium",
		"description": "Vendor risk assessment does not cover vulnerability disclosure, incident response, software development practices and third-party dependencies for every high/medium vendor",
		"remediation": "Extend each vendor risk assessment to cover all four supply chain factors",
	}
}

# decisions 2026-10-19: every rule that gates compliant has a matching violation.
violations contains v if {
	not vendor_incident_notification_process
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.1",
		"severity": "medium",
		"description": "CIP-013 R1.2.1: vendor incident notification process requirement not met",
		"remediation": "Satisfy and evidence the vendor incident notification process requirement (CIP-013 R1.2.1)",
	}
}

violations contains v if {
	not incident_coordination_process
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.2",
		"severity": "medium",
		"description": "CIP-013 R1.2.2: incident coordination process requirement not met",
		"remediation": "Satisfy and evidence the incident coordination process requirement (CIP-013 R1.2.2)",
	}
}

violations contains v if {
	not supply_chain_monitoring_implemented
	v := {
		"standard": "CIP-013",
		"requirement": "R2",
		"severity": "medium",
		"description": "CIP-013 R2: supply chain monitoring implemented requirement not met",
		"remediation": "Satisfy and evidence the supply chain monitoring implemented requirement (CIP-013 R2)",
	}
}

violations contains v if {
	not vendor_notification_monitoring
	v := {
		"standard": "CIP-013",
		"requirement": "R2",
		"severity": "medium",
		"description": "CIP-013 R2: vendor notification monitoring requirement not met",
		"remediation": "Satisfy and evidence the vendor notification monitoring requirement (CIP-013 R2)",
	}
}

violations contains v if {
	not cip_senior_manager_approved
	v := {
		"standard": "CIP-013",
		"requirement": "R3",
		"severity": "medium",
		"description": "CIP-013 R3: cip senior manager approved requirement not met",
		"remediation": "Satisfy and evidence the cip senior manager approved requirement (CIP-013 R3)",
	}
}

violations contains v if {
	not incident_response_coordination_established
	v := {
		"standard": "CIP-013",
		"requirement": "R1.2.2",
		"severity": "medium",
		"description": "CIP-013 R1.2.2: incident response coordination established requirement not met",
		"remediation": "Satisfy and evidence the incident response coordination established requirement (CIP-013 R1.2.2)",
	}
}

# A dated record that is absent, not a date, or later than the evaluation time
# gets its own finding, so missing evidence is not reported as "overdue" and a
# future date is never read as a completed activity.
violations contains v if {
	some e in dated_evidence
	date_problem(e.value) == "missing"
	v := {
		"standard": "CIP-013",
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
		"standard": "CIP-013",
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
	vendor_assessments_comprehensive
}

report := {
	"standard": "CIP-013-2",
	"title": "Supply Chain Risk Management",
	"compliant": compliant,
	"requirements": {
		"R1_plan_implemented": supply_chain_cyber_security_plan_implemented,
		"R1_1_vendor_risk_assessments": vendor_risk_assessments_performed,
		"R1_1_vendor_assessments_comprehensive": vendor_assessments_comprehensive,
		"R1_2_1_incident_notification": vendor_incident_notification_process,
		"R1_2_2_incident_coordination": incident_coordination_process,
		"R1_2_2_ir_coordination": incident_response_coordination_established,
		"R1_2_4_vuln_notification": vendor_vulnerability_notification_process,
		"R1_2_5_software_authenticity": software_authenticity_verification_process,
		"R1_2_6_vendor_remote_access": vendor_remote_access_controlled,
		"R2_vendor_contracts": vendor_contracts_include_security_requirements,
		"R2_supporting_supply_chain_monitoring": supply_chain_monitoring_implemented,
		"R3_plan_review_current": supply_chain_plan_review_current,
		"R3_senior_manager_approved": cip_senior_manager_approved,
	},
	"vendor_summary": {
		"total_vendors": count(object.get(input, ["vendors"], [])),
		"critical_vendors": count([v | v := input.vendors[_]; v.criticality_level in ["high", "medium"]]),
		"assessed_vendors": count([v | v := input.vendors[_]; input.vendor_risk_assessments[v.vendor_id].completed == true]),
	},
	"violations": violations,
	"violation_count": count(violations),
}
