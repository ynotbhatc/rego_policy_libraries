package nerc_cip_main

import rego.v1

# NERC CIP (Critical Infrastructure Protection) Standards — Self-Contained Evaluator
# Covers CIP-002 through CIP-015 (all active standards)
#
# Regulatory Authority: North American Electric Reliability Corporation (NERC)
# Enforced by: FERC (US), applicable provincial regulators (Canada)
# Penalties: Up to $1,000,000 per violation per day
#
# This policy evaluates all CIP standards inline from input data.
# CIP-015 is also evaluated by nerc_cip_cip015 for detailed INSM reporting.

import data.nerc_cip_cip015

# =============================================================================
# CIP-002: BES Cyber System Categorization
# =============================================================================

all_bes_cyber_systems_categorized if {
	count([s |
		s := input.bes_cyber_systems[_]
		not s.impact_level in {"high", "medium", "low"}
	]) == 0
	count(input.bes_cyber_systems) > 0
}

default cip_002_compliant := false

cip_002_compliant if {
	all_bes_cyber_systems_categorized
	input.categorization_documentation.criteria_defined == true
	input.categorization_documentation.methodology_documented == true
}

# =============================================================================
# CIP-003: Security Management Controls
# =============================================================================

organization_violations contains msg if {
	not input.cybersecurity_organization.senior_manager.designated == true
	msg := "CIP-003: No designated CIP Senior Manager"
}

organization_violations contains msg if {
	not input.cybersecurity_organization.policies.documented == true
	msg := "CIP-003: Cybersecurity policies not documented"
}

organization_violations contains msg if {
	not input.cybersecurity_organization.policies.approved == true
	msg := "CIP-003: Cybersecurity policies not approved"
}

default cip_003_compliant := false

cip_003_compliant if {
	count(organization_violations) == 0
	input.cybersecurity_organization.senior_manager.designated == true
	input.cybersecurity_organization.policies.documented == true
}

# =============================================================================
# CIP-004: Personnel and Training
# =============================================================================

personnel_violations contains msg if {
	some person in input.personnel
	not person.training_completed == true
	msg := sprintf("CIP-004: Person %v has not completed CIP training", [person.person_id])
}

personnel_violations contains msg if {
	some person in input.personnel
	not person.risk_assessment_completed == true
	msg := sprintf("CIP-004: Person %v has no completed risk assessment", [person.person_id])
}

default cip_004_compliant := false

cip_004_compliant if {
	count(personnel_violations) == 0
	count(input.personnel) > 0
}

# =============================================================================
# CIP-005: Electronic Security Perimeters
# =============================================================================

security_perimeter_violations contains msg if {
	some eap in input.electronic_access_points
	not eap.deny_by_default == true
	msg := sprintf("CIP-005: EAP %v does not enforce deny-by-default", [eap.eap_id])
}

security_perimeter_violations contains msg if {
	some eap in input.electronic_access_points
	not eap.authenticated == true
	msg := sprintf("CIP-005: EAP %v does not require authentication", [eap.eap_id])
}

default cip_005_compliant := false

cip_005_compliant if {
	count(security_perimeter_violations) == 0
	count(input.electronic_access_points) > 0
}

# =============================================================================
# CIP-006: Physical Security
# =============================================================================

physical_security_violations contains msg if {
	not input.visitor_control_program.documented == true
	msg := "CIP-006: Visitor control program is not documented"
}

physical_security_violations contains msg if {
	not input.visitor_control_program.escort_procedures == true
	msg := "CIP-006: Visitor escort procedures not defined"
}

default cip_006_compliant := false

cip_006_compliant if {
	count(physical_security_violations) == 0
	count(object.keys(input.physical_security_perimeters)) > 0
	input.visitor_control_program.documented == true
}

# =============================================================================
# CIP-007: Systems Security Management
# =============================================================================

system_security_violations contains msg if {
	some sys_id, pm in input.patch_management
	not pm.patches_applied_or_mitigated == true
	msg := sprintf("CIP-007: %v has unapplied/unmitigated patches", [sys_id])
}

system_security_violations contains msg if {
	some sys_id, mcp in input.malicious_code_protection
	not mcp.deployed == true
	msg := sprintf("CIP-007: %v missing malicious code protection", [sys_id])
}

system_security_violations contains msg if {
	some sys_id, sac in input.system_access_controls
	not sac.authentication_required == true
	msg := sprintf("CIP-007: %v does not require authentication", [sys_id])
}

system_security_management_compliant if {
	count(system_security_violations) == 0
	count(object.keys(input.patch_management)) > 0
	count(object.keys(input.malicious_code_protection)) > 0
}

default cip_007_compliant := false

cip_007_compliant if {
	system_security_management_compliant
}

# =============================================================================
# CIP-008: Incident Reporting and Response Planning
# =============================================================================

incident_response_violations contains msg if {
	not input.incident_response_plan.documented == true
	msg := "CIP-008: Incident response plan is not documented"
}

incident_response_violations contains msg if {
	not input.incident_response_plan.approved == true
	msg := "CIP-008: Incident response plan is not approved"
}

incident_response_violations contains msg if {
	not input.incident_reporting.procedures_documented == true
	msg := "CIP-008: Incident reporting procedures not documented"
}

default cip_008_compliant := false

cip_008_compliant if {
	count(incident_response_violations) == 0
	input.incident_response_plan.documented == true
}

# =============================================================================
# CIP-009: Recovery Plans for BES Cyber Systems
# =============================================================================

recovery_plan_violations contains msg if {
	some sys_id, rp in input.recovery_plans
	not rp.documented == true
	msg := sprintf("CIP-009: %v recovery plan is not documented", [sys_id])
}

recovery_plan_violations contains msg if {
	some sys_id, rp in input.recovery_plans
	not rp.conditions_defined == true
	msg := sprintf("CIP-009: %v recovery plan missing conditions", [sys_id])
}

recovery_plan_violations contains msg if {
	some sys_id, bp in input.backup_procedures
	not bp.documented == true
	msg := sprintf("CIP-009: %v backup procedures not documented", [sys_id])
}

recovery_plans_compliant if {
	count(recovery_plan_violations) == 0
	count(object.keys(input.recovery_plans)) > 0
	count(object.keys(input.backup_procedures)) > 0
}

default cip_009_compliant := false

cip_009_compliant if {
	recovery_plans_compliant
}

# =============================================================================
# CIP-010: Configuration Change Management and Vulnerability Assessments
# =============================================================================

config_management_violations contains msg if {
	some sys_id, bc in input.baseline_configurations
	not bc.documented == true
	msg := sprintf("CIP-010: %v baseline configuration not documented", [sys_id])
}

config_management_violations contains msg if {
	some sys_id, va in input.vulnerability_assessments
	not va.performed == true
	msg := sprintf("CIP-010: %v vulnerability assessment not performed", [sys_id])
}

configuration_change_management_compliant if {
	count(config_management_violations) == 0
	count(object.keys(input.baseline_configurations)) > 0
	count(object.keys(input.vulnerability_assessments)) > 0
}

default cip_010_compliant := false

cip_010_compliant if {
	configuration_change_management_compliant
}

# =============================================================================
# CIP-011: Information Protection
# =============================================================================

information_protection_violations contains msg if {
	not input.bes_cyber_system_information.inventory_maintained == true
	msg := "CIP-011: BES Cyber System information inventory not maintained"
}

information_protection_violations contains msg if {
	not input.information_protection.procedures_documented == true
	msg := "CIP-011: Information protection procedures not documented"
}

information_protection_violations contains msg if {
	not input.information_protection.access_controls_enforced == true
	msg := "CIP-011: Information access controls not enforced"
}

information_protection_violations contains msg if {
	not input.information_disposal.procedures_documented == true
	msg := "CIP-011: Information disposal procedures not documented"
}

default cip_011_compliant := false

cip_011_compliant if {
	count(information_protection_violations) == 0
	input.information_protection.procedures_documented == true
}

# =============================================================================
# CIP-012: Communications Between Control Centers
# =============================================================================

comms_protection_violations contains msg if {
	not input.control_center_communications.inventory_maintained == true
	msg := "CIP-012: Control center communications inventory not maintained"
}

comms_protection_violations contains msg if {
	some link in input.control_center_communications.links
	not link.encrypted == true
	msg := sprintf("CIP-012: Link %v is not encrypted", [link.link_id])
}

comms_protection_violations contains msg if {
	some link in input.control_center_communications.links
	not link.authenticated == true
	msg := sprintf("CIP-012: Link %v is not authenticated", [link.link_id])
}

communication_protection_implemented if {
	count(comms_protection_violations) == 0
	input.control_center_communications.inventory_maintained == true
	count(input.control_center_communications.links) > 0
}

default cip_012_compliant := false

cip_012_compliant if {
	communication_protection_implemented
}

# =============================================================================
# CIP-013: Supply Chain Risk Management
# =============================================================================

supply_chain_violations contains msg if {
	not input.supply_chain_management.plan_documented == true
	msg := "CIP-013: Supply chain risk management plan not documented"
}

supply_chain_violations contains msg if {
	not input.supply_chain_management.plan_approved == true
	msg := "CIP-013: Supply chain risk management plan not approved"
}

supply_chain_violations contains msg if {
	not input.supply_chain_management.software_integrity_verification == true
	msg := "CIP-013: Software integrity verification not implemented"
}

default cip_013_compliant := false

cip_013_compliant if {
	count(supply_chain_violations) == 0
	input.supply_chain_management.plan_documented == true
}

# =============================================================================
# CIP-014: Physical Security of Transmission Stations and Substations
# =============================================================================

# CIP-014 requires transmission security assessments by an unaffiliated third party
# If no assessment data is provided, default to non-compliant

default cip_014_compliant := false

cip_014_compliant if {
	input.transmission_security_assessments.completed == true
	input.transmission_security_assessments.third_party_verified == true
}

# =============================================================================
# CIP-015: Internal Network Security Monitoring
# =============================================================================

default cip_015_compliant := false

cip_015_compliant if {
	nerc_cip_cip015.cip_015_compliant
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default nerc_cip_compliant := false

nerc_cip_compliant if {
	cip_002_compliant
	cip_003_compliant
	cip_004_compliant
	cip_005_compliant
	cip_006_compliant
	cip_007_compliant
	cip_008_compliant
	cip_009_compliant
	cip_010_compliant
	cip_011_compliant
	cip_012_compliant
	cip_013_compliant
	cip_014_compliant
	cip_015_compliant
}

# =============================================================================
# COMPLIANCE SCORING
# =============================================================================

standards_passing := count([1 |
	some s in [
		cip_002_compliant,
		cip_003_compliant,
		cip_004_compliant,
		cip_005_compliant,
		cip_006_compliant,
		cip_007_compliant,
		cip_008_compliant,
		cip_009_compliant,
		cip_010_compliant,
		cip_011_compliant,
		cip_012_compliant,
		cip_013_compliant,
		cip_014_compliant,
		cip_015_compliant,
	]
	s == true
])

nerc_cip_compliance_score := (standards_passing * 100) / 14

# =============================================================================
# VIOLATION AGGREGATION
# =============================================================================

all_violations := array.concat(
	array.concat(
		array.concat(
			array.concat(
				array.concat(
					array.concat(
						[v | v := organization_violations[_]],
						[v | v := personnel_violations[_]]
					),
					array.concat(
						[v | v := security_perimeter_violations[_]],
						[v | v := physical_security_violations[_]]
					)
				),
				array.concat(
					[v | v := system_security_violations[_]],
					[v | v := incident_response_violations[_]]
				)
			),
			array.concat(
				[v | v := recovery_plan_violations[_]],
				[v | v := config_management_violations[_]]
			)
		),
		array.concat(
			[v | v := information_protection_violations[_]],
			array.concat(
				[v | v := comms_protection_violations[_]],
				[v | v := supply_chain_violations[_]]
			)
		)
	),
	[]
)

nerc_cip_violations := all_violations

# =============================================================================
# COMPLIANCE LEVEL
# =============================================================================

nerc_cip_compliance_level := "COMPLIANT" if {
	nerc_cip_compliance_score >= 95
	cip_002_compliant
	cip_003_compliant
}

nerc_cip_compliance_level := "SUBSTANTIALLY_COMPLIANT" if {
	nerc_cip_compliance_score >= 85
	nerc_cip_compliance_score < 95
}

nerc_cip_compliance_level := "PARTIALLY_COMPLIANT" if {
	nerc_cip_compliance_score >= 70
	nerc_cip_compliance_score < 85
}

nerc_cip_compliance_level := "NON_COMPLIANT" if {
	nerc_cip_compliance_score < 70
}

# =============================================================================
# FULL COMPLIANCE REPORT
# =============================================================================

report := {
	"standard": "NERC CIP — Critical Infrastructure Protection",
	"standards_covered": "CIP-002 through CIP-015",
	"overall_compliant": nerc_cip_compliant,
	"compliance_score": nerc_cip_compliance_score,
	"compliance_level": nerc_cip_compliance_level,
	"standards_passing": standards_passing,
	"standards_total": 14,
	"standards": {
		"CIP-002": {"title": "BES Cyber System Categorization", "compliant": cip_002_compliant},
		"CIP-003": {"title": "Security Management Controls", "compliant": cip_003_compliant},
		"CIP-004": {"title": "Personnel and Training", "compliant": cip_004_compliant},
		"CIP-005": {"title": "Electronic Security Perimeters", "compliant": cip_005_compliant},
		"CIP-006": {"title": "Physical Security of BES Cyber Systems", "compliant": cip_006_compliant},
		"CIP-007": {"title": "Systems Security Management", "compliant": cip_007_compliant},
		"CIP-008": {"title": "Incident Reporting and Response Planning", "compliant": cip_008_compliant},
		"CIP-009": {"title": "Recovery Plans for BES Cyber Systems", "compliant": cip_009_compliant},
		"CIP-010": {"title": "Configuration Change Management", "compliant": cip_010_compliant},
		"CIP-011": {"title": "Information Protection", "compliant": cip_011_compliant},
		"CIP-012": {"title": "Communications Between Control Centers", "compliant": cip_012_compliant},
		"CIP-013": {"title": "Supply Chain Risk Management", "compliant": cip_013_compliant},
		"CIP-014": {"title": "Physical Security of Transmission Stations", "compliant": cip_014_compliant},
		"CIP-015": {"title": "Internal Network Security Monitoring", "compliant": cip_015_compliant},
	},
	"violation_summary": {
		"total": count(all_violations),
	},
	"metadata": {
		"policy_name": "NERC CIP Critical Infrastructure Protection Standards",
		"version": "3.0",
		"regulatory_authority": "North American Electric Reliability Corporation (NERC)",
		"enforced_by": "FERC (US) / Provincial Regulators (Canada)",
		"penalties": "Up to $1,000,000 per violation per day",
	},
}
