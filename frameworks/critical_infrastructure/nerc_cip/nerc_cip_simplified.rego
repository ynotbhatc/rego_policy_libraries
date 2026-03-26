package nerc.cip.simplified

import rego.v1

# NERC CIP (Critical Infrastructure Protection) Standards Implementation
# Simplified version for demonstration and testing
# Covers key CIP-002 through CIP-013 standards

# Main NERC CIP compliance evaluation
nerc_cip_compliant if {
	bes_cyber_system_categorization_compliant # CIP-002
	cyber_security_organization_compliant # CIP-003
	personnel_risk_assessment_compliant # CIP-004
	electronic_security_perimeter_compliant # CIP-005
	physical_security_compliant # CIP-006
}

# CIP-002: BES Cyber System Categorization
bes_cyber_system_categorization_compliant if {
	all_bes_cyber_systems_identified
	all_bes_cyber_systems_categorized
	categorization_criteria_documented
}

all_bes_cyber_systems_identified if {
	count(input.bes_cyber_systems) > 0
	violations := [system |
		system := input.bes_cyber_systems[_]
		not system.system_id
	]
	count(violations) == 0
	violations2 := [system |
		system := input.bes_cyber_systems[_]
		not system.system_name
	]
	count(violations2) == 0
	violations3 := [system |
		system := input.bes_cyber_systems[_]
		not system.impact_categorization
	]
	count(violations3) == 0
}

all_bes_cyber_systems_categorized if {
	violations := [system |
		system := input.bes_cyber_systems[_]
		not system.impact_categorization in ["high", "medium", "low"]
	]
	count(violations) == 0
}

categorization_criteria_documented if {
	input.categorization_documentation.criteria_defined == true
	input.categorization_documentation.methodology_documented == true
	input.categorization_documentation.rationale_provided == true
}

# CIP-003: Cyber Security Organization
cyber_security_organization_compliant if {
	cybersecurity_leadership_designated
	cybersecurity_policies_established
}

cybersecurity_leadership_designated if {
	input.cybersecurity_organization.senior_manager.designated == true
	input.cybersecurity_organization.senior_manager.authority_documented == true
	input.cybersecurity_organization.senior_manager.responsibilities_defined == true
}

cybersecurity_policies_established if {
	input.cybersecurity_organization.policies.documented == true
	input.cybersecurity_organization.policies.approved == true
}

# CIP-004: Personnel & Training
personnel_risk_assessment_compliant if {
	personnel_with_access_have_assessments
	cybersecurity_training_completed
}

personnel_with_access_have_assessments if {
	violations := [person |
		person := input.personnel[_]
		person.access_level in ["authorized_unescorted_physical_access", "authorized_electronic_access", "authorized_cyber_asset_access"]
		not person.risk_assessment.completed == true
	]
	count(violations) == 0
}

cybersecurity_training_completed if {
	violations := [person |
		person := input.personnel[_]
		person.access_level in ["authorized_electronic_access", "authorized_cyber_asset_access"]
		not person.cybersecurity_training.completed == true
	]
	count(violations) == 0
}

# CIP-005: Electronic Security Perimeters
electronic_security_perimeter_compliant if {
	electronic_security_perimeters_documented
	electronic_access_points_controlled
}

electronic_security_perimeters_documented if {
	high_and_medium_systems := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
	]

	violations := [system |
		system := high_and_medium_systems[_]
		esp := input.electronic_security_perimeters[system.system_id]
		not esp.documented == true
	]
	count(violations) == 0
}

electronic_access_points_controlled if {
	violations := [eap |
		eap := input.electronic_access_points[_]
		not eap.access_control.enabled == true
	]
	count(violations) == 0
	violations2 := [eap |
		eap := input.electronic_access_points[_]
		not eap.monitoring.enabled == true
	]
	count(violations2) == 0
}

# CIP-006: Physical Security
physical_security_compliant if {
	physical_security_perimeters_defined
	physical_access_controls_implemented
}

physical_security_perimeters_defined if {
	high_and_medium_systems := [system |
		system := input.bes_cyber_systems[_]
		system.impact_categorization in ["high", "medium"]
	]

	violations := [system |
		system := high_and_medium_systems[_]
		psp := input.physical_security_perimeters[system.system_id]
		not psp.boundary_defined == true
	]
	count(violations) == 0
}

physical_access_controls_implemented if {
	violations := [control |
		control := input.physical_access_controls[_]
		not control.authentication_required == true
	]
	count(violations) == 0
	violations2 := [control |
		control := input.physical_access_controls[_]
		not control.monitoring_enabled == true
	]
	count(violations2) == 0
}

# NERC CIP Compliance Scoring
nerc_cip_compliance_score := score if {
	total_checks := 5
	passed_checks := count([check |
		checks := [
			bes_cyber_system_categorization_compliant,
			cyber_security_organization_compliant,
			personnel_risk_assessment_compliant,
			electronic_security_perimeter_compliant,
			physical_security_compliant,
		]
		check := checks[_]
		check == true
	])
	score := (passed_checks * 100) / total_checks
}

# NERC CIP Violations
nerc_cip_violations := violations if {
	all_violations := []

	categorization_violations := [violation |
		not bes_cyber_system_categorization_compliant
		violation := {
			"standard": "CIP-002",
			"requirement": "BES Cyber System Categorization",
			"severity": "high",
			"description": "BES Cyber Systems not properly categorized",
			"remediation": "Complete categorization of all BES Cyber Systems",
		}
	]

	organization_violations := [violation |
		not cyber_security_organization_compliant
		violation := {
			"standard": "CIP-003",
			"requirement": "Cyber Security Organization",
			"severity": "high",
			"description": "Cybersecurity organization not properly established",
			"remediation": "Establish cybersecurity leadership and policies",
		}
	]

	personnel_violations := [violation |
		not personnel_risk_assessment_compliant
		violation := {
			"standard": "CIP-004",
			"requirement": "Personnel Risk Assessment",
			"severity": "high",
			"description": "Personnel risk assessments not current",
			"remediation": "Complete risk assessments and training for all personnel",
		}
	]

	esp_violations := [violation |
		not electronic_security_perimeter_compliant
		violation := {
			"standard": "CIP-005",
			"requirement": "Electronic Security Perimeters",
			"severity": "critical",
			"description": "Electronic Security Perimeters not properly implemented",
			"remediation": "Document and implement Electronic Security Perimeters",
		}
	]

	physical_violations := [violation |
		not physical_security_compliant
		violation := {
			"standard": "CIP-006",
			"requirement": "Physical Security",
			"severity": "high",
			"description": "Physical security controls not properly implemented",
			"remediation": "Implement physical security perimeters and controls",
		}
	]

	violations := array.concat(categorization_violations, array.concat(organization_violations, array.concat(personnel_violations, array.concat(esp_violations, physical_violations))))
}

# Compliance Level Determination
nerc_cip_compliance_level := "COMPLIANT" if {
	nerc_cip_compliance_score >= 95
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

# Simple Assessment Test
nerc_cip_simple_test := {
	"score": nerc_cip_compliance_score,
	"level": nerc_cip_compliance_level,
}

# Detailed Assessment Report
nerc_cip_assessment := {
		"compliance_score": nerc_cip_compliance_score,
		"compliance_level": nerc_cip_compliance_level,
}

# Policy Metadata
nerc_cip_metadata := {
	"policy_name": "NERC CIP Critical Infrastructure Protection Standards",
	"version": "1.0",
	"effective_date": "2024-01-01",
	"last_updated": "2025-01-06",
	"policy_owner": "Chief Information Security Officer",
	"regulatory_authority": "North American Electric Reliability Corporation (NERC)",
	"applicable_standards": ["CIP-002", "CIP-003", "CIP-004", "CIP-005", "CIP-006"],
	"enforcement_level": "mandatory",
	"penalties": "Financial penalties up to $1M per day per violation",
	"scope": "Bulk Electric System (BES) cyber assets and systems",
}