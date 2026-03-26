package nerc_cip.cip_003

import rego.v1

# CIP-003-8: Security Management Controls
# Requirement: Specify consistent and sustainable security management controls
# that establish responsibility and accountability for the protection of
# BES Cyber Systems.
#
# NERC Standards Reference: CIP-003-8

# =============================================================================
# R1: CIP Senior Manager Designation
# =============================================================================

# R1 - Designate one or more individuals as CIP Senior Manager(s)
# to authorize and oversee implementation of cybersecurity policies

cip_senior_manager_designated if {
	input.cybersecurity_organization.senior_manager.designated == true
	input.cybersecurity_organization.senior_manager.name
	input.cybersecurity_organization.senior_manager.title
	input.cybersecurity_organization.senior_manager.authority_documented == true
	input.cybersecurity_organization.senior_manager.responsibilities_defined == true
	input.cybersecurity_organization.senior_manager.accountability_documented == true
}

# Delegations must be documented if authority is delegated
delegation_documented if {
	not input.cybersecurity_organization.delegated_authority
} else if {
	input.cybersecurity_organization.delegated_authority.exists == true
	input.cybersecurity_organization.delegated_authority.documented == true
	input.cybersecurity_organization.delegated_authority.current == true
	input.cybersecurity_organization.delegated_authority.delegate_name
	input.cybersecurity_organization.delegated_authority.scope_defined == true
}

# =============================================================================
# R2: Cybersecurity Policies for High and Medium Impact Systems
# =============================================================================

# R2 - Review and obtain CIP Senior Manager approval for cybersecurity policies
# at least once every 15 calendar months

cybersecurity_policies_established if {
	input.cybersecurity_policies.documented == true
	input.cybersecurity_policies.approved == true
	input.cybersecurity_policies.cip_senior_manager_approved == true
}

# Policies must cover all required areas (R2.1 - R2.7 for High/Medium)
required_policy_areas_covered if {
	input.cybersecurity_policies.areas.personnel_and_training == true # R2.1
	input.cybersecurity_policies.areas.electronic_security_perimeters == true # R2.2
	input.cybersecurity_policies.areas.physical_security == true # R2.3
	input.cybersecurity_policies.areas.systems_security_management == true # R2.4
	input.cybersecurity_policies.areas.incident_response == true # R2.5
	input.cybersecurity_policies.areas.recovery_plans == true # R2.6
	input.cybersecurity_policies.areas.configuration_management == true # R2.7
}

# Policies must be reviewed within 15 calendar months
policy_review_current if {
	last_review_ns := time.parse_rfc3339_ns(input.cybersecurity_policies.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# =============================================================================
# R3: Low Impact BES Cyber Systems — CIP Security Plan
# =============================================================================

# R3 - Implement one or more documented cybersecurity plans for Low Impact BES Cyber Systems

low_impact_plan_implemented if {
	# Only required if low impact systems exist
	low_systems := [s | s := input.bes_cyber_systems[_]; s.impact_categorization == "low"]
	count(low_systems) == 0
} else if {
	input.low_impact_plan.documented == true
	input.low_impact_plan.approved == true
	input.low_impact_plan.physical_security_controls == true
	input.low_impact_plan.electronic_access_controls == true
	input.low_impact_plan.cyber_security_incident_response == true
	input.low_impact_plan.transient_cyber_asset_controls == true
}

low_impact_plan_reviewed if {
	low_systems := [s | s := input.bes_cyber_systems[_]; s.impact_categorization == "low"]
	count(low_systems) == 0
} else if {
	last_review_ns := time.parse_rfc3339_ns(input.low_impact_plan.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# =============================================================================
# R4: Transient Cyber Assets and Removable Media (TCAs)
# =============================================================================

# R4 - Policies and procedures for Transient Cyber Assets and Removable Media
# connected to or used with High and Medium Impact BES Cyber Systems

transient_cyber_asset_policy if {
	input.transient_cyber_assets.policy_documented == true
	input.transient_cyber_assets.asset_management.inventory_maintained == true
	input.transient_cyber_assets.asset_management.authorization_required == true
}

transient_asset_security_controls if {
	input.transient_cyber_assets.controls.malicious_code_prevention == true
	input.transient_cyber_assets.controls.security_patches.applied == true
	input.transient_cyber_assets.controls.security_patches.documented == true
}

removable_media_controls if {
	input.removable_media.policy_documented == true
	input.removable_media.authorization_required == true
	input.removable_media.scanning_before_use == true
	input.removable_media.encryption_when_applicable == true
}

# =============================================================================
# R5: Information Sharing Plan
# =============================================================================

# Information sharing plan with NERC and Regional Entities
information_sharing_plan_exists if {
	input.information_sharing_plan.documented == true
	input.information_sharing_plan.nerc_contact_included == true
	input.information_sharing_plan.regional_entity_contact_included == true
	input.information_sharing_plan.contacts_current == true
	last_review_ns := time.parse_rfc3339_ns(input.information_sharing_plan.last_review_date)
	review_age_days := (time.now_ns() - last_review_ns) / (24 * 60 * 60 * 1000000000)
	review_age_days <= 455
}

# =============================================================================
# VIOLATIONS
# =============================================================================

violations contains v if {
	not cip_senior_manager_designated
	v := {
		"standard": "CIP-003",
		"requirement": "R1",
		"severity": "critical",
		"description": "CIP Senior Manager not properly designated with documented authority",
		"remediation": "Designate CIP Senior Manager with documented authority and defined responsibilities",
	}
}

violations contains v if {
	not cybersecurity_policies_established
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "Cybersecurity policies not established or not approved by CIP Senior Manager",
		"remediation": "Document cybersecurity policies and obtain CIP Senior Manager approval",
	}
}

violations contains v if {
	not required_policy_areas_covered
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "high",
		"description": "Cybersecurity policies do not cover all required areas (R2.1-R2.7)",
		"remediation": "Ensure policies address all required areas: personnel, ESPs, physical security, systems, IR, recovery, and configuration",
	}
}

violations contains v if {
	not policy_review_current
	v := {
		"standard": "CIP-003",
		"requirement": "R2",
		"severity": "medium",
		"description": "Cybersecurity policies not reviewed within 15 calendar months",
		"remediation": "Review and obtain CIP Senior Manager re-approval within 15 calendar months",
	}
}

violations contains v if {
	not information_sharing_plan_exists
	v := {
		"standard": "CIP-003",
		"requirement": "R5",
		"severity": "medium",
		"description": "Information sharing plan missing or contacts not current",
		"remediation": "Maintain current information sharing plan with NERC and Regional Entity contacts",
	}
}

# =============================================================================
# OVERALL COMPLIANCE
# =============================================================================

default compliant := false

compliant if {
	cip_senior_manager_designated
	delegation_documented
	cybersecurity_policies_established
	required_policy_areas_covered
	policy_review_current
	low_impact_plan_implemented
	low_impact_plan_reviewed
	transient_cyber_asset_policy
	transient_asset_security_controls
	removable_media_controls
	information_sharing_plan_exists
}

report := {
	"standard": "CIP-003-8",
	"title": "Security Management Controls",
	"compliant": compliant,
	"requirements": {
		"R1_cip_senior_manager": cip_senior_manager_designated,
		"R1_delegation_documented": delegation_documented,
		"R2_policies_established": cybersecurity_policies_established,
		"R2_policy_areas_covered": required_policy_areas_covered,
		"R2_policy_review_current": policy_review_current,
		"R3_low_impact_plan": low_impact_plan_implemented,
		"R3_low_impact_plan_reviewed": low_impact_plan_reviewed,
		"R4_transient_asset_policy": transient_cyber_asset_policy,
		"R4_transient_asset_controls": transient_asset_security_controls,
		"R4_removable_media_controls": removable_media_controls,
		"R5_information_sharing_plan": information_sharing_plan_exists,
	},
	"violations": violations,
	"violation_count": count(violations),
}
