package nist.rmf.categorize

import rego.v1

# NIST Risk Management Framework (RMF) - CATEGORIZE Step
# System Categorization based on FIPS 199 and SP 800-60

# FIPS 199 Security Categories: Confidentiality, Integrity, Availability
# Impact Levels: Low, Moderate, High

# Confidentiality Impact Assessment
confidentiality_impact_low if {
    input.system_categorization.confidentiality.impact_level == "low"
    input.system_categorization.confidentiality.rationale != ""
    input.system_categorization.confidentiality.loss_scenario_documented == true
}

confidentiality_impact_moderate if {
    input.system_categorization.confidentiality.impact_level == "moderate"
    input.system_categorization.confidentiality.rationale != ""
    input.system_categorization.confidentiality.loss_scenario_documented == true
}

confidentiality_impact_high if {
    input.system_categorization.confidentiality.impact_level == "high"
    input.system_categorization.confidentiality.rationale != ""
    input.system_categorization.confidentiality.loss_scenario_documented == true
}

confidentiality_properly_categorized if {
    confidentiality_impact_low
}

confidentiality_properly_categorized if {
    confidentiality_impact_moderate
}

confidentiality_properly_categorized if {
    confidentiality_impact_high
}

# Integrity Impact Assessment
integrity_impact_low if {
    input.system_categorization.integrity.impact_level == "low"
    input.system_categorization.integrity.rationale != ""
    input.system_categorization.integrity.loss_scenario_documented == true
}

integrity_impact_moderate if {
    input.system_categorization.integrity.impact_level == "moderate"
    input.system_categorization.integrity.rationale != ""
    input.system_categorization.integrity.loss_scenario_documented == true
}

integrity_impact_high if {
    input.system_categorization.integrity.impact_level == "high"
    input.system_categorization.integrity.rationale != ""
    input.system_categorization.integrity.loss_scenario_documented == true
}

integrity_properly_categorized if {
    integrity_impact_low
}

integrity_properly_categorized if {
    integrity_impact_moderate
}

integrity_properly_categorized if {
    integrity_impact_high
}

# Availability Impact Assessment
availability_impact_low if {
    input.system_categorization.availability.impact_level == "low"
    input.system_categorization.availability.rationale != ""
    input.system_categorization.availability.loss_scenario_documented == true
}

availability_impact_moderate if {
    input.system_categorization.availability.impact_level == "moderate"
    input.system_categorization.availability.rationale != ""
    input.system_categorization.availability.loss_scenario_documented == true
}

availability_impact_high if {
    input.system_categorization.availability.impact_level == "high"
    input.system_categorization.availability.rationale != ""
    input.system_categorization.availability.loss_scenario_documented == true
}

availability_properly_categorized if {
    availability_impact_low
}

availability_properly_categorized if {
    availability_impact_moderate
}

availability_properly_categorized if {
    availability_impact_high
}

# Overall System Security Categorization
overall_system_categorization_valid if {
    input.system_categorization.overall_impact_level in ["low", "moderate", "high"]
    input.system_categorization.high_water_mark_applied == true
    input.system_categorization.rationale_documented == true
}

# High-water mark rule: System categorization = highest impact level
high_water_mark_properly_applied if {
    input.system_categorization.confidentiality.impact_level == "high"
    input.system_categorization.overall_impact_level == "high"
}

high_water_mark_properly_applied if {
    input.system_categorization.integrity.impact_level == "high"
    input.system_categorization.overall_impact_level == "high"
}

high_water_mark_properly_applied if {
    input.system_categorization.availability.impact_level == "high"
    input.system_categorization.overall_impact_level == "high"
}

high_water_mark_properly_applied if {
    input.system_categorization.confidentiality.impact_level != "high"
    input.system_categorization.integrity.impact_level != "high"
    input.system_categorization.availability.impact_level != "high"
    # If no high impacts, check for moderate
    moderate_impacts = [level | level := [
        input.system_categorization.confidentiality.impact_level,
        input.system_categorization.integrity.impact_level,
        input.system_categorization.availability.impact_level
    ][_]; level == "moderate"]
    count(moderate_impacts) > 0
    input.system_categorization.overall_impact_level == "moderate"
}

high_water_mark_properly_applied if {
    input.system_categorization.confidentiality.impact_level == "low"
    input.system_categorization.integrity.impact_level == "low"
    input.system_categorization.availability.impact_level == "low"
    input.system_categorization.overall_impact_level == "low"
}

# Information Types and Impact Assessment
information_types_identified if {
    count(input.system_categorization.information_types) > 0
    every info_type in input.system_categorization.information_types {
        info_type.confidentiality_impact != ""
        info_type.integrity_impact != ""
        info_type.availability_impact != ""
    }
}

# System Boundary Definition
system_boundary_defined if {
    input.system_categorization.system_boundary.clearly_defined == true
    input.system_categorization.system_boundary.documented == true
    input.system_categorization.system_boundary.components_identified == true
}

# Categorization Documentation Requirements
categorization_documentation_complete if {
    input.system_categorization.documentation.categorization_results_documented == true
    input.system_categorization.documentation.rationale_provided == true
    input.system_categorization.documentation.stakeholder_approval == true
    input.system_categorization.documentation.review_date != ""
}

# Information System Owner Responsibilities
system_owner_responsibilities_met if {
    input.system_categorization.system_owner.identified == true
    input.system_categorization.system_owner.categorization_approved == true
    input.system_categorization.system_owner.responsibilities_documented == true
}

# Senior Agency Information Security Officer (SAISO) Review
saiso_review_completed if {
    input.system_categorization.saiso_review.completed == true
    input.system_categorization.saiso_review.approval_documented == true
    input.system_categorization.saiso_review.date != ""
}

# Provisional Authorization Consideration
provisional_authorization_considered if {
    input.system_categorization.provisional_authorization.evaluated == true
    input.system_categorization.provisional_authorization.rationale_documented == true
}

provisional_authorization_considered if {
    # Not all systems require provisional authorization
    input.system_categorization.provisional_authorization.not_applicable == true
}

# External Service Dependencies
external_dependencies_identified if {
    count(input.system_categorization.external_dependencies) >= 0
    every dependency in input.system_categorization.external_dependencies {
        dependency.service_provider != ""
        dependency.categorization_level != ""
        dependency.risk_assessment_completed == true
    }
}

# Aggregate RMF Categorization compliance
rmf_categorization_compliant if {
    confidentiality_properly_categorized
    integrity_properly_categorized
    availability_properly_categorized
    overall_system_categorization_valid
    high_water_mark_properly_applied
    information_types_identified
    system_boundary_defined
    categorization_documentation_complete
    system_owner_responsibilities_met
    saiso_review_completed
    provisional_authorization_considered
    external_dependencies_identified
}

# Detailed RMF Categorization compliance report
rmf_categorization_compliance := {
    "confidentiality_properly_categorized": confidentiality_properly_categorized,
    "integrity_properly_categorized": integrity_properly_categorized,
    "availability_properly_categorized": availability_properly_categorized,
    "overall_system_categorization_valid": overall_system_categorization_valid,
    "high_water_mark_properly_applied": high_water_mark_properly_applied,
    "information_types_identified": information_types_identified,
    "system_boundary_defined": system_boundary_defined,
    "categorization_documentation_complete": categorization_documentation_complete,
    "system_owner_responsibilities_met": system_owner_responsibilities_met,
    "saiso_review_completed": saiso_review_completed,
    "provisional_authorization_considered": provisional_authorization_considered,
    "external_dependencies_identified": external_dependencies_identified,
    "overall_compliant": rmf_categorization_compliant,
    "system_impact_level": input.system_categorization.overall_impact_level
}