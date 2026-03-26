# SOC 2 Trust Service Criteria - Main Aggregation Policy
# Comprehensive SOC 2 Type II Compliance Assessment

package soc2.main

import rego.v1

import data.soc2.security.access_controls
import data.soc2.availability.system_availability
import data.soc2.processing_integrity.data_processing
import data.soc2.confidentiality.data_confidentiality
import data.soc2.privacy.data_privacy

# Infrastructure components
import data.soc2.infrastructure.network.network_infrastructure
import data.soc2.infrastructure.security.security_infrastructure
import data.soc2.infrastructure.systems.systems_infrastructure
import data.soc2.infrastructure.storage.storage_infrastructure
import data.soc2.infrastructure.applications_services.applications_services

# =================================================================
# SOC 2 TRUST SERVICE CRITERIA AGGREGATION
# =================================================================

# Security (Common Criteria) - Required for all SOC 2 reports
security_compliant if {
    access_controls.overall_security_compliant
}

# Availability - Optional criteria
availability_compliant if {
    system_availability.overall_availability_compliant
}

# Processing Integrity - Optional criteria
processing_integrity_compliant if {
    data_processing.overall_processing_integrity_compliant
}

# Confidentiality - Optional criteria
confidentiality_compliant if {
    data_confidentiality.overall_confidentiality_compliant
}

# Privacy - Optional criteria
privacy_compliant if {
    data_privacy.overall_privacy_compliant
}

# =================================================================
# INFRASTRUCTURE COMPLIANCE ASSESSMENT
# =================================================================

# Network infrastructure compliance
network_infrastructure_compliant if {
    network_infrastructure.overall_network_infrastructure_compliant
}

# Security infrastructure compliance
security_infrastructure_compliant if {
    security_infrastructure.overall_security_infrastructure_compliant
}

# Systems infrastructure compliance
systems_infrastructure_compliant if {
    systems_infrastructure.overall_systems_infrastructure_compliant
}

# Storage infrastructure compliance
storage_infrastructure_compliant if {
    storage_infrastructure.overall_storage_infrastructure_compliant
}

# Applications and services compliance
applications_services_compliant if {
    applications_services.overall_applications_services_compliant
}

# =================================================================
# COMPREHENSIVE SOC 2 COMPLIANCE ASSESSMENT
# =================================================================

# SOC 2 Type I - Point-in-time assessment
soc2_type_i_compliant if {
    security_compliant
    # Additional criteria based on service commitments
    count([criteria | 
        criteria := [availability_compliant, processing_integrity_compliant, confidentiality_compliant, privacy_compliant][_]; 
        criteria == true
    ]) >= 1
}

# SOC 2 Type II - Operating effectiveness over time
soc2_type_ii_compliant if {
    soc2_type_i_compliant
    operating_effectiveness_demonstrated
}

# Operating effectiveness criteria
operating_effectiveness_demonstrated if {
    input.soc2.operating_effectiveness.testing_period_months >= 12
    input.soc2.operating_effectiveness.continuous_monitoring == true
    input.soc2.operating_effectiveness.exception_reporting == true
    input.soc2.operating_effectiveness.management_response.documented == true
}

# =================================================================
# SOC 2 SCOPE AND SERVICE COMMITMENTS
# =================================================================

# Service commitments and system requirements are defined
service_commitments_defined if {
    input.soc2.service_commitments.security.defined == true
    input.soc2.service_commitments.suitability_of_design == true
    input.soc2.service_commitments.operating_effectiveness == true
}

# System boundaries are properly defined
system_boundaries_defined if {
    input.soc2.system_boundaries.infrastructure.documented == true
    input.soc2.system_boundaries.software.documented == true
    input.soc2.system_boundaries.people.documented == true
    input.soc2.system_boundaries.procedures.documented == true
    input.soc2.system_boundaries.data.documented == true
}

# =================================================================
# RISK ASSESSMENT AND MANAGEMENT
# =================================================================

# Risk assessment process is established
risk_assessment_established if {
    input.soc2.risk_management.risk_assessment.periodic == true
    input.soc2.risk_management.risk_assessment.methodology.defined == true
    input.soc2.risk_management.risk_identification.comprehensive == true
    input.soc2.risk_management.risk_response.documented == true
}

# Risk monitoring and reporting
risk_monitoring_active if {
    input.soc2.risk_management.monitoring.continuous == true
    input.soc2.risk_management.reporting.regular == true
    input.soc2.risk_management.escalation.procedures.defined == true
}

# =================================================================
# CONTROL ENVIRONMENT
# =================================================================

# Management oversight and tone at the top
management_oversight if {
    input.soc2.control_environment.governance.board_oversight == true
    input.soc2.control_environment.governance.management_philosophy == true
    input.soc2.control_environment.integrity.code_of_conduct == true
    input.soc2.control_environment.competence.defined_roles == true
}

# Human resources controls
hr_controls_effective if {
    input.soc2.human_resources.background_checks == true
    input.soc2.human_resources.training_programs == true
    input.soc2.human_resources.performance_evaluations == true
    input.soc2.human_resources.disciplinary_procedures == true
}

# =================================================================
# VENDOR AND SUBSERVICE ORGANIZATION MANAGEMENT
# =================================================================

# Vendor management program
vendor_management_program if {
    input.soc2.vendor_management.due_diligence.performed == true
    input.soc2.vendor_management.contracts.security_requirements == true
    input.soc2.vendor_management.monitoring.ongoing == true
    input.soc2.vendor_management.termination.procedures.defined == true
}

# Subservice organization oversight
subservice_organization_oversight if {
    count(input.soc2.subservice_organizations) == 0
    # OR if subservice organizations exist:
    # all([org.soc_report.current == true | org := input.soc2.subservice_organizations[_]])
}

# =================================================================
# CHANGE MANAGEMENT
# =================================================================

# Change management process
change_management_process if {
    input.soc2.change_management.process.documented == true
    input.soc2.change_management.approval.required == true
    input.soc2.change_management.testing.required == true
    input.soc2.change_management.rollback.procedures.defined == true
}

# Configuration management
configuration_management if {
    input.soc2.configuration_management.baseline.established == true
    input.soc2.configuration_management.version_control == true
    input.soc2.configuration_management.unauthorized_changes.detection == true
}

# =================================================================
# INCIDENT RESPONSE AND BUSINESS CONTINUITY
# =================================================================

# Incident response program
incident_response_program if {
    input.soc2.incident_response.program.established == true
    input.soc2.incident_response.team.defined == true
    input.soc2.incident_response.procedures.documented == true
    input.soc2.incident_response.testing.regular == true
}

# Business continuity planning
business_continuity_planning if {
    input.soc2.business_continuity.plan.documented == true
    input.soc2.business_continuity.testing.annual == true
    input.soc2.business_continuity.recovery_objectives.defined == true
    input.soc2.business_continuity.communication.plan.defined == true
}

# =================================================================
# MONITORING AND LOGGING
# =================================================================

# System monitoring
system_monitoring_comprehensive if {
    input.soc2.monitoring.infrastructure.comprehensive == true
    input.soc2.monitoring.applications.comprehensive == true
    input.soc2.monitoring.security_events.real_time == true
    input.soc2.monitoring.performance.continuous == true
}

# Log management
log_management_effective if {
    input.soc2.logging.centralized == true
    input.soc2.logging.integrity_protection == true
    input.soc2.logging.retention.adequate == true
    input.soc2.logging.review.regular == true
}

# =================================================================
# OVERALL SOC 2 ASSESSMENT
# =================================================================

# Core SOC 2 requirements
core_soc2_requirements_met if {
    service_commitments_defined
    system_boundaries_defined
    risk_assessment_established
    risk_monitoring_active
    management_oversight
    hr_controls_effective
}

# Operational controls
operational_controls_effective if {
    vendor_management_program
    subservice_organization_oversight
    change_management_process
    configuration_management
    incident_response_program
    business_continuity_planning
}

# Monitoring and oversight
monitoring_oversight_effective if {
    system_monitoring_comprehensive
    log_management_effective
}

# Infrastructure compliance aggregate
infrastructure_compliant if {
    network_infrastructure_compliant
    security_infrastructure_compliant
    systems_infrastructure_compliant
    storage_infrastructure_compliant
    applications_services_compliant
}

# Overall SOC 2 compliance
overall_soc2_compliant if {
    security_compliant
    core_soc2_requirements_met
    operational_controls_effective
    monitoring_oversight_effective
    infrastructure_compliant
}

# =================================================================
# SOC 2 COMPLIANCE SCORING
# =================================================================

# Individual trust service criteria scores
trust_service_criteria_scores := scores if {
    scores := {
        "security": access_controls.security_score,
        "availability": system_availability.availability_score,
        "processing_integrity": data_processing.processing_integrity_score,
        "confidentiality": data_confidentiality.confidentiality_score,
        "privacy": data_privacy.privacy_score
    }
}

# Infrastructure component scores
infrastructure_scores := scores if {
    scores := {
        "network": network_infrastructure.network_infrastructure_score,
        "security": security_infrastructure.security_infrastructure_score,
        "systems": systems_infrastructure.systems_infrastructure_score,
        "storage": storage_infrastructure.storage_infrastructure_score,
        "applications_services": applications_services.applications_services_score
    }
}

# Overall SOC 2 compliance score
soc2_compliance_score := score if {
    # Weight security more heavily as it's required
    security_weight := 0.4
    other_criteria_weight := 0.15  # Each of the 4 optional criteria
    
    security_score := access_controls.security_score * security_weight
    availability_score := system_availability.availability_score * other_criteria_weight
    processing_integrity_score := data_processing.processing_integrity_score * other_criteria_weight
    confidentiality_score := data_confidentiality.confidentiality_score * other_criteria_weight
    privacy_score := data_privacy.privacy_score * other_criteria_weight
    
    score := security_score + availability_score + processing_integrity_score + confidentiality_score + privacy_score
}

# =================================================================
# DETAILED SOC 2 FINDINGS
# =================================================================

soc2_detailed_findings := findings if {
    findings := {
        "trust_service_criteria": {
            "security": access_controls.security_findings,
            "availability": system_availability.availability_findings,
            "processing_integrity": data_processing.processing_integrity_findings,
            "confidentiality": data_confidentiality.confidentiality_findings,
            "privacy": data_privacy.privacy_findings
        },
        "compliance_status": {
            "security_compliant": security_compliant,
            "availability_compliant": availability_compliant,
            "processing_integrity_compliant": processing_integrity_compliant,
            "confidentiality_compliant": confidentiality_compliant,
            "privacy_compliant": privacy_compliant,
            "soc2_type_i_compliant": soc2_type_i_compliant,
            "soc2_type_ii_compliant": soc2_type_ii_compliant,
            "overall_soc2_compliant": overall_soc2_compliant
        },
        "scores": {
            "individual_criteria": trust_service_criteria_scores,
            "infrastructure_components": infrastructure_scores,
            "overall_compliance": soc2_compliance_score
        },
        "operational_effectiveness": {
            "core_requirements_met": core_soc2_requirements_met,
            "operational_controls_effective": operational_controls_effective,
            "monitoring_oversight_effective": monitoring_oversight_effective
        },
        "infrastructure": {
            "network": network_infrastructure.network_infrastructure_findings,
            "security": security_infrastructure.security_infrastructure_findings,
            "systems": systems_infrastructure.systems_infrastructure_findings,
            "storage": storage_infrastructure.storage_infrastructure_findings,
            "applications_services": applications_services.applications_services_findings
        }
    }
}