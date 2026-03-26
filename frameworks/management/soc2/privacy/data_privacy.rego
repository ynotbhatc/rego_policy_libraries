# SOC 2 Trust Service Criteria - Privacy (P1.0)
# Data Privacy Controls and Personal Information Management

package soc2.privacy.data_privacy

import rego.v1

# =================================================================
# P1.1 - Privacy - Personal Information Collection
# =================================================================

# Personal information collection is governed by policies
pi_collection_governed if {
    input.privacy.collection.policy_documented == true
    input.privacy.collection.legal_basis_identified == true
    input.privacy.collection.purpose_limitation == true
    input.privacy.collection.data_minimization == true
}

# Consent management is implemented
consent_management_implemented if {
    input.privacy.consent.explicit_consent_required == true
    input.privacy.consent.consent_tracking.enabled == true
    input.privacy.consent.withdrawal_mechanism.available == true
    input.privacy.consent.granular_consent.supported == true
}

# Data subject rights are supported
data_subject_rights_supported if {
    input.privacy.data_subject_rights.access_request.supported == true
    input.privacy.data_subject_rights.rectification.supported == true
    input.privacy.data_subject_rights.erasure.supported == true
    input.privacy.data_subject_rights.portability.supported == true
}

# =================================================================
# P1.2 - Privacy - Personal Information Use and Retention
# =================================================================

# Personal information use is restricted
pi_use_restricted if {
    input.privacy.use.purpose_limitation == true
    input.privacy.use.compatible_use_only == true
    input.privacy.use.access_controls.role_based == true
    input.privacy.use.processing_logging == true
}

# Data retention policies are implemented
privacy_retention_implemented if {
    input.privacy.retention.policies_documented == true
    input.privacy.retention.automated_deletion == true
    input.privacy.retention.legal_hold_management == true
    input.privacy.retention.retention_schedules.defined == true
}

# Data accuracy and quality controls
data_accuracy_controls if {
    input.privacy.data_quality.accuracy_verification == true
    input.privacy.data_quality.regular_updates == true
    input.privacy.data_quality.correction_procedures == true
}

# =================================================================
# P1.3 - Privacy - Personal Information Disclosure
# =================================================================

# Third-party data sharing is controlled
third_party_sharing_controlled if {
    input.privacy.third_party_sharing.documented_agreements == true
    input.privacy.third_party_sharing.due_diligence_performed == true
    input.privacy.third_party_sharing.data_processing_agreements == true
    input.privacy.third_party_sharing.regular_assessments == true
}

# Cross-border data transfers are managed
cross_border_transfers_managed if {
    input.privacy.cross_border_transfers.adequacy_decisions.verified == true
    input.privacy.cross_border_transfers.safeguards.implemented == true
    input.privacy.cross_border_transfers.transfer_logging == true
}

# Data breach notification procedures
breach_notification_procedures if {
    input.privacy.breach_notification.procedures_documented == true
    input.privacy.breach_notification.timeline_compliance.authorities <= 72  # hours
    input.privacy.breach_notification.timeline_compliance.individuals <= 72  # hours
    input.privacy.breach_notification.assessment_criteria.defined == true
}

# =================================================================
# OpenShift/Kubernetes Privacy Controls
# =================================================================

# Container-level privacy controls
container_privacy_controls if {
    input.openshift.privacy.data_isolation.namespace_separation == true
    input.openshift.privacy.data_isolation.pod_security_policies == true
    input.openshift.privacy.secrets_management.personal_data_encryption == true
}

# Application-level privacy controls
application_privacy_controls if {
    input.openshift.applications.privacy.data_anonymization.enabled == true
    input.openshift.applications.privacy.pseudonymization.enabled == true
    input.openshift.applications.privacy.encryption_at_field_level == true
}

# Service mesh privacy enforcement
service_mesh_privacy if {
    input.openshift.service_mesh.privacy.traffic_encryption == true
    input.openshift.service_mesh.privacy.data_flow_monitoring == true
    input.openshift.service_mesh.privacy.policy_enforcement == true
}

# =================================================================
# Privacy by Design Implementation
# =================================================================

# Privacy by design principles
privacy_by_design if {
    input.privacy.by_design.default_privacy_settings == true
    input.privacy.by_design.privacy_impact_assessments == true
    input.privacy.by_design.data_protection_officer.appointed == true
    input.privacy.by_design.privacy_training.provided == true
}

# Technical privacy measures
technical_privacy_measures if {
    input.privacy.technical_measures.encryption.personal_data == true
    input.privacy.technical_measures.anonymization.automated == true
    input.privacy.technical_measures.access_logging.personal_data == true
    input.privacy.technical_measures.data_masking.non_production == true
}

# Organizational privacy measures
organizational_privacy_measures if {
    input.privacy.organizational_measures.policies_documented == true
    input.privacy.organizational_measures.staff_training == true
    input.privacy.organizational_measures.vendor_management == true
    input.privacy.organizational_measures.regular_audits == true
}

# =================================================================
# Privacy Monitoring and Compliance
# =================================================================

# Privacy monitoring systems
privacy_monitoring_active if {
    input.privacy.monitoring.data_processing_activities == true
    input.privacy.monitoring.consent_compliance == true
    input.privacy.monitoring.retention_compliance == true
    input.privacy.monitoring.automated_alerts == true
}

# Privacy compliance reporting
privacy_compliance_reporting if {
    input.privacy.compliance.regular_reports.generated == true
    input.privacy.compliance.metrics.tracked == true
    input.privacy.compliance.management_review.conducted == true
    input.privacy.compliance.continuous_improvement == true
}

# Data subject request handling
data_subject_request_handling if {
    input.privacy.data_subject_requests.automated_workflow == true
    input.privacy.data_subject_requests.identity_verification == true
    input.privacy.data_subject_requests.response_timeline <= 30  # days
    input.privacy.data_subject_requests.request_logging == true
}

# =================================================================
# International Privacy Compliance
# =================================================================

# GDPR compliance (EU)
gdpr_compliance if {
    input.privacy.gdpr.lawful_basis.documented == true
    input.privacy.gdpr.dpo_appointed == true
    input.privacy.gdpr.privacy_notices.compliant == true
    input.privacy.gdpr.records_of_processing == true
}

# CCPA compliance (California)
ccpa_compliance if {
    input.privacy.ccpa.consumer_rights.supported == true
    input.privacy.ccpa.opt_out_mechanisms.available == true
    input.privacy.ccpa.privacy_policy.compliant == true
    input.privacy.ccpa.sale_disclosure == true
}

# Other regional privacy laws
regional_privacy_compliance if {
    input.privacy.regional_laws.identification_completed == true
    input.privacy.regional_laws.compliance_assessment.conducted == true
    input.privacy.regional_laws.implementation.verified == true
}

# =================================================================
# Overall Privacy Assessment
# =================================================================

privacy_collection_compliant if {
    pi_collection_governed
    consent_management_implemented
    data_subject_rights_supported
}

privacy_processing_compliant if {
    pi_use_restricted
    privacy_retention_implemented
    data_accuracy_controls
}

privacy_disclosure_compliant if {
    third_party_sharing_controlled
    cross_border_transfers_managed
    breach_notification_procedures
}

openshift_privacy_compliant if {
    container_privacy_controls
    application_privacy_controls
    service_mesh_privacy
}

privacy_governance_compliant if {
    privacy_by_design
    technical_privacy_measures
    organizational_privacy_measures
}

privacy_operations_compliant if {
    privacy_monitoring_active
    privacy_compliance_reporting
    data_subject_request_handling
}

international_privacy_compliant if {
    gdpr_compliance
    ccpa_compliance
    regional_privacy_compliance
}

overall_privacy_compliant if {
    privacy_collection_compliant
    privacy_processing_compliant
    privacy_disclosure_compliant
    openshift_privacy_compliant
    privacy_governance_compliant
    privacy_operations_compliant
    international_privacy_compliant
}

# =================================================================
# Privacy Score Calculation
# =================================================================

privacy_score := score if {
    controls := [
        pi_collection_governed,
        consent_management_implemented,
        data_subject_rights_supported,
        pi_use_restricted,
        privacy_retention_implemented,
        data_accuracy_controls,
        third_party_sharing_controlled,
        cross_border_transfers_managed,
        breach_notification_procedures,
        container_privacy_controls,
        application_privacy_controls,
        service_mesh_privacy,
        privacy_by_design,
        technical_privacy_measures,
        organizational_privacy_measures,
        privacy_monitoring_active,
        privacy_compliance_reporting,
        data_subject_request_handling,
        gdpr_compliance,
        ccpa_compliance,
        regional_privacy_compliance
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# Detailed Findings
# =================================================================

privacy_findings := findings if {
    findings := {
        "pi_collection_governed": pi_collection_governed,
        "consent_management_implemented": consent_management_implemented,
        "data_subject_rights_supported": data_subject_rights_supported,
        "pi_use_restricted": pi_use_restricted,
        "privacy_retention_implemented": privacy_retention_implemented,
        "data_accuracy_controls": data_accuracy_controls,
        "third_party_sharing_controlled": third_party_sharing_controlled,
        "cross_border_transfers_managed": cross_border_transfers_managed,
        "breach_notification_procedures": breach_notification_procedures,
        "container_privacy_controls": container_privacy_controls,
        "application_privacy_controls": application_privacy_controls,
        "service_mesh_privacy": service_mesh_privacy,
        "privacy_by_design": privacy_by_design,
        "technical_privacy_measures": technical_privacy_measures,
        "organizational_privacy_measures": organizational_privacy_measures,
        "privacy_monitoring_active": privacy_monitoring_active,
        "privacy_compliance_reporting": privacy_compliance_reporting,
        "data_subject_request_handling": data_subject_request_handling,
        "gdpr_compliance": gdpr_compliance,
        "ccpa_compliance": ccpa_compliance,
        "regional_privacy_compliance": regional_privacy_compliance,
        "overall_score": privacy_score
    }
}