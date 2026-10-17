# SOC 2 Infrastructure - Security Infrastructure and Operations
# Comprehensive security infrastructure controls for SOC 2 compliance

# METADATA
# title: "SOC 2 Infrastructure - Security Infrastructure and Operations"
# custom:
#   class: compliance
#   framework: soc2
#   source: aicpa
#   domains: [assurance]
#   coverage:
#     checks: 30
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package soc2.infrastructure.security

import rego.v1

# =================================================================
# SECURITY OPERATIONS CENTER (SOC)
# =================================================================

# SOC capabilities and coverage
default soc_capabilities_comprehensive := false

soc_capabilities_comprehensive if {
    input.security.soc.coverage.twenty_four_seven == true
    input.security.soc.staffing.qualified_analysts == true
    input.security.soc.procedures.documented == true
    input.security.soc.escalation.defined == true
    input.security.soc.metrics.tracked == true
}

# Security incident response capabilities
default incident_response_capabilities := false

incident_response_capabilities if {
    input.security.incident_response.team.dedicated == true
    input.security.incident_response.procedures.tested == true
    input.security.incident_response.tools.automated == true
    input.security.incident_response.communication.established == true
    input.security.incident_response.forensics.capable == true
}

# Threat hunting and intelligence
default threat_hunting_implemented := false

threat_hunting_implemented if {
    input.security.threat_hunting.proactive.enabled == true
    input.security.threat_hunting.intelligence.feeds == true
    input.security.threat_hunting.indicators.managed == true
    input.security.threat_hunting.analysis.behavioral == true
}

# =================================================================
# SECURITY INFORMATION AND EVENT MANAGEMENT (SIEM)
# =================================================================

# SIEM platform and capabilities
default siem_platform_comprehensive := false

siem_platform_comprehensive if {
    input.security.siem.platform.enterprise_grade == true
    input.security.siem.log_sources.comprehensive == true
    input.security.siem.correlation.rules == true
    input.security.siem.alerting.real_time == true
    input.security.siem.retention.compliant == true
}

# Security analytics and detection
default security_analytics_advanced := false

security_analytics_advanced if {
    input.security.analytics.machine_learning.enabled == true
    input.security.analytics.behavioral.analysis == true
    input.security.analytics.anomaly_detection.automated == true
    input.security.analytics.threat_scoring.implemented == true
}

# Security orchestration and automated response (SOAR)
default soar_capabilities_implemented := false

soar_capabilities_implemented if {
    input.security.soar.playbooks.automated == true
    input.security.soar.integration.comprehensive == true
    input.security.soar.response.orchestrated == true
    input.security.soar.metrics.measured == true
}

# =================================================================
# VULNERABILITY MANAGEMENT PROGRAM
# =================================================================

# Vulnerability assessment program
default vulnerability_assessment_comprehensive := false

vulnerability_assessment_comprehensive if {
    input.security.vulnerability_management.scanning.continuous == true
    input.security.vulnerability_management.coverage.comprehensive == true
    input.security.vulnerability_management.prioritization.risk_based == true
    input.security.vulnerability_management.reporting.automated == true
}

# Penetration testing program
default penetration_testing_regular := false

penetration_testing_regular if {
    input.security.penetration_testing.frequency.annual == true
    input.security.penetration_testing.scope.comprehensive == true
    input.security.penetration_testing.methodology.standard == true
    input.security.penetration_testing.remediation.tracked == true
}

# Security assessments and audits
default security_assessments_regular := false

security_assessments_regular if {
    input.security.assessments.risk_assessments.periodic == true
    input.security.assessments.security_audits.independent == true
    input.security.assessments.compliance_reviews.regular == true
    input.security.assessments.gap_analysis.conducted == true
}

# =================================================================
# IDENTITY AND ACCESS MANAGEMENT (IAM)
# =================================================================

# Enterprise identity management
default identity_management_enterprise := false

identity_management_enterprise if {
    input.security.iam.directory_services.centralized == true
    input.security.iam.user_lifecycle.automated == true
    input.security.iam.privileged_access.managed == true
    input.security.iam.federation.implemented == true
}

# Multi-factor authentication deployment
default mfa_deployment_comprehensive := false

mfa_deployment_comprehensive if {
    input.security.iam.mfa.universal.deployed == true
    input.security.iam.mfa.risk_based.enabled == true
    input.security.iam.mfa.adaptive.implemented == true
    input.security.iam.mfa.backup_methods.available == true
}

# Privileged access management (PAM)
default pam_solution_implemented := false

pam_solution_implemented if {
    input.security.iam.pam.password_vaulting == true
    input.security.iam.pam.session_recording == true
    input.security.iam.pam.just_in_time_access == true
    input.security.iam.pam.privilege_escalation.controlled == true
}

# =================================================================
# ENDPOINT DETECTION AND RESPONSE (EDR)
# =================================================================

# EDR platform deployment
default edr_platform_deployed := false

edr_platform_deployed if {
    input.security.edr.coverage.comprehensive == true
    input.security.edr.detection.behavioral == true
    input.security.edr.response.automated == true
    input.security.edr.forensics.detailed == true
    input.security.edr.threat_hunting.enabled == true
}

# Endpoint protection platform (EPP)
default epp_solution_comprehensive := false

epp_solution_comprehensive if {
    input.security.epp.antivirus.next_generation == true
    input.security.epp.firewall.host_based == true
    input.security.epp.application_control.enabled == true
    input.security.epp.device_control.implemented == true
}

# Mobile device management (MDM)
default mdm_solution_deployed := false

mdm_solution_deployed if {
    input.security.mdm.enrollment.mandatory == true
    input.security.mdm.policies.enforced == true
    input.security.mdm.compliance.monitored == true
    input.security.mdm.remote_wipe.capable == true
}

# =================================================================
# NETWORK SECURITY INFRASTRUCTURE
# =================================================================

# Network security monitoring
default network_security_monitoring := false

network_security_monitoring if {
    input.security.network.monitoring.traffic_analysis == true
    input.security.network.monitoring.intrusion_detection == true
    input.security.network.monitoring.behavioral_analysis == true
    input.security.network.monitoring.threat_intelligence == true
}

# Network access control (NAC)
default network_access_control_deployed := false

network_access_control_deployed if {
    input.security.network.nac.device_authentication == true
    input.security.network.nac.posture_assessment == true
    input.security.network.nac.policy_enforcement == true
    input.security.network.nac.quarantine.automated == true
}

# Zero trust network architecture
default zero_trust_implemented := false

zero_trust_implemented if {
    input.security.network.zero_trust.verification.continuous == true
    input.security.network.zero_trust.least_privilege == true
    input.security.network.zero_trust.micro_segmentation == true
    input.security.network.zero_trust.encryption.ubiquitous == true
}

# =================================================================
# CLOUD SECURITY INFRASTRUCTURE
# =================================================================

# Cloud security posture management (CSPM)
default cspm_implemented := false

cspm_implemented if {
    input.security.cloud.cspm.multi_cloud == true
    input.security.cloud.cspm.continuous_monitoring == true
    input.security.cloud.cspm.policy_enforcement == true
    input.security.cloud.cspm.compliance_reporting == true
}

# Cloud workload protection platform (CWPP)
default cwpp_deployed := false

cwpp_deployed if {
    input.security.cloud.cwpp.container_security == true
    input.security.cloud.cwpp.serverless_security == true
    input.security.cloud.cwpp.vm_protection == true
    input.security.cloud.cwpp.compliance_monitoring == true
}

# Cloud access security broker (CASB)
default casb_solution_implemented := false

casb_solution_implemented if {
    input.security.cloud.casb.shadow_it_discovery == true
    input.security.cloud.casb.data_loss_prevention == true
    input.security.cloud.casb.threat_protection == true
    input.security.cloud.casb.compliance_monitoring == true
}

# =================================================================
# DATA SECURITY INFRASTRUCTURE
# =================================================================

# Data loss prevention (DLP)
default dlp_solution_comprehensive := false

dlp_solution_comprehensive if {
    input.security.dlp.coverage.comprehensive == true
    input.security.dlp.policies.data_classification == true
    input.security.dlp.monitoring.real_time == true
    input.security.dlp.response.automated == true
}

# Database activity monitoring (DAM)
default database_activity_monitoring := false

database_activity_monitoring if {
    input.security.dam.monitoring.real_time == true
    input.security.dam.policies.comprehensive == true
    input.security.dam.alerting.configured == true
    input.security.dam.compliance.reporting == true
}

# File integrity monitoring (FIM)
default file_integrity_monitoring := false

file_integrity_monitoring if {
    input.security.fim.coverage.critical_files == true
    input.security.fim.monitoring.real_time == true
    input.security.fim.alerting.immediate == true
    input.security.fim.reporting.detailed == true
}

# =================================================================
# SECURITY GOVERNANCE AND COMPLIANCE
# =================================================================

# Security governance framework
default security_governance_established := false

security_governance_established if {
    input.security.governance.framework.established == true
    input.security.governance.policies.comprehensive == true
    input.security.governance.standards.defined == true
    input.security.governance.procedures.documented == true
}

# Risk management program
default risk_management_program := false

risk_management_program if {
    input.security.risk_management.framework.implemented == true
    input.security.risk_management.assessment.regular == true
    input.security.risk_management.mitigation.tracked == true
    input.security.risk_management.reporting.executive == true
}

# Compliance management system
default compliance_management_automated := false

compliance_management_automated if {
    input.security.compliance.monitoring.continuous == true
    input.security.compliance.reporting.automated == true
    input.security.compliance.evidence.collection == true
    input.security.compliance.gap_remediation.tracked == true
}

# =================================================================
# SECURITY AWARENESS AND TRAINING
# =================================================================

# Security awareness program
default security_awareness_comprehensive := false

security_awareness_comprehensive if {
    input.security.awareness.program.established == true
    input.security.awareness.training.mandatory == true
    input.security.awareness.phishing.simulations == true
    input.security.awareness.metrics.tracked == true
}

# Security training and certification
default security_training_program := false

security_training_program if {
    input.security.training.role_based.implemented == true
    input.security.training.technical.provided == true
    input.security.training.certifications.encouraged == true
    input.security.training.effectiveness.measured == true
}

# Incident response training
default incident_response_training := false

incident_response_training if {
    input.security.training.incident_response.regular == true
    input.security.training.tabletop_exercises.conducted == true
    input.security.training.simulation.realistic == true
    input.security.training.lessons_learned.documented == true
}

# =================================================================
# OVERALL SECURITY INFRASTRUCTURE ASSESSMENT
# =================================================================

default security_operations_compliant := false

security_operations_compliant if {
    soc_capabilities_comprehensive
    incident_response_capabilities
    threat_hunting_implemented
}

default security_monitoring_compliant := false

security_monitoring_compliant if {
    siem_platform_comprehensive
    security_analytics_advanced
    soar_capabilities_implemented
}

default vulnerability_management_compliant := false

vulnerability_management_compliant if {
    vulnerability_assessment_comprehensive
    penetration_testing_regular
    security_assessments_regular
}

default identity_access_compliant := false

identity_access_compliant if {
    identity_management_enterprise
    mfa_deployment_comprehensive
    pam_solution_implemented
}

default endpoint_security_compliant := false

endpoint_security_compliant if {
    edr_platform_deployed
    epp_solution_comprehensive
    mdm_solution_deployed
}

default network_security_compliant := false

network_security_compliant if {
    network_security_monitoring
    network_access_control_deployed
    zero_trust_implemented
}

default cloud_security_compliant := false

cloud_security_compliant if {
    cspm_implemented
    cwpp_deployed
    casb_solution_implemented
}

default data_security_compliant := false

data_security_compliant if {
    dlp_solution_comprehensive
    database_activity_monitoring
    file_integrity_monitoring
}

default security_governance_compliant := false

security_governance_compliant if {
    security_governance_established
    risk_management_program
    compliance_management_automated
}

default security_training_compliant := false

security_training_compliant if {
    security_awareness_comprehensive
    security_training_program
    incident_response_training
}

default overall_security_infrastructure_compliant := false

overall_security_infrastructure_compliant if {
    security_operations_compliant
    security_monitoring_compliant
    vulnerability_management_compliant
    identity_access_compliant
    endpoint_security_compliant
    network_security_compliant
    cloud_security_compliant
    data_security_compliant
    security_governance_compliant
    security_training_compliant
}

# =================================================================
# SECURITY INFRASTRUCTURE SCORE CALCULATION
# =================================================================

security_infrastructure_score := score if {
    controls := [
        soc_capabilities_comprehensive,
        incident_response_capabilities,
        threat_hunting_implemented,
        siem_platform_comprehensive,
        security_analytics_advanced,
        soar_capabilities_implemented,
        vulnerability_assessment_comprehensive,
        penetration_testing_regular,
        security_assessments_regular,
        identity_management_enterprise,
        mfa_deployment_comprehensive,
        pam_solution_implemented,
        edr_platform_deployed,
        epp_solution_comprehensive,
        mdm_solution_deployed,
        network_security_monitoring,
        network_access_control_deployed,
        zero_trust_implemented,
        cspm_implemented,
        cwpp_deployed,
        casb_solution_implemented,
        dlp_solution_comprehensive,
        database_activity_monitoring,
        file_integrity_monitoring,
        security_governance_established,
        risk_management_program,
        compliance_management_automated,
        security_awareness_comprehensive,
        security_training_program,
        incident_response_training
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# DETAILED SECURITY INFRASTRUCTURE FINDINGS
# =================================================================

security_infrastructure_findings := findings if {
    findings := {
        "security_operations": {
            "soc_capabilities_comprehensive": soc_capabilities_comprehensive,
            "incident_response_capabilities": incident_response_capabilities,
            "threat_hunting_implemented": threat_hunting_implemented
        },
        "security_monitoring": {
            "siem_platform_comprehensive": siem_platform_comprehensive,
            "security_analytics_advanced": security_analytics_advanced,
            "soar_capabilities_implemented": soar_capabilities_implemented
        },
        "vulnerability_management": {
            "vulnerability_assessment_comprehensive": vulnerability_assessment_comprehensive,
            "penetration_testing_regular": penetration_testing_regular,
            "security_assessments_regular": security_assessments_regular
        },
        "identity_access": {
            "identity_management_enterprise": identity_management_enterprise,
            "mfa_deployment_comprehensive": mfa_deployment_comprehensive,
            "pam_solution_implemented": pam_solution_implemented
        },
        "endpoint_security": {
            "edr_platform_deployed": edr_platform_deployed,
            "epp_solution_comprehensive": epp_solution_comprehensive,
            "mdm_solution_deployed": mdm_solution_deployed
        },
        "network_security": {
            "network_security_monitoring": network_security_monitoring,
            "network_access_control_deployed": network_access_control_deployed,
            "zero_trust_implemented": zero_trust_implemented
        },
        "cloud_security": {
            "cspm_implemented": cspm_implemented,
            "cwpp_deployed": cwpp_deployed,
            "casb_solution_implemented": casb_solution_implemented
        },
        "data_security": {
            "dlp_solution_comprehensive": dlp_solution_comprehensive,
            "database_activity_monitoring": database_activity_monitoring,
            "file_integrity_monitoring": file_integrity_monitoring
        },
        "governance": {
            "security_governance_established": security_governance_established,
            "risk_management_program": risk_management_program,
            "compliance_management_automated": compliance_management_automated
        },
        "training": {
            "security_awareness_comprehensive": security_awareness_comprehensive,
            "security_training_program": security_training_program,
            "incident_response_training": incident_response_training
        },
        "overall_score": security_infrastructure_score
    }
}