# SOC 2 Infrastructure - Applications and Services Security
# Comprehensive application and service infrastructure controls for SOC 2 compliance

package soc2.infrastructure.applications_services

import rego.v1

# =================================================================
# APPLICATION ARCHITECTURE AND DESIGN
# =================================================================

# Secure application architecture
application_architecture_secure if {
    input.applications.architecture.security_by_design == true
    input.applications.architecture.microservices.isolated == true
    input.applications.architecture.api_gateway.implemented == true
    input.applications.architecture.service_mesh.enabled == true
    input.applications.architecture.zero_trust.implemented == true
}

# Application development lifecycle security
application_development_secure if {
    input.applications.development.secure_coding.standards == true
    input.applications.development.code_review.mandatory == true
    input.applications.development.security_testing.automated == true
    input.applications.development.dependency_scanning.enabled == true
    input.applications.development.sast_dast.integrated == true
}

# Application deployment security
application_deployment_secure if {
    input.applications.deployment.ci_cd_security.enabled == true
    input.applications.deployment.container_scanning.automated == true
    input.applications.deployment.secrets_management.secure == true
    input.applications.deployment.configuration_management.secure == true
}

# =================================================================
# APPLICATION SECURITY CONTROLS
# =================================================================

# Authentication and authorization
application_auth_comprehensive if {
    input.applications.security.authentication.multi_factor == true
    input.applications.security.authorization.rbac == true
    input.applications.security.session_management.secure == true
    input.applications.security.single_sign_on.implemented == true
    input.applications.security.oauth_oidc.implemented == true
}

# Input validation and output encoding
application_input_validation if {
    input.applications.security.input_validation.comprehensive == true
    input.applications.security.output_encoding.implemented == true
    input.applications.security.sql_injection.prevention == true
    input.applications.security.xss_prevention.implemented == true
    input.applications.security.csrf_protection.enabled == true
}

# Application-level encryption
application_encryption_implemented if {
    input.applications.security.encryption.data_at_rest == true
    input.applications.security.encryption.data_in_transit == true
    input.applications.security.encryption.field_level == true
    input.applications.security.encryption.key_management == true
}

# =================================================================
# API SECURITY AND MANAGEMENT
# =================================================================

# API security framework
api_security_comprehensive if {
    input.applications.apis.authentication.required == true
    input.applications.apis.authorization.granular == true
    input.applications.apis.rate_limiting.implemented == true
    input.applications.apis.input_validation.strict == true
    input.applications.apis.versioning.managed == true
}

# API gateway security
api_gateway_secure if {
    input.applications.apis.gateway.security_policies == true
    input.applications.apis.gateway.threat_protection == true
    input.applications.apis.gateway.monitoring.comprehensive == true
    input.applications.apis.gateway.analytics.enabled == true
}

# API documentation and lifecycle
api_lifecycle_managed if {
    input.applications.apis.documentation.current == true
    input.applications.apis.documentation.security_requirements == true
    input.applications.apis.testing.automated == true
    input.applications.apis.deprecation.managed == true
}

# =================================================================
# MICROSERVICES AND CONTAINER SECURITY
# =================================================================

# Microservices security architecture
microservices_security_implemented if {
    input.applications.microservices.service_isolation == true
    input.applications.microservices.inter_service_auth == true
    input.applications.microservices.service_mesh.security == true
    input.applications.microservices.secrets_per_service == true
}

# Container security for applications
container_application_security if {
    input.applications.containers.base_images.minimal == true
    input.applications.containers.vulnerability_scanning == true
    input.applications.containers.runtime_security == true
    input.applications.containers.secrets_injection.secure == true
    input.applications.containers.network_policies == true
}

# Service-to-service communication security
service_communication_secure if {
    input.applications.communication.mutual_tls.enforced == true
    input.applications.communication.encryption.end_to_end == true
    input.applications.communication.certificate_management == true
    input.applications.communication.traffic_encryption == true
}

# =================================================================
# APPLICATION MONITORING AND LOGGING
# =================================================================

# Application performance monitoring (APM)
application_monitoring_comprehensive if {
    input.applications.monitoring.performance.real_time == true
    input.applications.monitoring.user_experience.tracked == true
    input.applications.monitoring.resource_utilization == true
    input.applications.monitoring.error_tracking.comprehensive == true
    input.applications.monitoring.distributed_tracing == true
}

# Security event logging and monitoring
application_security_logging if {
    input.applications.logging.security_events.comprehensive == true
    input.applications.logging.authentication_events == true
    input.applications.logging.authorization_failures == true
    input.applications.logging.data_access.tracked == true
    input.applications.logging.anomaly_detection == true
}

# Application observability
application_observability_implemented if {
    input.applications.observability.metrics.comprehensive == true
    input.applications.observability.logs.structured == true
    input.applications.observability.traces.distributed == true
    input.applications.observability.dashboards.real_time == true
}

# =================================================================
# DATA PROTECTION IN APPLICATIONS
# =================================================================

# Data classification and handling
application_data_classification if {
    input.applications.data.classification.implemented == true
    input.applications.data.handling.policies.enforced == true
    input.applications.data.masking.implemented == true
    input.applications.data.tokenization.enabled == true
}

# Privacy controls in applications
application_privacy_controls if {
    input.applications.privacy.consent_management == true
    input.applications.privacy.data_minimization == true
    input.applications.privacy.right_to_erasure == true
    input.applications.privacy.data_portability == true
    input.applications.privacy.privacy_by_design == true
}

# Sensitive data protection
sensitive_data_protection if {
    input.applications.data.pii_protection.implemented == true
    input.applications.data.pci_compliance.implemented == true
    input.applications.data.phi_protection.implemented == true
    input.applications.data.data_loss_prevention == true
}

# =================================================================
# APPLICATION AVAILABILITY AND RESILIENCE
# =================================================================

# High availability design
application_high_availability if {
    input.applications.availability.load_balancing.implemented == true
    input.applications.availability.auto_scaling.configured == true
    input.applications.availability.health_checks.comprehensive == true
    input.applications.availability.circuit_breakers.implemented == true
    input.applications.availability.retry_mechanisms.configured == true
}

# Disaster recovery for applications
application_disaster_recovery if {
    input.applications.disaster_recovery.backup_strategies == true
    input.applications.disaster_recovery.failover.automated == true
    input.applications.disaster_recovery.data_replication == true
    input.applications.disaster_recovery.testing.regular == true
}

# Application resilience patterns
application_resilience_patterns if {
    input.applications.resilience.bulkhead_pattern.implemented == true
    input.applications.resilience.timeout_handling.configured == true
    input.applications.resilience.graceful_degradation == true
    input.applications.resilience.chaos_engineering.practiced == true
}

# =================================================================
# DEVOPS AND CI/CD SECURITY
# =================================================================

# Secure DevOps practices
devops_security_implemented if {
    input.applications.devops.pipeline_security.enabled == true
    input.applications.devops.infrastructure_as_code.secure == true
    input.applications.devops.secrets_management.automated == true
    input.applications.devops.compliance_automation == true
}

# CI/CD pipeline security
cicd_pipeline_secure if {
    input.applications.cicd.source_code.protected == true
    input.applications.cicd.build_security.enabled == true
    input.applications.cicd.artifact_scanning.automated == true
    input.applications.cicd.deployment_controls.implemented == true
    input.applications.cicd.rollback_capabilities.tested == true
}

# Configuration and secrets management
config_secrets_management if {
    input.applications.config.externalized == true
    input.applications.config.encrypted == true
    input.applications.config.version_controlled == true
    input.applications.secrets.vault_integration == true
    input.applications.secrets.rotation.automated == true
}

# =================================================================
# THIRD-PARTY INTEGRATIONS AND DEPENDENCIES
# =================================================================

# Third-party service integration security
third_party_integration_secure if {
    input.applications.third_party.security_assessment.conducted == true
    input.applications.third_party.data_sharing.controlled == true
    input.applications.third_party.sla_monitoring.enabled == true
    input.applications.third_party.vendor_management.implemented == true
}

# Dependency management and security
dependency_management_secure if {
    input.applications.dependencies.vulnerability_scanning == true
    input.applications.dependencies.license_compliance == true
    input.applications.dependencies.update_management.automated == true
    input.applications.dependencies.supply_chain.secured == true
}

# Software composition analysis
software_composition_analysis if {
    input.applications.sca.open_source.scanning == true
    input.applications.sca.license_compliance == true
    input.applications.sca.vulnerability_management == true
    input.applications.sca.policy_enforcement == true
}

# =================================================================
# CLOUD-NATIVE APPLICATION SECURITY
# =================================================================

# Serverless security (Functions as a Service)
serverless_security_implemented if {
    input.applications.serverless.function_isolation == true
    input.applications.serverless.iam_roles.minimal == true
    input.applications.serverless.environment_variables.secure == true
    input.applications.serverless.cold_start.secured == true
}

# Platform as a Service (PaaS) security
paas_security_implemented if {
    input.applications.paas.platform_hardening == true
    input.applications.paas.application_isolation == true
    input.applications.paas.shared_responsibility.understood == true
    input.applications.paas.compliance.maintained == true
}

# Cloud-native security patterns
cloud_native_security_patterns if {
    input.applications.cloud_native.twelve_factor.compliance == true
    input.applications.cloud_native.stateless_design == true
    input.applications.cloud_native.immutable_infrastructure == true
    input.applications.cloud_native.event_driven.secure == true
}

# =================================================================
# APPLICATION COMPLIANCE AND GOVERNANCE
# =================================================================

# Application compliance framework
application_compliance_maintained if {
    input.applications.compliance.requirements.identified == true
    input.applications.compliance.controls.implemented == true
    input.applications.compliance.monitoring.continuous == true
    input.applications.compliance.reporting.automated == true
}

# Application governance processes
application_governance_implemented if {
    input.applications.governance.architecture.review == true
    input.applications.governance.security.review == true
    input.applications.governance.risk_assessment == true
    input.applications.governance.change_management == true
}

# Application risk management
application_risk_managed if {
    input.applications.risk.assessment.regular == true
    input.applications.risk.mitigation.implemented == true
    input.applications.risk.monitoring.continuous == true
    input.applications.risk.reporting.executive == true
}

# =================================================================
# OVERALL APPLICATIONS AND SERVICES ASSESSMENT
# =================================================================

application_architecture_compliant if {
    application_architecture_secure
    application_development_secure
    application_deployment_secure
}

application_security_compliant if {
    application_auth_comprehensive
    application_input_validation
    application_encryption_implemented
    api_security_comprehensive
    api_gateway_secure
    api_lifecycle_managed
}

microservices_container_compliant if {
    microservices_security_implemented
    container_application_security
    service_communication_secure
}

application_monitoring_compliant if {
    application_monitoring_comprehensive
    application_security_logging
    application_observability_implemented
}

application_data_protection_compliant if {
    application_data_classification
    application_privacy_controls
    sensitive_data_protection
}

application_resilience_compliant if {
    application_high_availability
    application_disaster_recovery
    application_resilience_patterns
}

devops_security_compliant if {
    devops_security_implemented
    cicd_pipeline_secure
    config_secrets_management
}

third_party_security_compliant if {
    third_party_integration_secure
    dependency_management_secure
    software_composition_analysis
}

cloud_native_compliant if {
    serverless_security_implemented
    paas_security_implemented
    cloud_native_security_patterns
}

application_governance_compliant if {
    application_compliance_maintained
    application_governance_implemented
    application_risk_managed
}

overall_applications_services_compliant if {
    application_architecture_compliant
    application_security_compliant
    microservices_container_compliant
    application_monitoring_compliant
    application_data_protection_compliant
    application_resilience_compliant
    devops_security_compliant
    third_party_security_compliant
    cloud_native_compliant
    application_governance_compliant
}

# =================================================================
# APPLICATIONS AND SERVICES SCORE CALCULATION
# =================================================================

applications_services_score := score if {
    controls := [
        application_architecture_secure,
        application_development_secure,
        application_deployment_secure,
        application_auth_comprehensive,
        application_input_validation,
        application_encryption_implemented,
        api_security_comprehensive,
        api_gateway_secure,
        api_lifecycle_managed,
        microservices_security_implemented,
        container_application_security,
        service_communication_secure,
        application_monitoring_comprehensive,
        application_security_logging,
        application_observability_implemented,
        application_data_classification,
        application_privacy_controls,
        sensitive_data_protection,
        application_high_availability,
        application_disaster_recovery,
        application_resilience_patterns,
        devops_security_implemented,
        cicd_pipeline_secure,
        config_secrets_management,
        third_party_integration_secure,
        dependency_management_secure,
        software_composition_analysis,
        serverless_security_implemented,
        paas_security_implemented,
        cloud_native_security_patterns,
        application_compliance_maintained,
        application_governance_implemented,
        application_risk_managed
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# DETAILED APPLICATIONS AND SERVICES FINDINGS
# =================================================================

applications_services_findings := findings if {
    findings := {
        "architecture": {
            "application_architecture_secure": application_architecture_secure,
            "application_development_secure": application_development_secure,
            "application_deployment_secure": application_deployment_secure
        },
        "security": {
            "application_auth_comprehensive": application_auth_comprehensive,
            "application_input_validation": application_input_validation,
            "application_encryption_implemented": application_encryption_implemented,
            "api_security_comprehensive": api_security_comprehensive,
            "api_gateway_secure": api_gateway_secure,
            "api_lifecycle_managed": api_lifecycle_managed
        },
        "microservices_containers": {
            "microservices_security_implemented": microservices_security_implemented,
            "container_application_security": container_application_security,
            "service_communication_secure": service_communication_secure
        },
        "monitoring": {
            "application_monitoring_comprehensive": application_monitoring_comprehensive,
            "application_security_logging": application_security_logging,
            "application_observability_implemented": application_observability_implemented
        },
        "data_protection": {
            "application_data_classification": application_data_classification,
            "application_privacy_controls": application_privacy_controls,
            "sensitive_data_protection": sensitive_data_protection
        },
        "resilience": {
            "application_high_availability": application_high_availability,
            "application_disaster_recovery": application_disaster_recovery,
            "application_resilience_patterns": application_resilience_patterns
        },
        "devops": {
            "devops_security_implemented": devops_security_implemented,
            "cicd_pipeline_secure": cicd_pipeline_secure,
            "config_secrets_management": config_secrets_management
        },
        "third_party": {
            "third_party_integration_secure": third_party_integration_secure,
            "dependency_management_secure": dependency_management_secure,
            "software_composition_analysis": software_composition_analysis
        },
        "cloud_native": {
            "serverless_security_implemented": serverless_security_implemented,
            "paas_security_implemented": paas_security_implemented,
            "cloud_native_security_patterns": cloud_native_security_patterns
        },
        "governance": {
            "application_compliance_maintained": application_compliance_maintained,
            "application_governance_implemented": application_governance_implemented,
            "application_risk_managed": application_risk_managed
        },
        "overall_score": applications_services_score
    }
}