# SOC 2 Infrastructure - Systems Architecture and Management
# Comprehensive systems infrastructure controls for SOC 2 compliance

package soc2.infrastructure.systems

import rego.v1

# =================================================================
# SYSTEM ARCHITECTURE AND DESIGN
# =================================================================

# System architecture is documented and managed
system_architecture_managed if {
    input.systems.architecture.documentation.current == true
    input.systems.architecture.documentation.detailed == true
    input.systems.architecture.design_principles.security_by_design == true
    input.systems.architecture.scalability.horizontal.supported == true
    input.systems.architecture.fault_tolerance.designed == true
}

# Infrastructure as Code (IaC) implementation
infrastructure_as_code_implemented if {
    input.systems.iac.enabled == true
    input.systems.iac.version_control.git_managed == true
    input.systems.iac.validation.automated == true
    input.systems.iac.deployment.automated == true
    input.systems.iac.rollback.capability == true
}

# System standardization and consistency
system_standardization if {
    input.systems.standardization.base_images.standardized == true
    input.systems.standardization.configurations.templated == true
    input.systems.standardization.naming_conventions.enforced == true
    input.systems.standardization.tagging.consistent == true
}

# =================================================================
# OPERATING SYSTEM HARDENING
# =================================================================

# OS hardening standards compliance
os_hardening_compliant if {
    input.systems.hardening.cis_benchmarks.applied == true
    input.systems.hardening.unnecessary_services.disabled == true
    input.systems.hardening.kernel_parameters.secured == true
    input.systems.hardening.file_permissions.restrictive == true
    input.systems.hardening.network_services.minimized == true
}

# Security configurations management
security_configurations_managed if {
    input.systems.security_config.baseline.defined == true
    input.systems.security_config.compliance_scanning.automated == true
    input.systems.security_config.drift_detection.enabled == true
    input.systems.security_config.remediation.automated == true
}

# System access controls
system_access_controls if {
    input.systems.access_control.local_accounts.minimized == true
    input.systems.access_control.privileged_access.managed == true
    input.systems.access_control.sudo_configuration.restricted == true
    input.systems.access_control.ssh_keys.managed == true
    input.systems.access_control.session_timeout.configured == true
}

# =================================================================
# PATCH MANAGEMENT AND VULNERABILITY MANAGEMENT
# =================================================================

# Patch management program
patch_management_effective if {
    input.systems.patch_management.automated_scanning == true
    input.systems.patch_management.testing_environment == true
    input.systems.patch_management.rollout_schedule.defined == true
    input.systems.patch_management.emergency_patching.process == true
    input.systems.patch_management.rollback_procedures == true
}

# Vulnerability assessment and management
vulnerability_management_comprehensive if {
    input.systems.vulnerability_management.scanning.continuous == true
    input.systems.vulnerability_management.assessment.risk_based == true
    input.systems.vulnerability_management.remediation.prioritized == true
    input.systems.vulnerability_management.metrics.tracked == true
}

# Security update automation
security_updates_automated if {
    input.systems.security_updates.critical_patches.automatic == true
    input.systems.security_updates.non_critical.scheduled == true
    input.systems.security_updates.verification.post_update == true
    input.systems.security_updates.notifications.enabled == true
}

# =================================================================
# SYSTEM MONITORING AND LOGGING
# =================================================================

# System monitoring infrastructure
system_monitoring_comprehensive if {
    input.systems.monitoring.performance.continuous == true
    input.systems.monitoring.availability.real_time == true
    input.systems.monitoring.resource_utilization.tracked == true
    input.systems.monitoring.capacity_planning.enabled == true
    input.systems.monitoring.alerts.configured == true
}

# System logging and audit
system_logging_compliant if {
    input.systems.logging.audit_logs.comprehensive == true
    input.systems.logging.security_events.captured == true
    input.systems.logging.centralized.enabled == true
    input.systems.logging.retention.policy_defined == true
    input.systems.logging.integrity.protected == true
}

# Performance monitoring and optimization
performance_monitoring_active if {
    input.systems.performance.metrics.comprehensive == true
    input.systems.performance.baselines.established == true
    input.systems.performance.anomaly_detection.enabled == true
    input.systems.performance.optimization.continuous == true
}

# =================================================================
# BACKUP AND DISASTER RECOVERY
# =================================================================

# Backup strategy and implementation
backup_strategy_comprehensive if {
    input.systems.backup.strategy.three_two_one_rule == true
    input.systems.backup.automation.scheduled == true
    input.systems.backup.verification.regular == true
    input.systems.backup.encryption.enabled == true
    input.systems.backup.offsite.configured == true
}

# Disaster recovery planning
disaster_recovery_ready if {
    input.systems.disaster_recovery.plan.documented == true
    input.systems.disaster_recovery.testing.regular == true
    input.systems.disaster_recovery.rto.defined == true
    input.systems.disaster_recovery.rpo.defined == true
    input.systems.disaster_recovery.communication.plan == true
}

# Business continuity controls
business_continuity_implemented if {
    input.systems.business_continuity.critical_systems.identified == true
    input.systems.business_continuity.dependencies.mapped == true
    input.systems.business_continuity.failover.automated == true
    input.systems.business_continuity.testing.scheduled == true
}

# =================================================================
# CONTAINER AND ORCHESTRATION SECURITY
# =================================================================

# Container platform security
container_platform_secure if {
    input.systems.containers.runtime_security.enabled == true
    input.systems.containers.image_scanning.automated == true
    input.systems.containers.registry_security.configured == true
    input.systems.containers.secrets_management.secure == true
}

# Kubernetes/OpenShift security
orchestration_security_compliant if {
    input.systems.orchestration.rbac.configured == true
    input.systems.orchestration.pod_security.standards_enforced == true
    input.systems.orchestration.network_policies.implemented == true
    input.systems.orchestration.admission_controllers.configured == true
}

# Container lifecycle management
container_lifecycle_managed if {
    input.systems.containers.lifecycle.build_security == true
    input.systems.containers.lifecycle.deployment_controls == true
    input.systems.containers.lifecycle.runtime_monitoring == true
    input.systems.containers.lifecycle.termination_procedures == true
}

# =================================================================
# CLOUD INFRASTRUCTURE SECURITY
# =================================================================

# Cloud security posture management
cloud_security_posture_managed if {
    input.systems.cloud.cspm.enabled == true
    input.systems.cloud.compliance_monitoring.continuous == true
    input.systems.cloud.misconfigurations.detected == true
    input.systems.cloud.security_benchmarks.applied == true
}

# Infrastructure security controls
infrastructure_security_controls if {
    input.systems.cloud.identity_management.centralized == true
    input.systems.cloud.resource_access.controlled == true
    input.systems.cloud.encryption.default_enabled == true
    input.systems.cloud.logging.comprehensive == true
}

# Multi-cloud and hybrid security
multi_cloud_security_consistent if {
    input.systems.multi_cloud.policies.consistent == true
    input.systems.multi_cloud.monitoring.unified == true
    input.systems.multi_cloud.compliance.standardized == true
    input.systems.multi_cloud.security_orchestration == true
}

# =================================================================
# CONFIGURATION MANAGEMENT
# =================================================================

# Configuration management system
configuration_management_implemented if {
    input.systems.config_management.tool.deployed == true
    input.systems.config_management.version_control.enabled == true
    input.systems.config_management.change_tracking.automated == true
    input.systems.config_management.compliance_enforcement == true
}

# Configuration drift detection
configuration_drift_managed if {
    input.systems.config_drift.detection.continuous == true
    input.systems.config_drift.alerting.real_time == true
    input.systems.config_drift.remediation.automated == true
    input.systems.config_drift.reporting.regular == true
}

# Baseline configuration management
baseline_configuration_enforced if {
    input.systems.baseline.security_hardening.applied == true
    input.systems.baseline.performance_optimization.applied == true
    input.systems.baseline.compliance_requirements.met == true
    input.systems.baseline.updates.managed == true
}

# =================================================================
# CAPACITY MANAGEMENT AND SCALING
# =================================================================

# Capacity planning and management
capacity_management_effective if {
    input.systems.capacity.planning.predictive == true
    input.systems.capacity.monitoring.real_time == true
    input.systems.capacity.scaling.automated == true
    input.systems.capacity.optimization.continuous == true
}

# Auto-scaling implementation
auto_scaling_configured if {
    input.systems.scaling.horizontal.enabled == true
    input.systems.scaling.vertical.enabled == true
    input.systems.scaling.policies.optimized == true
    input.systems.scaling.monitoring.comprehensive == true
}

# Resource optimization
resource_optimization_active if {
    input.systems.resources.utilization.monitored == true
    input.systems.resources.allocation.optimized == true
    input.systems.resources.cost_optimization.enabled == true
    input.systems.resources.rightsizing.automated == true
}

# =================================================================
# OVERALL SYSTEMS INFRASTRUCTURE ASSESSMENT
# =================================================================

systems_architecture_compliant if {
    system_architecture_managed
    infrastructure_as_code_implemented
    system_standardization
}

systems_security_compliant if {
    os_hardening_compliant
    security_configurations_managed
    system_access_controls
    patch_management_effective
    vulnerability_management_comprehensive
    security_updates_automated
}

systems_monitoring_compliant if {
    system_monitoring_comprehensive
    system_logging_compliant
    performance_monitoring_active
}

systems_resilience_compliant if {
    backup_strategy_comprehensive
    disaster_recovery_ready
    business_continuity_implemented
}

container_orchestration_compliant if {
    container_platform_secure
    orchestration_security_compliant
    container_lifecycle_managed
}

cloud_systems_compliant if {
    cloud_security_posture_managed
    infrastructure_security_controls
    multi_cloud_security_consistent
}

systems_management_compliant if {
    configuration_management_implemented
    configuration_drift_managed
    baseline_configuration_enforced
    capacity_management_effective
    auto_scaling_configured
    resource_optimization_active
}

overall_systems_infrastructure_compliant if {
    systems_architecture_compliant
    systems_security_compliant
    systems_monitoring_compliant
    systems_resilience_compliant
    container_orchestration_compliant
    cloud_systems_compliant
    systems_management_compliant
}

# =================================================================
# SYSTEMS INFRASTRUCTURE SCORE CALCULATION
# =================================================================

systems_infrastructure_score := score if {
    controls := [
        system_architecture_managed,
        infrastructure_as_code_implemented,
        system_standardization,
        os_hardening_compliant,
        security_configurations_managed,
        system_access_controls,
        patch_management_effective,
        vulnerability_management_comprehensive,
        security_updates_automated,
        system_monitoring_comprehensive,
        system_logging_compliant,
        performance_monitoring_active,
        backup_strategy_comprehensive,
        disaster_recovery_ready,
        business_continuity_implemented,
        container_platform_secure,
        orchestration_security_compliant,
        container_lifecycle_managed,
        cloud_security_posture_managed,
        infrastructure_security_controls,
        multi_cloud_security_consistent,
        configuration_management_implemented,
        configuration_drift_managed,
        baseline_configuration_enforced,
        capacity_management_effective,
        auto_scaling_configured,
        resource_optimization_active
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# DETAILED SYSTEMS INFRASTRUCTURE FINDINGS
# =================================================================

systems_infrastructure_findings := findings if {
    findings := {
        "architecture": {
            "system_architecture_managed": system_architecture_managed,
            "infrastructure_as_code_implemented": infrastructure_as_code_implemented,
            "system_standardization": system_standardization
        },
        "security": {
            "os_hardening_compliant": os_hardening_compliant,
            "security_configurations_managed": security_configurations_managed,
            "system_access_controls": system_access_controls,
            "patch_management_effective": patch_management_effective,
            "vulnerability_management_comprehensive": vulnerability_management_comprehensive,
            "security_updates_automated": security_updates_automated
        },
        "monitoring": {
            "system_monitoring_comprehensive": system_monitoring_comprehensive,
            "system_logging_compliant": system_logging_compliant,
            "performance_monitoring_active": performance_monitoring_active
        },
        "resilience": {
            "backup_strategy_comprehensive": backup_strategy_comprehensive,
            "disaster_recovery_ready": disaster_recovery_ready,
            "business_continuity_implemented": business_continuity_implemented
        },
        "containers": {
            "container_platform_secure": container_platform_secure,
            "orchestration_security_compliant": orchestration_security_compliant,
            "container_lifecycle_managed": container_lifecycle_managed
        },
        "cloud": {
            "cloud_security_posture_managed": cloud_security_posture_managed,
            "infrastructure_security_controls": infrastructure_security_controls,
            "multi_cloud_security_consistent": multi_cloud_security_consistent
        },
        "management": {
            "configuration_management_implemented": configuration_management_implemented,
            "configuration_drift_managed": configuration_drift_managed,
            "baseline_configuration_enforced": baseline_configuration_enforced,
            "capacity_management_effective": capacity_management_effective,
            "auto_scaling_configured": auto_scaling_configured,
            "resource_optimization_active": resource_optimization_active
        },
        "overall_score": systems_infrastructure_score
    }
}