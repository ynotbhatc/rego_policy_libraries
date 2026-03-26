# SOC 2 Infrastructure - Storage Security and Management
# Comprehensive storage infrastructure controls for SOC 2 compliance

package soc2.infrastructure.storage

import rego.v1

# =================================================================
# STORAGE ARCHITECTURE AND DESIGN
# =================================================================

# Storage architecture is well-designed and documented
storage_architecture_managed if {
    input.storage.architecture.documentation.current == true
    input.storage.architecture.design.tiered_storage == true
    input.storage.architecture.performance.optimized == true
    input.storage.architecture.scalability.planned == true
    input.storage.architecture.redundancy.implemented == true
}

# Storage virtualization and abstraction
storage_virtualization_implemented if {
    input.storage.virtualization.enabled == true
    input.storage.virtualization.pooling.configured == true
    input.storage.virtualization.thin_provisioning.enabled == true
    input.storage.virtualization.migration.seamless == true
}

# Storage capacity planning and management
storage_capacity_managed if {
    input.storage.capacity.planning.predictive == true
    input.storage.capacity.monitoring.real_time == true
    input.storage.capacity.thresholds.configured == true
    input.storage.capacity.alerts.enabled == true
    input.storage.capacity.growth_tracking == true
}

# =================================================================
# DATA ENCRYPTION AND PROTECTION
# =================================================================

# Encryption at rest implementation
encryption_at_rest_comprehensive if {
    input.storage.encryption.at_rest.enabled == true
    input.storage.encryption.at_rest.algorithm.aes_256 == true
    input.storage.encryption.at_rest.key_management.centralized == true
    input.storage.encryption.at_rest.hardware_acceleration == true
    input.storage.encryption.at_rest.performance_optimized == true
}

# Key management for storage encryption
storage_key_management_secure if {
    input.storage.encryption.key_management.hsm.enabled == true
    input.storage.encryption.key_management.rotation.automated == true
    input.storage.encryption.key_management.escrow.configured == true
    input.storage.encryption.key_management.access_control.strict == true
}

# Data-at-rest protection mechanisms
data_protection_comprehensive if {
    input.storage.protection.integrity_checking.enabled == true
    input.storage.protection.checksums.automated == true
    input.storage.protection.corruption_detection == true
    input.storage.protection.self_healing.enabled == true
}

# =================================================================
# ACCESS CONTROL AND AUTHENTICATION
# =================================================================

# Storage access control implementation
storage_access_control_enforced if {
    input.storage.access_control.rbac.implemented == true
    input.storage.access_control.least_privilege.enforced == true
    input.storage.access_control.authentication.multi_factor == true
    input.storage.access_control.authorization.granular == true
}

# File system permissions and ACLs
filesystem_permissions_secure if {
    input.storage.filesystem.permissions.restrictive == true
    input.storage.filesystem.acls.configured == true
    input.storage.filesystem.ownership.managed == true
    input.storage.filesystem.suid_sgid.controlled == true
}

# Network-attached storage (NAS) security
nas_security_implemented if {
    input.storage.nas.authentication.enabled == true
    input.storage.nas.authorization.configured == true
    input.storage.nas.encryption_in_transit == true
    input.storage.nas.access_logging.comprehensive == true
}

# =================================================================
# BACKUP AND RECOVERY
# =================================================================

# Backup strategy and implementation
backup_strategy_robust if {
    input.storage.backup.strategy.three_two_one.implemented == true
    input.storage.backup.automation.scheduled == true
    input.storage.backup.verification.integrity_checks == true
    input.storage.backup.encryption.enabled == true
    input.storage.backup.compression.enabled == true
}

# Backup infrastructure security
backup_infrastructure_secure if {
    input.storage.backup.infrastructure.isolated == true
    input.storage.backup.infrastructure.immutable == true
    input.storage.backup.infrastructure.air_gapped == true
    input.storage.backup.infrastructure.geographically_distributed == true
}

# Recovery procedures and testing
recovery_procedures_tested if {
    input.storage.recovery.procedures.documented == true
    input.storage.recovery.testing.regular == true
    input.storage.recovery.rto.defined == true
    input.storage.recovery.rpo.defined == true
    input.storage.recovery.automation.enabled == true
}

# =================================================================
# STORAGE MONITORING AND LOGGING
# =================================================================

# Storage performance monitoring
storage_performance_monitored if {
    input.storage.monitoring.performance.iops.tracked == true
    input.storage.monitoring.performance.latency.measured == true
    input.storage.monitoring.performance.throughput.monitored == true
    input.storage.monitoring.performance.queue_depth.analyzed == true
}

# Storage health and status monitoring
storage_health_monitored if {
    input.storage.monitoring.health.drive_status.tracked == true
    input.storage.monitoring.health.smart_data.analyzed == true
    input.storage.monitoring.health.predictive_failure == true
    input.storage.monitoring.health.temperature.monitored == true
}

# Storage access and security logging
storage_logging_comprehensive if {
    input.storage.logging.access.comprehensive == true
    input.storage.logging.security_events.captured == true
    input.storage.logging.administrative_actions.logged == true
    input.storage.logging.centralized.enabled == true
    input.storage.logging.retention.policy_defined == true
}

# =================================================================
# CLOUD STORAGE SECURITY
# =================================================================

# Cloud storage configuration security
cloud_storage_secure if {
    input.storage.cloud.encryption.customer_managed_keys == true
    input.storage.cloud.access_control.iam_policies == true
    input.storage.cloud.public_access.blocked == true
    input.storage.cloud.versioning.enabled == true
    input.storage.cloud.mfa_delete.enabled == true
}

# Object storage security
object_storage_secure if {
    input.storage.object.bucket_policies.restrictive == true
    input.storage.object.lifecycle_management.configured == true
    input.storage.object.access_logging.enabled == true
    input.storage.object.cross_region_replication.encrypted == true
}

# Hybrid cloud storage security
hybrid_storage_secure if {
    input.storage.hybrid.data_classification.implemented == true
    input.storage.hybrid.tiering_policies.secure == true
    input.storage.hybrid.sync_encryption.enabled == true
    input.storage.hybrid.bandwidth_management.configured == true
}

# =================================================================
# CONTAINER STORAGE SECURITY
# =================================================================

# Container storage interface (CSI) security
csi_security_implemented if {
    input.storage.containers.csi.encryption.enabled == true
    input.storage.containers.csi.access_control.rbac == true
    input.storage.containers.csi.secrets_management.secure == true
    input.storage.containers.csi.audit_logging.enabled == true
}

# Persistent volume security
persistent_volume_secure if {
    input.storage.containers.pv.encryption_at_rest == true
    input.storage.containers.pv.access_modes.restricted == true
    input.storage.containers.pv.reclaim_policies.secure == true
    input.storage.containers.pv.storage_classes.secure == true
}

# Container image storage security
container_image_storage_secure if {
    input.storage.containers.images.registry_security.enabled == true
    input.storage.containers.images.vulnerability_scanning == true
    input.storage.containers.images.signing.required == true
    input.storage.containers.images.admission_control == true
}

# =================================================================
# DATA LIFECYCLE MANAGEMENT
# =================================================================

# Data classification and handling
data_classification_implemented if {
    input.storage.data_lifecycle.classification.automated == true
    input.storage.data_lifecycle.classification.policies.defined == true
    input.storage.data_lifecycle.classification.labeling.consistent == true
    input.storage.data_lifecycle.classification.handling.differentiated == true
}

# Data retention and archival
data_retention_managed if {
    input.storage.data_lifecycle.retention.policies.documented == true
    input.storage.data_lifecycle.retention.enforcement.automated == true
    input.storage.data_lifecycle.archival.tiered == true
    input.storage.data_lifecycle.archival.cost_optimized == true
}

# Secure data disposal
data_disposal_secure if {
    input.storage.data_lifecycle.disposal.secure_erasure == true
    input.storage.data_lifecycle.disposal.verification.completed == true
    input.storage.data_lifecycle.disposal.media_destruction.certified == true
    input.storage.data_lifecycle.disposal.documentation.maintained == true
}

# =================================================================
# STORAGE COMPLIANCE AND AUDITING
# =================================================================

# Regulatory compliance for storage
storage_compliance_maintained if {
    input.storage.compliance.regulations.identified == true
    input.storage.compliance.controls.implemented == true
    input.storage.compliance.reporting.automated == true
    input.storage.compliance.auditing.regular == true
}

# Storage audit trail and forensics
storage_audit_comprehensive if {
    input.storage.auditing.trail.comprehensive == true
    input.storage.auditing.integrity.tamper_evident == true
    input.storage.auditing.forensics.capabilities == true
    input.storage.auditing.reporting.detailed == true
}

# Data sovereignty and location controls
data_sovereignty_controlled if {
    input.storage.sovereignty.location.tracked == true
    input.storage.sovereignty.jurisdiction.compliant == true
    input.storage.sovereignty.cross_border.controlled == true
    input.storage.sovereignty.residency.enforced == true
}

# =================================================================
# DISASTER RECOVERY AND BUSINESS CONTINUITY
# =================================================================

# Storage disaster recovery
storage_disaster_recovery_ready if {
    input.storage.disaster_recovery.replication.real_time == true
    input.storage.disaster_recovery.failover.automated == true
    input.storage.disaster_recovery.testing.regular == true
    input.storage.disaster_recovery.documentation.current == true
}

# Geographic redundancy
geographic_redundancy_implemented if {
    input.storage.redundancy.geographic.multi_site == true
    input.storage.redundancy.geographic.synchronous == true
    input.storage.redundancy.geographic.bandwidth_adequate == true
    input.storage.redundancy.geographic.failback.automated == true
}

# Business continuity for storage
storage_business_continuity if {
    input.storage.business_continuity.critical_data.identified == true
    input.storage.business_continuity.recovery_priorities.defined == true
    input.storage.business_continuity.communication.procedures == true
    input.storage.business_continuity.vendor_coordination == true
}

# =================================================================
# OVERALL STORAGE INFRASTRUCTURE ASSESSMENT
# =================================================================

storage_architecture_compliant if {
    storage_architecture_managed
    storage_virtualization_implemented
    storage_capacity_managed
}

storage_encryption_compliant if {
    encryption_at_rest_comprehensive
    storage_key_management_secure
    data_protection_comprehensive
}

storage_access_compliant if {
    storage_access_control_enforced
    filesystem_permissions_secure
    nas_security_implemented
}

storage_backup_compliant if {
    backup_strategy_robust
    backup_infrastructure_secure
    recovery_procedures_tested
}

storage_monitoring_compliant if {
    storage_performance_monitored
    storage_health_monitored
    storage_logging_comprehensive
}

cloud_storage_compliant if {
    cloud_storage_secure
    object_storage_secure
    hybrid_storage_secure
}

container_storage_compliant if {
    csi_security_implemented
    persistent_volume_secure
    container_image_storage_secure
}

storage_lifecycle_compliant if {
    data_classification_implemented
    data_retention_managed
    data_disposal_secure
}

storage_governance_compliant if {
    storage_compliance_maintained
    storage_audit_comprehensive
    data_sovereignty_controlled
}

storage_resilience_compliant if {
    storage_disaster_recovery_ready
    geographic_redundancy_implemented
    storage_business_continuity
}

overall_storage_infrastructure_compliant if {
    storage_architecture_compliant
    storage_encryption_compliant
    storage_access_compliant
    storage_backup_compliant
    storage_monitoring_compliant
    cloud_storage_compliant
    container_storage_compliant
    storage_lifecycle_compliant
    storage_governance_compliant
    storage_resilience_compliant
}

# =================================================================
# STORAGE INFRASTRUCTURE SCORE CALCULATION
# =================================================================

storage_infrastructure_score := score if {
    controls := [
        storage_architecture_managed,
        storage_virtualization_implemented,
        storage_capacity_managed,
        encryption_at_rest_comprehensive,
        storage_key_management_secure,
        data_protection_comprehensive,
        storage_access_control_enforced,
        filesystem_permissions_secure,
        nas_security_implemented,
        backup_strategy_robust,
        backup_infrastructure_secure,
        recovery_procedures_tested,
        storage_performance_monitored,
        storage_health_monitored,
        storage_logging_comprehensive,
        cloud_storage_secure,
        object_storage_secure,
        hybrid_storage_secure,
        csi_security_implemented,
        persistent_volume_secure,
        container_image_storage_secure,
        data_classification_implemented,
        data_retention_managed,
        data_disposal_secure,
        storage_compliance_maintained,
        storage_audit_comprehensive,
        data_sovereignty_controlled,
        storage_disaster_recovery_ready,
        geographic_redundancy_implemented,
        storage_business_continuity
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# DETAILED STORAGE INFRASTRUCTURE FINDINGS
# =================================================================

storage_infrastructure_findings := findings if {
    findings := {
        "architecture": {
            "storage_architecture_managed": storage_architecture_managed,
            "storage_virtualization_implemented": storage_virtualization_implemented,
            "storage_capacity_managed": storage_capacity_managed
        },
        "encryption": {
            "encryption_at_rest_comprehensive": encryption_at_rest_comprehensive,
            "storage_key_management_secure": storage_key_management_secure,
            "data_protection_comprehensive": data_protection_comprehensive
        },
        "access_control": {
            "storage_access_control_enforced": storage_access_control_enforced,
            "filesystem_permissions_secure": filesystem_permissions_secure,
            "nas_security_implemented": nas_security_implemented
        },
        "backup_recovery": {
            "backup_strategy_robust": backup_strategy_robust,
            "backup_infrastructure_secure": backup_infrastructure_secure,
            "recovery_procedures_tested": recovery_procedures_tested
        },
        "monitoring": {
            "storage_performance_monitored": storage_performance_monitored,
            "storage_health_monitored": storage_health_monitored,
            "storage_logging_comprehensive": storage_logging_comprehensive
        },
        "cloud_storage": {
            "cloud_storage_secure": cloud_storage_secure,
            "object_storage_secure": object_storage_secure,
            "hybrid_storage_secure": hybrid_storage_secure
        },
        "container_storage": {
            "csi_security_implemented": csi_security_implemented,
            "persistent_volume_secure": persistent_volume_secure,
            "container_image_storage_secure": container_image_storage_secure
        },
        "lifecycle": {
            "data_classification_implemented": data_classification_implemented,
            "data_retention_managed": data_retention_managed,
            "data_disposal_secure": data_disposal_secure
        },
        "governance": {
            "storage_compliance_maintained": storage_compliance_maintained,
            "storage_audit_comprehensive": storage_audit_comprehensive,
            "data_sovereignty_controlled": data_sovereignty_controlled
        },
        "resilience": {
            "storage_disaster_recovery_ready": storage_disaster_recovery_ready,
            "geographic_redundancy_implemented": geographic_redundancy_implemented,
            "storage_business_continuity": storage_business_continuity
        },
        "overall_score": storage_infrastructure_score
    }
}