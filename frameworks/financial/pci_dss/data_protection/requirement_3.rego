# PCI DSS Requirement 3 - Protect Stored Account Data
# Critical requirement for cardholder data protection at rest

package pci_dss.data_protection.requirement_3

import rego.v1

# =================================================================
# 3.1 - Processes and mechanisms for protecting stored account data
# =================================================================

# Account data protection policies and procedures
account_data_protection_policies if {
    input.pci.data_protection.policies.documented == true
    input.pci.data_protection.policies.approved == true
    input.pci.data_protection.policies.current == true
    input.pci.data_protection.policies.reviewed_annually == true
}

# Data protection roles and responsibilities
data_protection_roles_defined if {
    input.pci.data_protection.roles.defined == true
    input.pci.data_protection.roles.documented == true
    input.pci.data_protection.responsibilities.assigned == true
    input.pci.data_protection.accountability.established == true
}

# Account data inventory and classification
account_data_inventory_maintained if {
    input.pci.data_inventory.cardholder_data.documented == true
    input.pci.data_inventory.sensitive_auth_data.documented == true
    input.pci.data_inventory.locations.identified == true
    input.pci.data_inventory.data_flows.mapped == true
}

# =================================================================
# 3.2 - Account data storage is kept to a minimum
# =================================================================

# Data retention and disposal policy
data_retention_policy_implemented if {
    input.pci.data_retention.policy.documented == true
    input.pci.data_retention.policy.business_justified == true
    input.pci.data_retention.policy.legal_requirements_met == true
    input.pci.data_retention.policy.regularly_reviewed == true
}

# Cardholder data purging processes
cardholder_data_purging if {
    input.pci.data_purging.automated.implemented == true
    input.pci.data_purging.schedule.defined == true
    input.pci.data_purging.verification.conducted == true
    input.pci.data_purging.secure_deletion.implemented == true
}

# Sensitive authentication data post-authorization deletion
sad_post_auth_deletion if {
    input.pci.sad_deletion.post_authorization.automated == true
    input.pci.sad_deletion.verification.implemented == true
    input.pci.sad_deletion.logs.maintained == true
    input.pci.sad_deletion.exceptions.documented == true
}

# Quarterly data discovery and purging
quarterly_data_discovery if {
    input.pci.data_discovery.quarterly.conducted == true
    input.pci.data_discovery.automated_tools.used == true
    input.pci.data_discovery.results.documented == true
    input.pci.data_discovery.remediation.tracked == true
}

# =================================================================
# 3.3 - Sensitive authentication data is not stored after authorization
# =================================================================

# Full magnetic stripe data storage prohibition
magnetic_stripe_data_prohibited if {
    input.pci.sad_storage.magnetic_stripe.prohibited == true
    input.pci.sad_storage.track_data.prohibited == true
    input.pci.sad_storage.track_equivalent.prohibited == true
}

# Card verification code storage prohibition
cvc_storage_prohibited if {
    input.pci.sad_storage.cvc.prohibited == true
    input.pci.sad_storage.cvc2.prohibited == true
    input.pci.sad_storage.cvv2.prohibited == true
    input.pci.sad_storage.cid.prohibited == true
}

# PIN and PIN block storage prohibition
pin_storage_prohibited if {
    input.pci.sad_storage.pin.prohibited == true
    input.pci.sad_storage.pin_blocks.prohibited == true
    input.pci.sad_storage.pin_verification.prohibited == true
}

# =================================================================
# 3.4 - Access to displays of full PAN is restricted
# =================================================================

# PAN display restriction policies
pan_display_restricted if {
    input.pci.pan_display.restriction.implemented == true
    input.pci.pan_display.business_need.documented == true
    input.pci.pan_display.authorization.required == true
    input.pci.pan_display.logging.comprehensive == true
}

# PAN masking implementation
pan_masking_implemented if {
    input.pci.pan_masking["default"].enabled == true
    input.pci.pan_masking.first_six_last_four.maximum == true
    input.pci.pan_masking.applications.compliant == true
    input.pci.pan_masking.reports.implemented == true
}

# Screen protection for PAN display
screen_protection_implemented if {
    input.pci.screen_protection.automatic_timeout.enabled == true
    input.pci.screen_protection.shoulder_surfing.prevented == true
    input.pci.screen_protection.viewing_restrictions.implemented == true
}

# =================================================================
# 3.5 - Primary account number is protected wherever it is stored
# =================================================================

# PAN encryption requirements
pan_encryption_implemented if {
    input.pci.pan_encryption.strong_cryptography.used == true
    input.pci.pan_encryption.aes_minimum.compliant == true
    input.pci.pan_encryption.algorithm_approved.implemented == true
    input.pci.pan_encryption.key_strength.adequate == true
}

# Database-level encryption
database_encryption_implemented if {
    input.pci.database_encryption.tablespace.encrypted == true
    input.pci.database_encryption.column_level.implemented == true
    input.pci.database_encryption.transparent_data_encryption.enabled == true
    input.pci.database_encryption.application_level.implemented == true
}

# File system encryption
filesystem_encryption_implemented if {
    input.pci.filesystem_encryption.full_disk.enabled == true
    input.pci.filesystem_encryption.file_level.implemented == true
    input.pci.filesystem_encryption.removable_media.required == true
    input.pci.filesystem_encryption.backup_media.encrypted == true
}

# =================================================================
# 3.6 - Cryptographic keys used to protect stored account data
# =================================================================

# Key management policies and procedures
key_management_policies if {
    input.pci.key_management.policies.documented == true
    input.pci.key_management.policies.approved == true
    input.pci.key_management.procedures.defined == true
    input.pci.key_management.lifecycle.managed == true
}

# Key generation standards
key_generation_standards if {
    input.pci.key_generation.strong_methods.used == true
    input.pci.key_generation.random_sources.cryptographically_strong == true
    input.pci.key_generation.key_strength.adequate == true
    input.pci.key_generation.algorithm_compliance.verified == true
}

# Key distribution security
key_distribution_secure if {
    input.pci.key_distribution.secure_channels.used == true
    input.pci.key_distribution.split_knowledge.implemented == true
    input.pci.key_distribution.dual_control.enforced == true
    input.pci.key_distribution.authorization.required == true
}

# Key storage protection
key_storage_protected if {
    input.pci.key_storage.hsm.used == true
    input.pci.key_storage.encrypted.always == true
    input.pci.key_storage.access_controls.strict == true
    input.pci.key_storage.separation.from_data == true
}

# =================================================================
# 3.7 - Where cryptography is used to protect stored account data
# =================================================================

# Cryptographic architecture documentation
crypto_architecture_documented if {
    input.pci.cryptography.architecture.documented == true
    input.pci.cryptography.algorithms.approved == true
    input.pci.cryptography.protocols.secure == true
    input.pci.cryptography.implementation.validated == true
}

# Cryptographic key administration
crypto_key_administration if {
    input.pci.crypto_admin.procedures.documented == true
    input.pci.crypto_admin.access_controls.implemented == true
    input.pci.crypto_admin.change_management.enforced == true
    input.pci.crypto_admin.monitoring.comprehensive == true
}

# Key lifecycle management
key_lifecycle_management if {
    input.pci.key_lifecycle.generation.secure == true
    input.pci.key_lifecycle.distribution.controlled == true
    input.pci.key_lifecycle.rotation.scheduled == true
    input.pci.key_lifecycle.destruction.secure == true
}

# =================================================================
# OpenShift/Kubernetes Data Protection
# =================================================================

# OpenShift secrets management for PCI
openshift_secrets_pci_compliant if {
    input.openshift.secrets.external_vault.integrated == true
    input.openshift.secrets.encryption_at_rest.enabled == true
    input.openshift.secrets.rotation.automated == true
    input.openshift.secrets.access_control.rbac == true
}

# Container data encryption
container_data_encryption if {
    input.openshift.containers.data_encryption.persistent_volumes == true
    input.openshift.containers.data_encryption.ephemeral_storage == true
    input.openshift.containers.data_encryption.container_images == true
    input.openshift.containers.data_encryption.application_layer == true
}

# OpenShift storage encryption
openshift_storage_encryption if {
    input.openshift.storage.csi_encryption.enabled == true
    input.openshift.storage.storage_classes.encrypted == true
    input.openshift.storage.volume_encryption.automatic == true
    input.openshift.storage.backup_encryption.enabled == true
}

# Container registry security
container_registry_security if {
    input.openshift.registry.image_encryption.enabled == true
    input.openshift.registry.vulnerability_scanning.comprehensive == true
    input.openshift.registry.image_signing.required == true
    input.openshift.registry.access_controls.strict == true
}

# =================================================================
# Cloud Data Protection Controls
# =================================================================

# Cloud encryption services
cloud_encryption_services if {
    input.cloud.encryption.kms.integrated == true
    input.cloud.encryption.customer_managed_keys.used == true
    input.cloud.encryption.hsm.available == true
    input.cloud.encryption.key_rotation.automated == true
}

# Cloud database encryption
cloud_database_encryption if {
    input.cloud.databases.encryption_at_rest.enabled == true
    input.cloud.databases.transparent_data_encryption.configured == true
    input.cloud.databases.backup_encryption.enabled == true
    input.cloud.databases.key_management.integrated == true
}

# Cloud storage encryption
cloud_storage_encryption if {
    input.cloud.storage.server_side_encryption.enabled == true
    input.cloud.storage.client_side_encryption.implemented == true
    input.cloud.storage.bucket_encryption["default"] == true
    input.cloud.storage.access_logging.comprehensive == true
}

# =================================================================
# PCI Requirement 3 Overall Assessment
# =================================================================

requirement_3_1_compliant if {
    account_data_protection_policies
    data_protection_roles_defined
    account_data_inventory_maintained
}

requirement_3_2_compliant if {
    data_retention_policy_implemented
    cardholder_data_purging
    sad_post_auth_deletion
    quarterly_data_discovery
}

requirement_3_3_compliant if {
    magnetic_stripe_data_prohibited
    cvc_storage_prohibited
    pin_storage_prohibited
}

requirement_3_4_compliant if {
    pan_display_restricted
    pan_masking_implemented
    screen_protection_implemented
}

requirement_3_5_compliant if {
    pan_encryption_implemented
    database_encryption_implemented
    filesystem_encryption_implemented
}

requirement_3_6_compliant if {
    key_management_policies
    key_generation_standards
    key_distribution_secure
    key_storage_protected
}

requirement_3_7_compliant if {
    crypto_architecture_documented
    crypto_key_administration
    key_lifecycle_management
}

openshift_data_protection_compliant if {
    openshift_secrets_pci_compliant
    container_data_encryption
    openshift_storage_encryption
    container_registry_security
}

cloud_data_protection_compliant if {
    cloud_encryption_services
    cloud_database_encryption
    cloud_storage_encryption
}

pci_requirement_3_compliant if {
    requirement_3_1_compliant
    requirement_3_2_compliant
    requirement_3_3_compliant
    requirement_3_4_compliant
    requirement_3_5_compliant
    requirement_3_6_compliant
    requirement_3_7_compliant
    openshift_data_protection_compliant
    cloud_data_protection_compliant
}

# =================================================================
# PCI Requirement 3 Score Calculation
# =================================================================

pci_requirement_3_score := score if {
    controls := [
        account_data_protection_policies,
        data_protection_roles_defined,
        account_data_inventory_maintained,
        data_retention_policy_implemented,
        cardholder_data_purging,
        sad_post_auth_deletion,
        quarterly_data_discovery,
        magnetic_stripe_data_prohibited,
        cvc_storage_prohibited,
        pin_storage_prohibited,
        pan_display_restricted,
        pan_masking_implemented,
        screen_protection_implemented,
        pan_encryption_implemented,
        database_encryption_implemented,
        filesystem_encryption_implemented,
        key_management_policies,
        key_generation_standards,
        key_distribution_secure,
        key_storage_protected,
        crypto_architecture_documented,
        crypto_key_administration,
        key_lifecycle_management,
        openshift_secrets_pci_compliant,
        container_data_encryption,
        openshift_storage_encryption,
        container_registry_security,
        cloud_encryption_services,
        cloud_database_encryption,
        cloud_storage_encryption
    ]
    
    passed := count([control | control := controls[_]; control == true])
    total := count(controls)
    score := (passed / total) * 100
}

# =================================================================
# PCI Requirement 3 Detailed Findings
# =================================================================

pci_requirement_3_findings := findings if {
    findings := {
        "requirement_3_1": {
            "account_data_protection_policies": account_data_protection_policies,
            "data_protection_roles_defined": data_protection_roles_defined,
            "account_data_inventory_maintained": account_data_inventory_maintained
        },
        "requirement_3_2": {
            "data_retention_policy_implemented": data_retention_policy_implemented,
            "cardholder_data_purging": cardholder_data_purging,
            "sad_post_auth_deletion": sad_post_auth_deletion,
            "quarterly_data_discovery": quarterly_data_discovery
        },
        "requirement_3_3": {
            "magnetic_stripe_data_prohibited": magnetic_stripe_data_prohibited,
            "cvc_storage_prohibited": cvc_storage_prohibited,
            "pin_storage_prohibited": pin_storage_prohibited
        },
        "requirement_3_4": {
            "pan_display_restricted": pan_display_restricted,
            "pan_masking_implemented": pan_masking_implemented,
            "screen_protection_implemented": screen_protection_implemented
        },
        "requirement_3_5": {
            "pan_encryption_implemented": pan_encryption_implemented,
            "database_encryption_implemented": database_encryption_implemented,
            "filesystem_encryption_implemented": filesystem_encryption_implemented
        },
        "requirement_3_6": {
            "key_management_policies": key_management_policies,
            "key_generation_standards": key_generation_standards,
            "key_distribution_secure": key_distribution_secure,
            "key_storage_protected": key_storage_protected
        },
        "requirement_3_7": {
            "crypto_architecture_documented": crypto_architecture_documented,
            "crypto_key_administration": crypto_key_administration,
            "key_lifecycle_management": key_lifecycle_management
        },
        "openshift_controls": {
            "openshift_secrets_pci_compliant": openshift_secrets_pci_compliant,
            "container_data_encryption": container_data_encryption,
            "openshift_storage_encryption": openshift_storage_encryption,
            "container_registry_security": container_registry_security
        },
        "cloud_controls": {
            "cloud_encryption_services": cloud_encryption_services,
            "cloud_database_encryption": cloud_database_encryption,
            "cloud_storage_encryption": cloud_storage_encryption
        },
        "overall_score": pci_requirement_3_score,
        "overall_compliant": pci_requirement_3_compliant
    }
}