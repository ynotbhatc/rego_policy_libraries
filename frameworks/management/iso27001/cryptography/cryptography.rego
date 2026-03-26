package iso27001.cryptography

import rego.v1

# ISO 27001:2022 - A.10 Cryptography
# Technical controls for cryptographic information protection

# A.10.1 - Cryptographic controls
cryptographic_controls if {
    # A.10.1.1 - Policy on the use of cryptographic controls
    cryptographic_policy
    
    # A.10.1.2 - Key management
    key_management
}

# A.10.1.1 - Policy on the use of cryptographic controls
cryptographic_policy if {
    input.cryptography.policy.documented == true
    input.cryptography.policy.approved == true
    input.cryptography.policy.communicated == true
    input.cryptography.policy.regularly_reviewed == true
    
    # Policy should specify approved algorithms
    count(input.cryptography.policy.approved_algorithms) > 0
    
    # Policy should address key management
    input.cryptography.policy.key_management_addressed == true
    
    # Policy should specify encryption requirements
    input.cryptography.policy.encryption_requirements == true
}

# A.10.1.2 - Key management
key_management if {
    # Key generation requirements
    key_generation_secure
    
    # Key distribution and storage
    key_distribution_secure
    
    # Key usage and rotation
    key_usage_controlled
    
    # Key destruction
    key_destruction_secure
}

# Secure key generation
key_generation_secure if {
    input.key_management.generation.random_source_secure == true
    input.key_management.generation.approved_algorithms == true
    input.key_management.generation.sufficient_entropy == true
    input.key_management.generation.documented_process == true
    
    # Key specifications should be properly configured
    count(input.key_management.key_specifications) > 0
}

# Minimum key lengths based on algorithm
minimum_key_length(algorithm) := 2048 if {
    algorithm == "RSA"
}

minimum_key_length(algorithm) := 256 if {
    algorithm == "AES"
}

minimum_key_length(algorithm) := 256 if {
    algorithm == "ECC"
}

minimum_key_length(algorithm) := 160 if {
    algorithm == "SHA"
}

minimum_key_length(_) := 128  # Default minimum

# Secure key distribution and storage
key_distribution_secure if {
    input.key_management.distribution.encrypted_channels == true
    input.key_management.distribution.authentication_required == true
    input.key_management.distribution.integrity_protected == true
    
    input.key_management.storage.hardware_security_modules == true
    input.key_management.storage.access_controlled == true
    input.key_management.storage.audit_logged == true
    input.key_management.storage.backup_encrypted == true
}

# Controlled key usage and rotation
key_usage_controlled if {
    input.key_management.usage.purpose_specific == true
    input.key_management.usage.access_restricted == true
    input.key_management.usage.audit_logged == true
    
    input.key_management.rotation.regular_schedule == true
    input.key_management.rotation.automated_process == true
    input.key_management.rotation.emergency_procedures == true
    
    # Rotation should occur at least annually
    input.key_management.rotation.max_lifetime_days <= 365
}

# Secure key destruction
key_destruction_secure if {
    input.key_management.destruction.secure_deletion == true
    input.key_management.destruction.verification_required == true
    input.key_management.destruction.documented_process == true
    input.key_management.destruction.audit_logged == true
}

# Data encryption requirements
data_encryption if {
    # Data at rest encryption
    data_at_rest_encrypted
    
    # Data in transit encryption
    data_in_transit_encrypted
    
    # Database encryption
    database_encryption_enabled
    
    # Backup encryption
    backup_encryption_enabled
}

# Data at rest encryption
data_at_rest_encrypted if {
    input.encryption.data_at_rest.enabled == true
    input.encryption.data_at_rest.strong_algorithms == true
    input.encryption.data_at_rest.key_management_integrated == true
    
    # File system encryption
    input.encryption.filesystem.full_disk_encryption == true
    input.encryption.filesystem.secure_boot == true
    
    # Application data encryption
    input.encryption.application_data.sensitive_fields == true
    input.encryption.application_data.configuration_files == true
}

# Data in transit encryption
data_in_transit_encrypted if {
    input.encryption.data_in_transit.tls_enforced == true
    input.encryption.data_in_transit.minimum_tls_version >= "1.2"
    input.encryption.data_in_transit.certificate_validation == true
    input.encryption.data_in_transit.perfect_forward_secrecy == true
    
    # Network protocols encryption
    network_protocols_secure
    
    # API encryption
    api_encryption_enforced
}

# Secure network protocols
network_protocols_secure if {
    # SSH configuration
    input.network.ssh.protocol_version >= 2
    input.network.ssh.strong_ciphers == true
    input.network.ssh.key_based_auth == true
    
    # HTTPS enforcement
    input.network.https.enforced == true
    input.network.https.hsts_enabled == true
    input.network.https.secure_cookies == true
    
    # VPN encryption
    input.network.vpn.strong_encryption == true
    input.network.vpn.certificate_based == true
}

# API encryption enforcement
api_encryption_enforced if {
    input.api.tls_required == true
    input.api.token_encryption == true
    input.api.payload_encryption == true
    input.api.certificate_pinning == true
}

# Database encryption
database_encryption_enabled if {
    input.database.encryption.at_rest == true
    input.database.encryption.in_transit == true
    input.database.encryption.key_rotation == true
    input.database.encryption.transparent_encryption == true
    
    # Connection encryption
    input.database.connections.ssl_required == true
    input.database.connections.certificate_validation == true
}

# Backup encryption
backup_encryption_enabled if {
    input.backup.encryption.enabled == true
    input.backup.encryption.separate_keys == true
    input.backup.encryption.key_escrow == true
    input.backup.encryption.integrity_verification == true
}

# Digital signatures and certificates
digital_signatures if {
    # Certificate management
    certificate_management_secure
    
    # Digital signature usage
    digital_signature_implementation
    
    # Public Key Infrastructure (PKI)
    pki_implementation
}

# Secure certificate management
certificate_management_secure if {
    input.certificates.trusted_ca_only == true
    input.certificates.regular_renewal == true
    input.certificates.revocation_checking == true
    input.certificates.secure_storage == true
    
    # Certificate lifecycle management
    input.certificates.lifecycle.automated_renewal == true
    input.certificates.lifecycle.expiry_monitoring == true
    input.certificates.lifecycle.secure_generation == true
}

# Digital signature implementation
digital_signature_implementation if {
    input.digital_signatures.code_signing == true
    input.digital_signatures.document_signing == true
    input.digital_signatures.timestamp_verification == true
    input.digital_signatures.non_repudiation == true
}

# PKI implementation
pki_implementation if {
    input.pki.certificate_authority.trusted == true
    input.pki.certificate_authority.audited == true
    input.pki.certificate_policies.documented == true
    input.pki.certificate_revocation.crl_available == true
    input.pki.certificate_revocation.ocsp_enabled == true
}

# Cryptographic algorithm compliance
algorithm_compliance if {
    # Only approved algorithms should be used
    count(input.cryptography.algorithms_in_use) > 0
    count(input.cryptography.approved_algorithms) > 0
    
    # Weak algorithms should be disabled
    weak_algorithms_disabled
    
    # Quantum-resistant considerations
    quantum_resistance_planned
}

# Weak algorithms disabled
weak_algorithms_disabled if {
    weak_algorithms := ["MD5", "SHA1", "DES", "3DES", "RC4", "SSL", "TLS1.0", "TLS1.1"]
    
    # Check no weak algorithms are in use (simplified check)
    count([alg | alg := input.cryptography.algorithms_in_use[_]; alg in weak_algorithms]) == 0
}

# Quantum resistance planning
quantum_resistance_planned if {
    input.cryptography.quantum_resistance.assessment_completed == true
    input.cryptography.quantum_resistance.migration_plan == true
    input.cryptography.quantum_resistance.timeline_defined == true
}

# Hardware Security Module (HSM) usage
hsm_usage if {
    input.hsm.available == true
    input.hsm.key_generation == true
    input.hsm.key_storage == true
    input.hsm.cryptographic_operations == true
    input.hsm.tamper_protection == true
    input.hsm.fips_140_2_level >= 2
}

# Overall cryptography compliance
compliant if {
    cryptographic_controls
    data_encryption
    digital_signatures
    algorithm_compliance
}

# Detailed compliance reporting
compliance_details := {
    "cryptographic_policy": cryptographic_policy,
    "key_management": {
        "generation": key_generation_secure,
        "distribution_storage": key_distribution_secure,
        "usage_rotation": key_usage_controlled,
        "destruction": key_destruction_secure
    },
    "data_encryption": {
        "at_rest": data_at_rest_encrypted,
        "in_transit": data_in_transit_encrypted,
        "database": database_encryption_enabled,
        "backup": backup_encryption_enabled
    },
    "digital_signatures": {
        "certificate_management": certificate_management_secure,
        "signature_implementation": digital_signature_implementation,
        "pki": pki_implementation
    },
    "algorithm_compliance": {
        "approved_only": algorithm_compliance,
        "weak_disabled": weak_algorithms_disabled,
        "quantum_ready": quantum_resistance_planned
    },
    "hsm_usage": hsm_usage,
    "overall_compliant": compliant
}