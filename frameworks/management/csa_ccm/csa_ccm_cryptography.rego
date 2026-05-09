package csa_ccm.cryptography

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_policy.policy_established
    msg := "CEK-01: Cryptography and key management policy not formally established"
}

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_policy.approved_algorithms_listed
    msg := "CEK-01: Approved cryptographic algorithms not listed in policy — permitted algorithms must be enumerated"
}

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_policy.key_management_procedures_defined
    msg := "CEK-01: Key management procedures not defined within the cryptography policy"
}

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_policy.policy_reviewed_annually
    msg := "CEK-01: Cryptography policy not reviewed at least annually or when cryptographic standards change"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_at_rest.sensitive_data_encrypted
    msg := "CEK-02: Sensitive data not encrypted at rest — data classification must drive encryption requirements"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_at_rest.database_encryption_enabled
    msg := "CEK-02: Database encryption at rest not enabled for databases containing sensitive or regulated data"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_at_rest.storage_encryption_enabled
    msg := "CEK-02: Storage-level encryption not enabled for cloud storage containing sensitive data"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_at_rest.backup_encryption_enabled
    msg := "CEK-02: Backup data not encrypted — backup storage must enforce encryption at rest"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_in_transit.tls_enforced
    msg := "CEK-03: TLS not enforced for data in transit — all network communications must use TLS 1.2 or higher"
}

violations contains msg if {
    input.csa_ccm.cryptography.encryption_in_transit.tls_enforced
    not input.csa_ccm.cryptography.encryption_in_transit.minimum_tls_version_met
    msg := "CEK-03: TLS version below minimum required — TLS 1.2 is the minimum; TLS 1.3 is preferred"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_in_transit.weak_ciphers_disabled
    msg := "CEK-03: Weak cipher suites not disabled — RC4, DES, 3DES, and export ciphers must be disabled"
}

violations contains msg if {
    not input.csa_ccm.cryptography.encryption_in_transit.certificate_validity_enforced
    msg := "CEK-03: Certificate validity not enforced — expired or self-signed certificates must be rejected"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_generation.approved_algorithms_used
    msg := "CEK-04: Key generation does not use approved algorithms — AES-256, RSA-2048+, or ECC-256+ required"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_generation.key_length_meets_standard
    msg := "CEK-04: Cryptographic key length does not meet minimum standards for the algorithm in use"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_generation.random_number_generator_validated
    msg := "CEK-04: Random number generator used for key generation not validated as cryptographically secure"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_generation.weak_keys_prohibited
    msg := "CEK-04: Weak or deprecated key types (MD5, SHA-1 for signing, DSA-1024) not explicitly prohibited"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_storage.hsm_or_equivalent_used
    msg := "CEK-05: Cryptographic keys not protected using HSM or equivalent key management service"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_storage.keys_never_stored_in_plaintext
    msg := "CEK-05: Cryptographic keys stored in plaintext — keys must be encrypted when stored"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_storage.key_access_restricted
    msg := "CEK-05: Access to cryptographic keys not restricted — least-privilege access to keys must be enforced"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_storage.key_access_logged
    msg := "CEK-05: Access to cryptographic keys not logged — all key access must generate an audit record"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_rotation.rotation_schedule_defined
    msg := "CEK-06: Key rotation schedule not defined — rotation frequency must be specified per key type"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_rotation.rotation_enforced
    msg := "CEK-06: Key rotation not enforced per defined schedule — keys must be rotated automatically or with documented process"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_rotation.emergency_rotation_procedure
    msg := "CEK-06: Emergency key rotation procedure not defined for use when compromise is suspected"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_rotation.rotation_logged
    msg := "CEK-06: Key rotation events not logged — rotation history must be maintained for audit"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_destruction.destruction_procedure_defined
    msg := "CEK-07: Key destruction and revocation procedures not defined"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_destruction.destroyed_keys_irrecoverable
    msg := "CEK-07: Key destruction process does not guarantee keys are cryptographically irrecoverable"
}

violations contains msg if {
    not input.csa_ccm.cryptography.key_destruction.revocation_timely
    msg := "CEK-07: Key revocation does not occur within defined timeframe upon suspected compromise or employee departure"
}

violations contains msg if {
    not input.csa_ccm.cryptography.certificate_management.lifecycle_management_implemented
    msg := "CEK-08: Certificate lifecycle management not implemented — issuance, renewal, and revocation must be managed"
}

violations contains msg if {
    not input.csa_ccm.cryptography.certificate_management.expiry_monitoring_enabled
    msg := "CEK-08: Certificate expiry monitoring not enabled — alerts must fire before certificate expiration"
}

violations contains msg if {
    not input.csa_ccm.cryptography.certificate_management.certificate_inventory_maintained
    msg := "CEK-08: Certificate inventory not maintained — all issued certificates must be catalogued"
}

violations contains msg if {
    not input.csa_ccm.cryptography.certificate_management.crl_or_ocsp_implemented
    msg := "CEK-08: Certificate revocation (CRL or OCSP) not implemented and checked by relying parties"
}

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_review.standards_review_process
    msg := "CEK-09: Process not defined for reviewing cryptographic controls when industry standards change"
}

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_review.deprecated_crypto_identified
    msg := "CEK-09: Deprecated or weak cryptographic implementations not proactively identified across the environment"
}

violations contains msg if {
    not input.csa_ccm.cryptography.crypto_review.migration_plan_when_deprecated
    msg := "CEK-09: Migration plan not defined for transitioning away from deprecated cryptographic algorithms"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "CEK — Cryptography, Encryption & Key Management",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
