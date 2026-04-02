package iec_62443.fr4

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 4 — Data Confidentiality (DC)
#
# Purpose: Ensure confidentiality of information on communication channels
# and in data repositories used by or within the IACS.
#
# Security Requirements (SRs):
#   SR 4.1 — Information confidentiality
#   SR 4.2 — Information persistence
#   SR 4.3 — Use of cryptography
#
# Input shape:
#   input.target_sl                              - int (1–4)
#   input.ics_systems[]
#     .name                                      - string
#     .sensitive_data_transmitted                - bool
#     .data_encrypted_in_transit                 - bool
#     .data_at_rest_protected                    - bool
#     .media_sanitization_procedure              - bool
#     .approved_cryptographic_algorithms         - bool
#     .cryptographic_key_management              - bool
#     .fips_140_2_compliant                      - bool
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# SR 4.1 — Information confidentiality
# Protect the confidentiality of information at rest and in transit.
# ---------------------------------------------------------------------------

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.sensitive_data_transmitted
    not system.data_encrypted_in_transit
    msg := sprintf(
        "IEC 62443 SR 4.1 SL%v (DC): ICS system '%v' transmits sensitive data without encryption. All sensitive IACS communications must be encrypted in transit at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.data_at_rest_protected
    msg := sprintf(
        "IEC 62443 SR 4.1 SL%v (DC): ICS system '%v' does not protect data at rest. Configuration databases, historian data, and operational data must be encrypted or access-controlled at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

# SR 4.1 RE 1 (SL 3+): Encryption of all IACS data in transit
violations contains msg if {
    input.target_sl >= 3
    some system in input.ics_systems
    not system.data_encrypted_in_transit
    msg := sprintf(
        "IEC 62443 SR 4.1 RE 1 SL%v (DC): ICS system '%v' does not encrypt all communications in transit. At Security Level 3+, all IACS data in transit must be encrypted regardless of sensitivity classification.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.data_encrypted_in_transit
    not system.tls_version_current
    msg := sprintf(
        "IEC 62443 SR 4.1 (DC): ICS system '%v' uses outdated TLS version. TLS 1.2 minimum is required; TLS 1.3 is recommended for IACS communications.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 4.2 — Information persistence
# Protect residual information from leaking through reuse of resources.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.media_sanitization_procedure
    msg := sprintf(
        "IEC 62443 SR 4.2 (DC): ICS system '%v' has no media sanitization procedure. Storage media must be securely sanitized before reuse or disposal to prevent residual data leakage.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.memory_scrubbing_on_deallocation
    msg := sprintf(
        "IEC 62443 SR 4.2 (DC): ICS system '%v' does not clear sensitive data from memory on deallocation. Cryptographic keys, passwords, and process data must be zeroed before memory is released.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.secure_deletion_capability
    msg := sprintf(
        "IEC 62443 SR 4.2 RE 1 SL%v (DC): ICS system '%v' has no secure deletion capability. Overwrite or cryptographic erasure of sensitive data must be available at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 4.3 — Use of cryptography
# Use approved cryptographic algorithms and manage cryptographic keys.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.approved_cryptographic_algorithms
    msg := sprintf(
        "IEC 62443 SR 4.3 (DC): ICS system '%v' does not use approved cryptographic algorithms. Cryptography must be based on vetted algorithms (AES-128+, SHA-256+, RSA-2048+, or NIST-approved equivalents).",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.cryptographic_key_management
    msg := sprintf(
        "IEC 62443 SR 4.3 (DC): ICS system '%v' has no cryptographic key management. Keys must have defined generation, distribution, storage, rotation, and revocation procedures.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 3
    some system in input.ics_systems
    not system.fips_140_2_compliant
    msg := sprintf(
        "IEC 62443 SR 4.3 RE 1 SL%v (DC): ICS system '%v' cryptographic modules are not FIPS 140-2 validated. FIPS 140-2 Level 2+ is required for cryptographic implementations at Security Level 3+.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.cryptographic_key_management
    not system.key_rotation_policy
    msg := sprintf(
        "IEC 62443 SR 4.3 (DC): ICS system '%v' has no key rotation policy. Cryptographic keys must be rotated on a defined schedule and immediately upon suspected compromise.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.uses_deprecated_ciphers
    msg := sprintf(
        "IEC 62443 SR 4.3 (DC): ICS system '%v' uses deprecated cryptographic ciphers (DES, 3DES, RC4, MD5). These must be replaced with currently approved algorithms.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

fr4_passing_srs := count([sr |
    sr := [
        count([v | some v in violations; contains(v, "SR 4.1")]) == 0,
        count([v | some v in violations; contains(v, "SR 4.2")]) == 0,
        count([v | some v in violations; contains(v, "SR 4.3")]) == 0,
    ][_]
    sr == true
])

compliance_report := {
    "foundational_requirement": "FR 4",
    "title":                    "Data Confidentiality (DC)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                3,
    "passing_srs":              fr4_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
