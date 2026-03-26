package hipaa.integrity

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(c)
# Technical Safeguard: Integrity
#
# Implement policies and procedures to protect ePHI from improper alteration
# or destruction.
#
# Required:   164.312(c)(1) - Integrity controls
# Addressable: 164.312(c)(2) - Mechanism to authenticate ePHI
#
# Input shape:
#   input.phi_systems[]         - systems storing ePHI
#   input.integrity             - integrity control configuration
#   input.transmission          - data in transit controls
#   input.backup                - backup and recovery configuration
# =============================================================================

# ---------------------------------------------------------------------------
# 164.312(c)(1) — Integrity Controls (Required)
# Protect ePHI from improper alteration or destruction
# ---------------------------------------------------------------------------

violation_data_integrity contains msg if {
    some phi_system in input.phi_systems
    not phi_system.integrity_checking_enabled
    msg := sprintf(
        "HIPAA 164.312(c)(1): System '%v' does not have integrity checking enabled for ePHI. File integrity monitoring is required.",
        [phi_system.name]
    )
}

violation_data_integrity contains msg if {
    some phi_system in input.phi_systems
    phi_system.integrity_checking_enabled
    phi_system.integrity_check_frequency_hours > 24
    msg := sprintf(
        "HIPAA 164.312(c)(1): System '%v' integrity checks run every %v hours. Daily or more frequent checks are required for ePHI.",
        [phi_system.name, phi_system.integrity_check_frequency_hours]
    )
}

violation_data_integrity contains msg if {
    not input.integrity.change_management_process
    msg := "HIPAA 164.312(c)(1): No change management process for ePHI systems. Changes must be controlled to prevent unauthorized alteration."
}

violation_data_integrity contains msg if {
    not input.integrity.write_protection_on_archived_phi
    msg := "HIPAA 164.312(c)(1): Archived ePHI is not write-protected. Historical records must be protected from modification."
}

# ---------------------------------------------------------------------------
# 164.312(c)(2) — Mechanism to Authenticate ePHI (Addressable)
# Implement electronic mechanisms to corroborate ePHI has not been altered
# ---------------------------------------------------------------------------

violation_phi_authentication contains msg if {
    not input.integrity.checksum_or_hash_enabled
    msg := "HIPAA 164.312(c)(2): No cryptographic hashing or checksums used for ePHI. Hash-based integrity verification is required."
}

violation_phi_authentication contains msg if {
    input.integrity.checksum_or_hash_enabled
    input.integrity.hash_algorithm in {"MD5", "SHA1"}
    msg := sprintf(
        "HIPAA 164.312(c)(2): Hash algorithm '%v' is cryptographically weak. Use SHA-256 or stronger for ePHI integrity verification.",
        [input.integrity.hash_algorithm]
    )
}

violation_phi_authentication contains msg if {
    not input.integrity.digital_signatures_for_phi_export
    msg := "HIPAA 164.312(c)(2): ePHI exports do not use digital signatures. Signatures provide non-repudiation and integrity assurance."
}

# ---------------------------------------------------------------------------
# Backup and Recovery (supports integrity)
# ---------------------------------------------------------------------------

violation_backup contains msg if {
    not input.backup.regular_backups_enabled
    msg := "HIPAA 164.312(c)(1): Regular backups of ePHI are not configured. Backups are essential for recovery from corruption or destruction."
}

violation_backup contains msg if {
    input.backup.regular_backups_enabled
    input.backup.backup_frequency_hours > 24
    msg := sprintf(
        "HIPAA 164.312(c)(1): ePHI is backed up every %v hours. Daily backups are the recommended minimum.",
        [input.backup.backup_frequency_hours]
    )
}

violation_backup contains msg if {
    not input.backup.offsite_or_cloud_backup
    msg := "HIPAA 164.312(c)(1): ePHI backups are not stored offsite or in cloud. Backups must be protected from site-level disasters."
}

violation_backup contains msg if {
    not input.backup.restore_tested
    msg := "HIPAA 164.312(c)(1): ePHI backup restoration has not been tested. Backups must be verified to ensure recoverability."
}

violation_backup contains msg if {
    input.backup.restore_tested
    input.backup.restore_test_days > 90
    msg := sprintf(
        "HIPAA 164.312(c)(1): ePHI backup restore test is %v days old. Test restoration at least quarterly.",
        [input.backup.restore_test_days]
    )
}

# ---------------------------------------------------------------------------
# Destruction of ePHI
# ---------------------------------------------------------------------------

violation_destruction contains msg if {
    not input.integrity.secure_deletion_policy
    msg := "HIPAA 164.312(c)(1): No secure deletion policy for ePHI. Media containing ePHI must be securely destroyed when no longer needed."
}

violation_destruction contains msg if {
    input.integrity.media_reuse_without_sanitization
    msg := "HIPAA 164.312(c)(1): Media containing ePHI is being reused without sanitization. Media must be sanitized before reuse."
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if { some msg in violation_data_integrity }
violations contains msg if { some msg in violation_phi_authentication }
violations contains msg if { some msg in violation_backup }
violations contains msg if { some msg in violation_destruction }

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

compliant if {
    count(violations) == 0
}

compliance_report := {
    "section":        "164.312(c)",
    "title":          "Integrity",
    "required":       true,
    "compliant":      compliant,
    "violation_count": count(violations),
    "violations":     violations,
    "controls": {
        "data_integrity":       count(violation_data_integrity) == 0,
        "phi_authentication":   count(violation_phi_authentication) == 0,
        "backup_recovery":      count(violation_backup) == 0,
        "secure_destruction":   count(violation_destruction) == 0,
    },
}
