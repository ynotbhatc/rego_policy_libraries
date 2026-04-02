package iec_62443.fr3

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 3 — System Integrity (SI)
#
# Purpose: Ensure the integrity of the IACS by protecting against unauthorized
# modification of hardware, software, and data in transit and at rest.
#
# Security Requirements (SRs):
#   SR 3.1 — Communication integrity
#   SR 3.2 — Malicious code protection
#   SR 3.3 — Security functionality verification
#   SR 3.4 — Software and information integrity
#   SR 3.5 — Input validation
#   SR 3.6 — Deterministic output
#   SR 3.7 — Error handling
#   SR 3.8 — Session integrity
#   SR 3.9 — Protection of audit information
#
# Input shape:
#   input.target_sl                              - int (1–4)
#   input.ics_systems[]
#     .name                                      - string
#     .communication_integrity                   - bool
#     .malware_protection                        - bool
#     .application_whitelisting                  - bool
#     .firmware_integrity_checking               - bool
#     .software_integrity_verification           - bool
#     .input_validation                          - bool
#     .deterministic_output_verification         - bool
#     .error_handling_implemented                - bool
#     .session_integrity                         - bool
#     .audit_log_tamper_protection               - bool
#     .os_version_current                        - bool
#   input.patch_management
#     .process_documented                        - bool
#     .max_patch_delay_days                      - int
#     .tested_before_deployment                  - bool
#     .rollback_capability                       - bool
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# SR 3.1 — Communication integrity
# Protect the integrity of transmitted information.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.communication_integrity
    msg := sprintf(
        "IEC 62443 SR 3.1 (SI): ICS system '%v' does not protect communication integrity. IACS communications must use mechanisms (checksums, MACs, digital signatures) to detect unauthorized modification.",
        [system.name]
    )
}

# SR 3.1 RE 1 (SL 2+): Cryptographic integrity protection
violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.cryptographic_integrity_protection
    msg := sprintf(
        "IEC 62443 SR 3.1 RE 1 SL%v (SI): ICS system '%v' does not use cryptographic mechanisms for communication integrity. HMAC or digital signatures are required at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 3.2 — Malicious code protection
# Protect against malware and unauthorized software.
# ---------------------------------------------------------------------------

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.malware_protection
    not system.application_whitelisting
    msg := sprintf(
        "IEC 62443 SR 3.2 SL%v (SI): ICS system '%v' has neither malware protection nor application whitelisting. One of these controls is required at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.malware_protection
    not system.malware_definitions_current
    msg := sprintf(
        "IEC 62443 SR 3.2 (SI): ICS system '%v' malware definitions are not current. Malware signatures must be updated at least weekly, or more frequently if the system is Internet-connected.",
        [system.name]
    )
}

# SR 3.2 RE 1 (SL 3+): Malware protection at all entry points
violations contains msg if {
    input.target_sl >= 3
    not input.network.malware_protection_at_boundaries
    msg := sprintf(
        "IEC 62443 SR 3.2 RE 1 SL%v (SI): Malware protection is not deployed at all IACS network entry points. Boundary-level malware scanning is required at Security Level 3+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 3.3 — Security functionality verification
# Verify that security functions operate correctly.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.security_function_testing
    msg := sprintf(
        "IEC 62443 SR 3.3 (SI): ICS system '%v' has no security function verification process. Security controls must be periodically tested to confirm they operate as intended.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    not input.security_management.security_testing_schedule_documented
    msg := sprintf(
        "IEC 62443 SR 3.3 RE 1 SL%v (SI): No documented schedule for security function verification. A formal testing schedule is required at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 3.4 — Software and information integrity
# Detect unauthorized changes to software and data.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.software_integrity_verification
    msg := sprintf(
        "IEC 62443 SR 3.4 (SI): ICS system '%v' does not verify software integrity. File integrity monitoring or hash verification must be implemented to detect unauthorized changes.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.firmware_integrity_checking == false
    msg := sprintf(
        "IEC 62443 SR 3.4 (SI): ICS system '%v' does not verify firmware integrity. Firmware must be verified against known-good hashes before and after updates.",
        [system.name]
    )
}

violations contains msg if {
    not input.patch_management.process_documented
    msg := "IEC 62443 SR 3.4 (SI): No patch management process documented. Security patches for IACS components must be evaluated and applied through a controlled process."
}

violations contains msg if {
    input.patch_management.process_documented
    input.patch_management.max_patch_delay_days > 90
    msg := sprintf(
        "IEC 62443 SR 3.4 (SI): Critical IACS patches are delayed up to %v days. Critical security patches must be evaluated within 30 days and applied within 90 days.",
        [input.patch_management.max_patch_delay_days]
    )
}

# SR 3.4 RE 1 (SL 2+): Automated integrity checking
violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.automated_integrity_checking
    msg := sprintf(
        "IEC 62443 SR 3.4 RE 1 SL%v (SI): ICS system '%v' lacks automated integrity checking. Automated file integrity monitoring is required at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 3.5 — Input validation
# Validate input to protect against injection and malformed data attacks.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.input_validation
    msg := sprintf(
        "IEC 62443 SR 3.5 (SI): ICS system '%v' does not validate inputs. All external inputs (HMI, APIs, data feeds) must be validated to prevent injection attacks and unexpected behavior.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 3.6 — Deterministic output
# Ensure outputs remain within expected ranges under all conditions.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.deterministic_output_verification
    msg := sprintf(
        "IEC 62443 SR 3.6 (SI): ICS system '%v' does not enforce output range checking. Control outputs must remain within safe operational bounds even under error or attack conditions.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 3.7 — Error handling
# Handle errors without exposing sensitive information or failing unsafely.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.error_handling_implemented
    msg := sprintf(
        "IEC 62443 SR 3.7 (SI): ICS system '%v' does not implement secure error handling. Errors must not expose sensitive information and must fail to a known safe state.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.error_messages_expose_sensitive_data
    msg := sprintf(
        "IEC 62443 SR 3.7 (SI): ICS system '%v' error messages expose sensitive system information. Error messages must be sanitized before display to operators.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 3.8 — Session integrity
# Protect the integrity of active sessions against hijacking and replay.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.session_integrity
    msg := sprintf(
        "IEC 62443 SR 3.8 (SI): ICS system '%v' does not protect session integrity. Session tokens must be cryptographically protected against hijacking and replay attacks.",
        [system.name]
    )
}

# SR 3.8 RE 1 (SL 2+): Invalidate sessions on privilege change
violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.session_invalidated_on_privilege_change
    msg := sprintf(
        "IEC 62443 SR 3.8 RE 1 SL%v (SI): ICS system '%v' does not invalidate sessions when privileges change. Sessions must be re-established after any privilege modification.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 3.9 — Protection of audit information
# Protect audit records from unauthorized access, modification, and deletion.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.audit_log_tamper_protection
    msg := sprintf(
        "IEC 62443 SR 3.9 (SI): ICS system '%v' audit logs are not tamper-protected. Audit records must be write-protected and access-controlled to preserve their evidential value.",
        [system.name]
    )
}

violations contains msg if {
    not input.monitoring.log_access_controlled
    msg := "IEC 62443 SR 3.9 (SI): IACS audit log access is not controlled. Only authorized personnel should be able to read audit logs; no one should be able to modify or delete them."
}

violations contains msg if {
    input.target_sl >= 2
    not input.monitoring.logs_sent_to_immutable_store
    msg := sprintf(
        "IEC 62443 SR 3.9 RE 1 SL%v (SI): Audit logs are not forwarded to an immutable store. Write-once log forwarding (SIEM, syslog-ng with WORM storage) is required at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

fr3_passing_srs := count([sr |
    sr := [
        count([v | some v in violations; contains(v, "SR 3.1")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.2")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.3")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.4")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.5")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.6")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.7")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.8")]) == 0,
        count([v | some v in violations; contains(v, "SR 3.9")]) == 0,
    ][_]
    sr == true
])

compliance_report := {
    "foundational_requirement": "FR 3",
    "title":                    "System Integrity (SI)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                9,
    "passing_srs":              fr3_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
