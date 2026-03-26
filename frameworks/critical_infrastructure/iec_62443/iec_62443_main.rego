package iec_62443

import rego.v1

# =============================================================================
# IEC 62443 — Industrial Automation and Control Systems Security
# International standard for OT/ICS cybersecurity
#
# Structure:
#   Part 2-1: Security management system requirements
#   Part 2-4: Security program requirements for IACS service providers
#   Part 3-2: Security risk assessment for system design
#   Part 3-3: System security requirements and security levels
#
# Security Levels (SL):
#   SL 1 — Protection against casual or coincidental violation
#   SL 2 — Protection against intentional violation with simple means
#   SL 3 — Protection against sophisticated attacks
#   SL 4 — Protection against state-sponsored attacks
#
# Foundational Requirements (FR):
#   FR 1 — Identification & Authentication Control (IAC)
#   FR 2 — Use Control (UC)
#   FR 3 — System Integrity (SI)
#   FR 4 — Data Confidentiality (DC)
#   FR 5 — Restricted Data Flow (RDF)
#   FR 6 — Timely Response to Events (TRE)
#   FR 7 — Resource Availability (RA)
#
# Input shape:
#   input.ics_systems[]         - industrial control systems
#   input.zones[]               - network zones/cells
#   input.conduits[]            - communication conduits between zones
#   input.target_sl             - target security level (1-4)
#   input.authentication        - authentication controls
#   input.network               - network controls
#   input.monitoring            - monitoring controls
#   input.patch_management      - patch/update management
# =============================================================================

# ---------------------------------------------------------------------------
# FR 1 — Identification & Authentication Control (IAC)
# ---------------------------------------------------------------------------

violation_fr1 contains msg if {
    some system in input.ics_systems
    not system.unique_identification
    msg := sprintf(
        "IEC 62443 FR1 (IAC): ICS system '%v' does not enforce unique user identification. All users and devices must have unique identifiers.",
        [system.name]
    )
}

violation_fr1 contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.mfa_enabled
    msg := sprintf(
        "IEC 62443 FR1 SL2 (IAC): ICS system '%v' does not enforce multi-factor authentication. MFA is required at Security Level 2+.",
        [system.name]
    )
}

violation_fr1 contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.default_credentials_unchanged
    msg := sprintf(
        "IEC 62443 FR1 SL2 (IAC): ICS system '%v' uses unchanged default credentials. Default credentials are a critical vulnerability in OT environments.",
        [system.name]
    )
}

violation_fr1 contains msg if {
    input.target_sl >= 3
    not input.authentication.pki_or_certificate_based
    msg := "IEC 62443 FR1 SL3 (IAC): PKI or certificate-based authentication is not implemented. Required at Security Level 3+ for strong identity assurance."
}

# ---------------------------------------------------------------------------
# FR 2 — Use Control (UC)
# ---------------------------------------------------------------------------

violation_fr2 contains msg if {
    some system in input.ics_systems
    not system.least_privilege_enforced
    msg := sprintf(
        "IEC 62443 FR2 (UC): ICS system '%v' does not enforce least privilege. Users must only have access required for their function.",
        [system.name]
    )
}

violation_fr2 contains msg if {
    input.target_sl >= 2
    not input.authentication.audit_trail_for_privileged_access
    msg := "IEC 62443 FR2 SL2 (UC): Privileged access is not audited. All privileged operations on ICS must be logged."
}

violation_fr2 contains msg if {
    some system in input.ics_systems
    system.remote_access_enabled
    not system.remote_access_controlled
    msg := sprintf(
        "IEC 62443 FR2 (UC): ICS system '%v' has uncontrolled remote access. Remote access to ICS must be explicitly authorized and controlled.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# FR 3 — System Integrity (SI)
# ---------------------------------------------------------------------------

violation_fr3 contains msg if {
    some system in input.ics_systems
    not system.communication_integrity
    msg := sprintf(
        "IEC 62443 FR3 (SI): ICS system '%v' does not enforce communication integrity. Messages must be protected against unauthorized modification.",
        [system.name]
    )
}

violation_fr3 contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.malware_protection
    not system.application_whitelisting
    msg := sprintf(
        "IEC 62443 FR3 SL2 (SI): ICS system '%v' has no malware protection or application whitelisting. One of these controls is required at SL2.",
        [system.name]
    )
}

violation_fr3 contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.firmware_integrity_checking == false
    msg := sprintf(
        "IEC 62443 FR3 SL2 (SI): ICS system '%v' does not verify firmware integrity. Firmware integrity checking is required at SL2.",
        [system.name]
    )
}

violation_fr3 contains msg if {
    not input.patch_management.process_documented
    msg := "IEC 62443 FR3 (SI): No patch management process for ICS. Security patches must be evaluated and applied in a timely manner."
}

violation_fr3 contains msg if {
    input.patch_management.process_documented
    input.patch_management.max_patch_delay_days > 90
    msg := sprintf(
        "IEC 62443 FR3 (SI): Critical ICS patches are delayed up to %v days. Evaluate and apply critical patches within 30 days.",
        [input.patch_management.max_patch_delay_days]
    )
}

# ---------------------------------------------------------------------------
# FR 4 — Data Confidentiality (DC)
# ---------------------------------------------------------------------------

violation_fr4 contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.sensitive_data_transmitted
    not system.data_encrypted_in_transit
    msg := sprintf(
        "IEC 62443 FR4 SL2 (DC): ICS system '%v' transmits sensitive data without encryption. Encrypt all sensitive ICS communications.",
        [system.name]
    )
}

violation_fr4 contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.data_at_rest_protected
    msg := sprintf(
        "IEC 62443 FR4 SL2 (DC): ICS system '%v' does not protect data at rest. Configuration and operational data must be protected.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# FR 5 — Restricted Data Flow (RDF) — Zone and Conduit Model
# ---------------------------------------------------------------------------

violation_fr5 contains msg if {
    count(input.zones) == 0
    msg := "IEC 62443 FR5 (RDF): No network zones defined. IEC 62443 requires network segmentation using zones and conduits."
}

violation_fr5 contains msg if {
    some zone in input.zones
    not zone.security_level_defined
    msg := sprintf(
        "IEC 62443 FR5 (RDF): Zone '%v' does not have a defined security level. Each zone must have an assigned SL.",
        [zone.name]
    )
}

violation_fr5 contains msg if {
    some conduit in input.conduits
    not conduit.firewall_or_dmz
    msg := sprintf(
        "IEC 62443 FR5 (RDF): Conduit between zones '%v' and '%v' has no firewall or DMZ. All zone boundaries must be protected.",
        [conduit.source_zone, conduit.dest_zone]
    )
}

violation_fr5 contains msg if {
    some conduit in input.conduits
    conduit.source_zone == "corporate_it"
    conduit.dest_zone == "ics_control"
    not conduit.unidirectional_gateway
    msg := "IEC 62443 FR5 (RDF): IT/OT boundary between corporate and ICS control zone lacks a unidirectional gateway (data diode). This is a critical segmentation requirement."
}

violation_fr5 contains msg if {
    not input.network.it_ot_segmentation
    msg := "IEC 62443 FR5 (RDF): IT and OT networks are not segmented. Industrial control systems must be isolated from corporate IT networks."
}

violation_fr5 contains msg if {
    input.network.direct_internet_connectivity_to_ics
    msg := "IEC 62443 FR5 (RDF): ICS systems have direct Internet connectivity. ICS must not be directly Internet-accessible."
}

# ---------------------------------------------------------------------------
# FR 6 — Timely Response to Events (TRE)
# ---------------------------------------------------------------------------

violation_fr6 contains msg if {
    some system in input.ics_systems
    not system.audit_logging_enabled
    msg := sprintf(
        "IEC 62443 FR6 (TRE): ICS system '%v' does not have audit logging enabled. Security events must be logged for timely response.",
        [system.name]
    )
}

violation_fr6 contains msg if {
    not input.monitoring.security_event_monitoring
    msg := "IEC 62443 FR6 (TRE): No security event monitoring for ICS. Real-time monitoring is required to enable timely response to incidents."
}

violation_fr6 contains msg if {
    not input.monitoring.incident_response_plan_for_ics
    msg := "IEC 62443 FR6 (TRE): No ICS-specific incident response plan. OT/ICS incidents require specialized response procedures distinct from IT IR plans."
}

violation_fr6 contains msg if {
    input.monitoring.ics_log_retention_days < 90
    msg := sprintf(
        "IEC 62443 FR6 (TRE): ICS audit logs are retained for only %v days. Retain ICS security logs for at least 90 days.",
        [input.monitoring.ics_log_retention_days]
    )
}

# ---------------------------------------------------------------------------
# FR 7 — Resource Availability (RA)
# ---------------------------------------------------------------------------

violation_fr7 contains msg if {
    some system in input.ics_systems
    not system.high_availability_configured
    system.criticality == "high"
    msg := sprintf(
        "IEC 62443 FR7 (RA): High-criticality ICS system '%v' does not have high availability configured. Redundancy is required for critical systems.",
        [system.name]
    )
}

violation_fr7 contains msg if {
    not input.monitoring.dos_protection
    msg := "IEC 62443 FR7 (RA): No DoS protection for ICS network. ICS systems must be protected against denial-of-service attacks."
}

violation_fr7 contains msg if {
    not input.patch_management.tested_before_deployment
    msg := "IEC 62443 FR7 (RA): ICS patches are not tested before deployment. Untested patches can cause availability failures in critical systems."
}

# ---------------------------------------------------------------------------
# IACS Service Provider Requirements (Part 2-4)
# ---------------------------------------------------------------------------

violation_service_provider contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.security_program_documented
    msg := "IEC 62443-2-4: IACS service provider has no documented security program. Service providers must have a formal security management program."
}

violation_service_provider contains msg if {
    input.is_iacs_service_provider == true
    not input.service_provider.customer_security_requirements_reviewed
    msg := "IEC 62443-2-4: IACS service provider has not reviewed customer security requirements. Provider must align with customer security requirements."
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

all_violations := array.concat(
    array.concat(
        [v | some v in violation_fr1],
        [v | some v in violation_fr2]
    ),
    array.concat(
        array.concat(
            [v | some v in violation_fr3],
            [v | some v in violation_fr4]
        ),
        array.concat(
            array.concat(
                [v | some v in violation_fr5],
                [v | some v in violation_fr6]
            ),
            array.concat(
                [v | some v in violation_fr7],
                [v | some v in violation_service_provider]
            )
        )
    )
)

iec_62443_compliant if { count(all_violations) == 0 }

passing_requirements := count([fr |
    fr := [
        count(violation_fr1) == 0,
        count(violation_fr2) == 0,
        count(violation_fr3) == 0,
        count(violation_fr4) == 0,
        count(violation_fr5) == 0,
        count(violation_fr6) == 0,
        count(violation_fr7) == 0,
    ][_]
    fr == true
])

compliance_score := round((passing_requirements / 7) * 100)

iec_62443_compliance_report := {
    "standard":         "IEC 62443",
    "full_title":       "Industrial Automation and Control Systems Security",
    "target_sl":        input.target_sl,
    "compliant":        iec_62443_compliant,
    "compliance_score": compliance_score,
    "total_violations": count(all_violations),
    "violations":       all_violations,
    "foundational_requirements": {
        "FR1_identification_authentication": {
            "compliant": count(violation_fr1) == 0,
            "violations": violation_fr1,
        },
        "FR2_use_control": {
            "compliant": count(violation_fr2) == 0,
            "violations": violation_fr2,
        },
        "FR3_system_integrity": {
            "compliant": count(violation_fr3) == 0,
            "violations": violation_fr3,
        },
        "FR4_data_confidentiality": {
            "compliant": count(violation_fr4) == 0,
            "violations": violation_fr4,
        },
        "FR5_restricted_data_flow": {
            "compliant": count(violation_fr5) == 0,
            "violations": violation_fr5,
        },
        "FR6_timely_response": {
            "compliant": count(violation_fr6) == 0,
            "violations": violation_fr6,
        },
        "FR7_resource_availability": {
            "compliant": count(violation_fr7) == 0,
            "violations": violation_fr7,
        },
    },
}
