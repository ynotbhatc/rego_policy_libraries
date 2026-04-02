package iec_62443.fr2

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 2 — Use Control (UC)
#
# Purpose: Enforce authorized use of the IACS by ensuring that only authorized
# actions are permitted and that all actions by authenticated users are audited.
#
# Security Requirements (SRs):
#   SR 2.1  — Authorization enforcement
#   SR 2.2  — Wireless use control
#   SR 2.3  — Use control for portable and mobile devices
#   SR 2.4  — Mobile code
#   SR 2.5  — Session lock
#   SR 2.6  — Remote session termination
#   SR 2.7  — Concurrent session control
#   SR 2.8  — Auditable events
#   SR 2.9  — Audit storage capacity
#   SR 2.10 — Response to audit processing failures
#   SR 2.11 — Timestamps
#   SR 2.12 — Non-repudiation
#
# Input shape:
#   input.target_sl                          - int (1–4)
#   input.ics_systems[]
#     .name                                  - string
#     .least_privilege_enforced              - bool
#     .remote_access_enabled                 - bool
#     .remote_access_controlled              - bool
#     .wireless_access                       - bool
#     .portable_device_policy                - bool
#     .mobile_code_controlled                - bool
#     .session_lock_timeout_minutes          - int
#     .concurrent_session_limit              - int
#     .audit_logging_enabled                 - bool
#     .non_repudiation_enabled               - bool
#   input.authentication
#     .audit_trail_for_privileged_access     - bool
#   input.monitoring
#     .audit_storage_adequate                - bool
#     .audit_processing_failure_alerts       - bool
#     .timestamps_synchronized               - bool
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# SR 2.1 — Authorization enforcement
# Enforce assigned authorizations; deny access by default (least privilege).
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.least_privilege_enforced
    msg := sprintf(
        "IEC 62443 SR 2.1 (UC): ICS system '%v' does not enforce least privilege. Users must only have the access rights required to perform their authorized functions.",
        [system.name]
    )
}

violations contains msg if {
    not input.authentication.audit_trail_for_privileged_access
    msg := "IEC 62443 SR 2.1 (UC): Privileged access is not audited. All privileged actions on IACS must generate an audit record."
}

# SR 2.1 RE 1 (SL 2+): Separate permission levels for different roles
violations contains msg if {
    input.target_sl >= 2
    not input.authentication.role_based_access_control
    msg := sprintf(
        "IEC 62443 SR 2.1 RE 1 SL%v (UC): Role-based access control (RBAC) is not implemented. Separate authorization roles are required at Security Level 2+.",
        [input.target_sl]
    )
}

# SR 2.1 RE 2 (SL 3+): Dual approval for high-impact actions
violations contains msg if {
    input.target_sl >= 3
    not input.authentication.dual_approval_for_critical_actions
    msg := sprintf(
        "IEC 62443 SR 2.1 RE 2 SL%v (UC): No dual-approval mechanism for high-impact IACS actions. Required at Security Level 3+ for critical system changes.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 2.2 — Wireless use control
# Authorize, monitor, and restrict wireless use in the IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.wireless_access == true
    not system.wireless_use_authorized
    msg := sprintf(
        "IEC 62443 SR 2.2 (UC): Wireless use on ICS system '%v' is not explicitly authorized. All wireless connections must be documented and approved.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.wireless_access == true
    not system.wireless_monitored
    msg := sprintf(
        "IEC 62443 SR 2.2 (UC): Wireless connections on ICS system '%v' are not monitored. Wireless activity must be continuously monitored for unauthorized access.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 2.3 — Use control for portable and mobile devices
# Enforce security controls on portable and mobile devices connected to IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.portable_device_policy
    msg := sprintf(
        "IEC 62443 SR 2.3 (UC): ICS system '%v' has no portable/mobile device use policy. USB drives, laptops, and tablets connecting to IACS must be governed by a formal policy.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.removable_media_controlled
    msg := sprintf(
        "IEC 62443 SR 2.3 (UC): ICS system '%v' does not control removable media. Removable media must be scanned for malware before use and restricted to authorized devices.",
        [system.name]
    )
}

# SR 2.3 RE 1 (SL 2+): Central management of portable device authorizations
violations contains msg if {
    input.target_sl >= 2
    not input.authentication.portable_device_central_mgmt
    msg := sprintf(
        "IEC 62443 SR 2.3 RE 1 SL%v (UC): Portable device authorizations are not centrally managed. Centralized control is required at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 2.4 — Mobile code
# Control mobile code (scripts, macros, executables) executed in the IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.mobile_code_controlled
    msg := sprintf(
        "IEC 62443 SR 2.4 (UC): ICS system '%v' does not control mobile code execution. Scripts, active content, and macros must be restricted to explicitly authorized code.",
        [system.name]
    )
}

# SR 2.4 RE 1 (SL 2+): Application whitelisting
violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.application_whitelisting
    not system.malware_protection
    msg := sprintf(
        "IEC 62443 SR 2.4 RE 1 SL%v (UC): ICS system '%v' has neither application whitelisting nor malware protection. One of these is required at Security Level 2+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 2.5 — Session lock
# Automatically lock sessions after a period of inactivity.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.session_lock_timeout_minutes > 30
    msg := sprintf(
        "IEC 62443 SR 2.5 (UC): ICS system '%v' session lock timeout is %v minutes. Maximum inactivity timeout before lock must be 30 minutes or less.",
        [system.name, system.session_lock_timeout_minutes]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.session_lock_timeout_minutes > 15
    msg := sprintf(
        "IEC 62443 SR 2.5 RE 1 SL%v (UC): ICS system '%v' session lock timeout is %v minutes. Maximum 15 minutes is required at Security Level 2+.",
        [input.target_sl, system.name, system.session_lock_timeout_minutes]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.session_lock_enabled
    msg := sprintf(
        "IEC 62443 SR 2.5 (UC): ICS system '%v' does not enforce session locking. Automatic session lock after inactivity is required.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 2.6 — Remote session termination
# Provide the capability to terminate remote sessions.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    system.remote_access_enabled
    not system.remote_session_termination
    msg := sprintf(
        "IEC 62443 SR 2.6 (UC): ICS system '%v' does not support remote session termination. Authorized users must be able to terminate remote sessions at any time.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 2.7 — Concurrent session control
# Limit the number of concurrent sessions per user or device.
# ---------------------------------------------------------------------------

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    system.concurrent_session_limit == 0
    msg := sprintf(
        "IEC 62443 SR 2.7 SL%v (UC): ICS system '%v' has no concurrent session limit. Limiting concurrent sessions reduces the risk of session hijacking.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    input.target_sl >= 3
    some system in input.ics_systems
    system.concurrent_session_limit > 3
    msg := sprintf(
        "IEC 62443 SR 2.7 RE 1 SL%v (UC): ICS system '%v' allows up to %v concurrent sessions. Strict session limits (≤3) are recommended at Security Level 3+.",
        [input.target_sl, system.name, system.concurrent_session_limit]
    )
}

# ---------------------------------------------------------------------------
# SR 2.8 — Auditable events
# Generate audit records for defined security-relevant events.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.audit_logging_enabled
    msg := sprintf(
        "IEC 62443 SR 2.8 (UC): ICS system '%v' does not have audit logging enabled. Security-relevant events must be logged: login attempts, privilege use, configuration changes, and errors.",
        [system.name]
    )
}

violations contains msg if {
    some system in input.ics_systems
    system.audit_logging_enabled
    not system.audit_log_includes_required_fields
    msg := sprintf(
        "IEC 62443 SR 2.8 (UC): ICS system '%v' audit logs are missing required fields. Logs must include: event type, timestamp, source identity, outcome, and affected resource.",
        [system.name]
    )
}

# SR 2.8 RE 1 (SL 2+): Centralized audit log collection
violations contains msg if {
    input.target_sl >= 2
    not input.monitoring.centralized_log_collection
    msg := sprintf(
        "IEC 62443 SR 2.8 RE 1 SL%v (UC): Audit logs are not centrally collected. Centralized log aggregation is required at Security Level 2+ to enable correlation.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 2.9 — Audit storage capacity
# Allocate sufficient storage for audit records.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.monitoring.audit_storage_adequate
    msg := "IEC 62443 SR 2.9 (UC): Audit log storage capacity is insufficient. The system must allocate sufficient storage and alert when approaching capacity limits."
}

violations contains msg if {
    input.monitoring.ics_log_retention_days < 90
    msg := sprintf(
        "IEC 62443 SR 2.9 (UC): IACS audit logs are retained for only %v days. Minimum 90-day retention is required (1 year recommended for regulatory compliance).",
        [input.monitoring.ics_log_retention_days]
    )
}

# ---------------------------------------------------------------------------
# SR 2.10 — Response to audit processing failures
# Alert and respond when audit processing failures occur.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.monitoring.audit_processing_failure_alerts
    msg := "IEC 62443 SR 2.10 (UC): No alerting for audit processing failures. The system must alert personnel when audit subsystem failures occur (storage full, process crash, etc.)."
}

violations contains msg if {
    not input.monitoring.audit_failure_response_defined
    msg := "IEC 62443 SR 2.10 (UC): No defined response procedure for audit processing failures. A documented response procedure is required."
}

# ---------------------------------------------------------------------------
# SR 2.11 — Timestamps
# Provide reliable timestamps for all audit records.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.monitoring.timestamps_synchronized
    msg := "IEC 62443 SR 2.11 (UC): IACS timestamps are not synchronized. All systems must use a reliable time source (NTP/PTP) to ensure audit record integrity."
}

violations contains msg if {
    some system in input.ics_systems
    system.audit_logging_enabled
    not system.ntp_configured
    msg := sprintf(
        "IEC 62443 SR 2.11 (UC): ICS system '%v' does not have NTP configured. Accurate timestamps are required for audit trail integrity and incident correlation.",
        [system.name]
    )
}

# ---------------------------------------------------------------------------
# SR 2.12 — Non-repudiation
# Ensure actions cannot be repudiated by the originator.
# ---------------------------------------------------------------------------

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.non_repudiation_enabled
    msg := sprintf(
        "IEC 62443 SR 2.12 SL%v (UC): ICS system '%v' does not provide non-repudiation. Cryptographic signing or equivalent mechanism is required at Security Level 2+ for critical actions.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

fr2_passing_srs := count([sr |
    sr := [
        count([v | some v in violations; contains(v, "SR 2.1")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.2")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.3")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.4")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.5")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.6")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.7")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.8")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.9")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.10")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.11")]) == 0,
        count([v | some v in violations; contains(v, "SR 2.12")]) == 0,
    ][_]
    sr == true
])

compliance_report := {
    "foundational_requirement": "FR 2",
    "title":                    "Use Control (UC)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                12,
    "passing_srs":              fr2_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
