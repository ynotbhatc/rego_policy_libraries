package iec_62443.fr6

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 6 — Timely Response to Events (TRE)
#
# Purpose: Respond to security violations and incidents in a timely manner.
# This includes detecting incidents, generating notifications, and providing
# the capability to report violations to appropriate personnel.
#
# Security Requirements (SRs):
#   SR 6.1 — Audit log accessibility
#   SR 6.2 — Continuous monitoring
#
# Input shape:
#   input.target_sl                              - int (1–4)
#   input.ics_systems[]
#     .name                                      - string
#     .audit_logging_enabled                     - bool
#   input.monitoring
#     .security_event_monitoring                 - bool
#     .incident_response_plan_for_ics            - bool
#     .ics_log_retention_days                    - int
#     .continuous_monitoring                     - bool
#     .log_access_controlled                     - bool
#     .automated_alerts_configured               - bool
#     .mean_time_to_detect_hours                 - number
#     .mean_time_to_respond_hours                - number
#     .threat_intelligence_integrated            - bool
#     .ics_specific_soc_capability               - bool
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# SR 6.1 — Audit log accessibility
# Ensure audit logs are accessible to authorized personnel in a timely manner.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.monitoring.log_access_controlled
    msg := "IEC 62443 SR 6.1 (TRE): IACS audit log access is not controlled. Logs must be accessible to authorized security and operations personnel while protected against unauthorized access."
}

violations contains msg if {
    input.monitoring.ics_log_retention_days < 90
    msg := sprintf(
        "IEC 62443 SR 6.1 (TRE): IACS audit logs are retained for only %v days. Minimum 90-day retention is required to support incident investigations (1 year recommended for regulatory environments).",
        [input.monitoring.ics_log_retention_days]
    )
}

violations contains msg if {
    some system in input.ics_systems
    not system.audit_logging_enabled
    msg := sprintf(
        "IEC 62443 SR 6.1 (TRE): ICS system '%v' does not have audit logging enabled. Security event logs are required to enable timely detection and response.",
        [system.name]
    )
}

violations contains msg if {
    not input.monitoring.incident_response_plan_for_ics
    msg := "IEC 62443 SR 6.1 (TRE): No ICS-specific incident response plan. OT/ICS incidents require specialized response procedures distinct from IT IR plans — a documented plan is required."
}

# SR 6.1 RE 1 (SL 2+): Centralized audit log access
violations contains msg if {
    input.target_sl >= 2
    not input.monitoring.centralized_log_collection
    msg := sprintf(
        "IEC 62443 SR 6.1 RE 1 SL%v (TRE): Audit logs are not centrally collected. Centralized log management with correlation capability is required at Security Level 2+ for timely incident detection.",
        [input.target_sl]
    )
}

violations contains msg if {
    input.target_sl >= 2
    not input.monitoring.automated_alerts_configured
    msg := sprintf(
        "IEC 62443 SR 6.1 RE 1 SL%v (TRE): No automated security alerting configured. Automated detection and alerting on security events is required at Security Level 2+.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 6.2 — Continuous monitoring
# Monitor the IACS on a continuous basis for security events.
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.monitoring.security_event_monitoring
    msg := "IEC 62443 SR 6.2 (TRE): No security event monitoring for IACS. Real-time or near-real-time monitoring of the IACS is required to enable timely response to incidents."
}

violations contains msg if {
    not input.monitoring.continuous_monitoring
    msg := "IEC 62443 SR 6.2 (TRE): IACS security monitoring is not continuous (24/7). Continuous monitoring is required — gaps in monitoring create windows of undetected intrusion."
}

# SR 6.2 RE 1 (SL 2+): Automated monitoring with alert response
violations contains msg if {
    input.target_sl >= 2
    input.monitoring.mean_time_to_detect_hours > 24
    msg := sprintf(
        "IEC 62443 SR 6.2 RE 1 SL%v (TRE): Mean time to detect IACS security incidents is %v hours. Target is less than 24 hours at Security Level 2+; real-time detection recommended.",
        [input.target_sl, input.monitoring.mean_time_to_detect_hours]
    )
}

violations contains msg if {
    input.target_sl >= 2
    input.monitoring.mean_time_to_respond_hours > 4
    msg := sprintf(
        "IEC 62443 SR 6.2 RE 1 SL%v (TRE): Mean time to respond to IACS security incidents is %v hours. Target is less than 4 hours at Security Level 2+.",
        [input.target_sl, input.monitoring.mean_time_to_respond_hours]
    )
}

# SR 6.2 RE 2 (SL 3+): ICS-specific SOC capability
violations contains msg if {
    input.target_sl >= 3
    not input.monitoring.ics_specific_soc_capability
    msg := sprintf(
        "IEC 62443 SR 6.2 RE 2 SL%v (TRE): No ICS-specific Security Operations Center (SOC) capability. At Security Level 3+, OT-aware monitoring personnel or an OT-SOC is required.",
        [input.target_sl]
    )
}

# SR 6.2 RE 3 (SL 3+): Threat intelligence integration
violations contains msg if {
    input.target_sl >= 3
    not input.monitoring.threat_intelligence_integrated
    msg := sprintf(
        "IEC 62443 SR 6.2 RE 3 SL%v (TRE): Threat intelligence is not integrated into IACS monitoring. ICS-CERT/CISA advisories and sector-specific threat feeds must be operationalized at Security Level 3+.",
        [input.target_sl]
    )
}

violations contains msg if {
    input.target_sl >= 4
    not input.monitoring.anomaly_detection_enabled
    msg := sprintf(
        "IEC 62443 SR 6.2 RE 4 SL%v (TRE): No anomaly-based detection for IACS. Behavioral anomaly detection is required at Security Level 4 to detect sophisticated, previously unseen attacks.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

fr6_passing_srs := count([sr |
    sr := [
        count([v | some v in violations; contains(v, "SR 6.1")]) == 0,
        count([v | some v in violations; contains(v, "SR 6.2")]) == 0,
    ][_]
    sr == true
])

compliance_report := {
    "foundational_requirement": "FR 6",
    "title":                    "Timely Response to Events (TRE)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                2,
    "passing_srs":              fr6_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
