package hipaa.audit_controls

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(b)
# Technical Safeguard: Audit Controls
#
# Implement hardware, software, and/or procedural mechanisms that record and
# examine activity in information systems that contain or use ePHI.
#
# Input shape:
#   input.audit_logging         - audit logging configuration
#   input.audit_logs[]          - audit log entries/metadata
#   input.phi_systems[]         - systems with ePHI
#   input.monitoring            - monitoring/alerting configuration
# =============================================================================

# ---------------------------------------------------------------------------
# Audit logging must be enabled on all ePHI systems
# ---------------------------------------------------------------------------

violation_audit_enabled contains msg if {
    some phi_system in input.phi_systems
    not phi_system.audit_logging_enabled
    msg := sprintf(
        "HIPAA 164.312(b): Audit logging is not enabled on ePHI system '%v'. All ePHI systems must record activity.",
        [phi_system.name]
    )
}

# ---------------------------------------------------------------------------
# Audit log content requirements
# ---------------------------------------------------------------------------

required_audit_events := {
    "login_success",
    "login_failure",
    "logout",
    "phi_access",
    "phi_create",
    "phi_modify",
    "phi_delete",
    "phi_export",
    "permission_change",
    "account_creation",
    "account_deletion",
    "password_change",
}

violation_audit_content contains msg if {
    some phi_system in input.phi_systems
    phi_system.audit_logging_enabled
    some required_event in required_audit_events
    not required_event in phi_system.audited_events
    msg := sprintf(
        "HIPAA 164.312(b): ePHI system '%v' does not audit event type '%v'.",
        [phi_system.name, required_event]
    )
}

violation_audit_content contains msg if {
    not input.audit_logging.includes_user_id
    msg := "HIPAA 164.312(b): Audit logs do not capture user identity. Logs must identify who performed each action."
}

violation_audit_content contains msg if {
    not input.audit_logging.includes_timestamp
    msg := "HIPAA 164.312(b): Audit logs do not include timestamps. All log entries must be timestamped."
}

violation_audit_content contains msg if {
    not input.audit_logging.includes_source_ip
    msg := "HIPAA 164.312(b): Audit logs do not capture source IP address. Network source must be recorded for ePHI access."
}

violation_audit_content contains msg if {
    not input.audit_logging.includes_action_type
    msg := "HIPAA 164.312(b): Audit logs do not capture action type (read/write/delete). Action type must be recorded."
}

# ---------------------------------------------------------------------------
# Audit log retention
# ---------------------------------------------------------------------------

violation_audit_retention contains msg if {
    input.audit_logging.retention_days < 365
    msg := sprintf(
        "HIPAA 164.312(b): Audit log retention is %v days. HIPAA requires minimum 6 years (2190 days) for audit documentation.",
        [input.audit_logging.retention_days]
    )
}

violation_audit_retention contains msg if {
    not input.audit_logging.offsite_backup_enabled
    msg := "HIPAA 164.312(b): Audit logs are not backed up offsite. Log integrity requires backup to prevent tampering or loss."
}

# ---------------------------------------------------------------------------
# Audit log integrity
# ---------------------------------------------------------------------------

violation_audit_integrity contains msg if {
    not input.audit_logging.tamper_evident
    msg := "HIPAA 164.312(b): Audit logs are not tamper-evident. Logs must be protected from modification or deletion."
}

violation_audit_integrity contains msg if {
    not input.audit_logging.centralized
    msg := "HIPAA 164.312(b): Audit logs are not centralized. Distributed logs increase the risk of incomplete collection and tampering."
}

# ---------------------------------------------------------------------------
# Audit log review
# ---------------------------------------------------------------------------

violation_audit_review contains msg if {
    input.monitoring.audit_review_frequency_days > 7
    msg := sprintf(
        "HIPAA 164.312(b): Audit logs are reviewed every %v days. Logs for ePHI systems should be reviewed at least weekly.",
        [input.monitoring.audit_review_frequency_days]
    )
}

violation_audit_review contains msg if {
    not input.monitoring.automated_alerting_enabled
    msg := "HIPAA 164.312(b): No automated alerting on audit log anomalies. Suspicious ePHI access should trigger immediate alerts."
}

violation_audit_review contains msg if {
    not input.monitoring.unauthorized_access_alerts
    msg := "HIPAA 164.312(b): No alerts configured for unauthorized ePHI access attempts. Failed access attempts must be monitored."
}

# ---------------------------------------------------------------------------
# Audit log for after-hours access
# ---------------------------------------------------------------------------

violation_after_hours contains msg if {
    not input.monitoring.after_hours_access_alerts
    msg := "HIPAA 164.312(b): No monitoring for after-hours ePHI access. Unusual access times are a key indicator of unauthorized activity."
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if { some msg in violation_audit_enabled }
violations contains msg if { some msg in violation_audit_content }
violations contains msg if { some msg in violation_audit_retention }
violations contains msg if { some msg in violation_audit_integrity }
violations contains msg if { some msg in violation_audit_review }
violations contains msg if { some msg in violation_after_hours }

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

compliant if {
    count(violations) == 0
}

compliance_report := {
    "section":        "164.312(b)",
    "title":          "Audit Controls",
    "required":       true,
    "compliant":      compliant,
    "violation_count": count(violations),
    "violations":     violations,
    "controls": {
        "audit_enabled":    count(violation_audit_enabled) == 0,
        "audit_content":    count(violation_audit_content) == 0,
        "audit_retention":  count(violation_audit_retention) == 0,
        "audit_integrity":  count(violation_audit_integrity) == 0,
        "audit_review":     count(violation_audit_review) == 0,
    },
}
