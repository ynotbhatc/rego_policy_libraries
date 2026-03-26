package ami.nist_ir7628.audit

import rego.v1

# NIST IR 7628 Rev 1 - Smart Grid Cybersecurity
# Control Family: SG.AU - Audit and Accountability
# Scope: AMI head-end, MDMS, and communications infrastructure

# Required event types that must be logged per SG.AU-2
required_events := {
    "user_login",
    "user_logout",
    "failed_authentication",
    "data_access",
    "data_modification",
    "configuration_change",
    "privilege_escalation",
    "meter_tamper_alert",
    "firmware_update",
}

# SG.AU-2: Auditable Events
# All required event types must be captured in audit logs
all_required_events_logged if {
    logged := {event | event := input.audit.events_logged[_]}
    every required_event in required_events {
        required_event in logged
    }
}

# SG.AU-4: Audit Log Storage Capacity
# Audit log storage must not be allowed to reach capacity without alerting
audit_capacity_managed if {
    input.audit.storage.capacity_monitoring_enabled == true
    input.audit.storage.alert_threshold_percent <= 80
    input.audit.storage.auto_archive_enabled == true
}

# SG.AU-5: Response to Audit Logging Process Failures
# System must alert on audit subsystem failure
audit_failure_alerting if {
    input.audit.storage.failure_alerting_enabled == true
    input.audit.storage.failure_response_documented == true
}

# SG.AU-5: Log Retention
# Logs must be retained for minimum 365 days (1 year)
log_retention_sufficient if {
    input.audit.storage.retention_days >= 365
}

# SG.AU-9: Protection of Audit Information
# Logs must be encrypted and integrity-protected
log_integrity_protected if {
    input.audit.protection.encrypted == true
    input.audit.protection.integrity_mechanism == "HMAC_SHA256"
    input.audit.protection.write_protected == true
}

# SG.AU-11: Audit Record Retention and SIEM Integration
# Centralized logging with real-time alerting required
siem_integrated if {
    input.audit.siem.centralized_logging == true
    input.audit.siem.real_time_alerting == true
    input.audit.siem.correlation_enabled == true
}

# Violations

violations contains msg if {
    not all_required_events_logged
    missing := required_events - {event | event := input.audit.events_logged[_]}
    msg := sprintf("SG.AU-2: Required audit events not logged: %v", [missing])
}

violations contains msg if {
    not audit_capacity_managed
    msg := "SG.AU-4: Audit log capacity monitoring or auto-archive not configured"
}

violations contains msg if {
    not audit_failure_alerting
    msg := "SG.AU-5: Audit subsystem failure alerting not enabled"
}

violations contains msg if {
    not log_retention_sufficient
    msg := sprintf("SG.AU-5: Audit log retention is %d days — minimum 365 required", [input.audit.storage.retention_days])
}

violations contains msg if {
    not log_integrity_protected
    msg := "SG.AU-9: Audit logs are not encrypted or HMAC-integrity protected"
}

violations contains msg if {
    not siem_integrated
    msg := "SG.AU-11: SIEM integration or real-time alerting not configured"
}

default compliant := false

compliant if {
    count(violations) == 0
}

compliance_report := {
    "control_family": "SG.AU",
    "framework": "NIST IR 7628 Rev 1",
    "controls_assessed": ["SG.AU-2", "SG.AU-4", "SG.AU-5", "SG.AU-9", "SG.AU-11"],
    "total_violations": count(violations),
    "compliant": compliant,
    "violations": violations,
}
