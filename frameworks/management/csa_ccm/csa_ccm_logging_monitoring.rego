package csa_ccm.logging_monitoring

import rego.v1

default compliant := false

violations contains msg if {
    not input.csa_ccm.logging_monitoring.audit_logging.logging_policy_established
    msg := "LOG-01: Audit logging policy not established — requirements for what must be logged must be formally defined"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.audit_logging.audit_logging_enabled
    msg := "LOG-01: Audit logging not enabled across cloud management planes and application layers"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.audit_logging.cloud_api_logging_enabled
    msg := "LOG-01: Cloud control plane API logging not enabled — all API calls to cloud management APIs must be logged"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.audit_logging.log_coverage_verified
    msg := "LOG-01: Audit log coverage not verified — gaps in logging across systems must be identified and addressed"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_retention.retention_policy_defined
    msg := "LOG-02: Log retention policy not defined — minimum retention periods must be documented per log type and regulatory requirement"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_retention.retention_period_enforced
    msg := "LOG-02: Log retention period not technically enforced — automated retention and deletion controls must be configured"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_retention.minimum_retention_met
    msg := "LOG-02: Log retention does not meet minimum period required by applicable regulations (typically 1 year or more)"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_retention.archived_logs_protected
    msg := "LOG-02: Archived logs not protected from unauthorized modification or deletion"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.centralized_logging.siem_deployed
    msg := "LOG-03: SIEM or centralized logging platform not deployed — logs must be aggregated for correlation and analysis"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.centralized_logging.cloud_logs_forwarded
    msg := "LOG-03: Cloud service logs not forwarded to centralized logging platform"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.centralized_logging.all_critical_sources_onboarded
    msg := "LOG-03: All critical log sources not onboarded to centralized SIEM or logging platform"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.centralized_logging.log_parsing_configured
    msg := "LOG-03: Log parsing and normalization not configured — raw logs must be structured for effective analysis"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.real_time_alerting.alerting_configured
    msg := "LOG-04: Real-time security alerting not configured — critical events must trigger immediate notifications"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.real_time_alerting.alert_rules_defined
    msg := "LOG-04: Alert rules not defined for security-relevant events — specific conditions requiring alerts must be documented"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.real_time_alerting.alert_response_times_defined
    msg := "LOG-04: Response time requirements for security alerts not defined by severity level"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.real_time_alerting.alerts_reviewed_and_actioned
    msg := "LOG-04: Security alerts not reviewed and actioned within defined response time requirements"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.anomaly_detection.anomaly_detection_implemented
    msg := "LOG-05: Anomaly detection not implemented — baseline behavior must be established and deviations detected"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.anomaly_detection.ueba_or_equivalent
    msg := "LOG-05: User and entity behavior analytics (UEBA) or equivalent not implemented for threat detection"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.anomaly_detection.cloud_anomalies_detected
    msg := "LOG-05: Cloud-specific anomalies (unusual API calls, impossible travel, credential abuse) not detected"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.privileged_access_logging.privileged_actions_logged
    msg := "LOG-06: Privileged user actions not logged — all administrative activities must generate audit records"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.privileged_access_logging.privileged_session_content_captured
    msg := "LOG-06: Privileged session content not captured — commands and actions during elevated sessions must be recorded"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.privileged_access_logging.privileged_log_tampering_prevented
    msg := "LOG-06: Privileged users not prevented from modifying or deleting their own audit logs"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.ntp.time_synchronization_configured
    msg := "LOG-07: Network time synchronization (NTP) not configured on cloud systems — accurate timestamps required for log correlation"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.ntp.single_time_source_used
    msg := "LOG-07: Consistent time source not enforced across all systems — divergent clocks undermine log correlation"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.ntp.time_drift_monitored
    msg := "LOG-07: Time drift not monitored and alerted — clock skew must be detected and corrected"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_integrity.logs_protected_from_tampering
    msg := "LOG-08: Log integrity protection not implemented — logs must be protected from unauthorized modification"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_integrity.immutable_log_storage_used
    msg := "LOG-08: Immutable log storage not used — write-once storage or cryptographic verification must protect log integrity"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_integrity.log_integrity_verified
    msg := "LOG-08: Log integrity not periodically verified — mechanisms to detect log tampering must be operational"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.log_integrity.log_access_controlled
    msg := "LOG-08: Log access not restricted — only authorized security personnel must be able to read or manage audit logs"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.monitoring_coverage.all_environments_monitored
    msg := "LOG-09: All cloud environments (production, development, staging) not covered by security monitoring"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.monitoring_coverage.network_monitoring_active
    msg := "LOG-09: Cloud network traffic monitoring not active — network-level visibility required alongside host-level logging"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.monitoring_coverage.application_logging_enabled
    msg := "LOG-09: Application-level logging not enabled — application events must be captured alongside infrastructure logs"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.incident_detection.detection_use_cases_defined
    msg := "LOG-10: Threat detection use cases not defined — specific attack patterns and behaviors to detect must be documented"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.incident_detection.detection_rules_tuned
    msg := "LOG-10: Detection rules not regularly tuned — false positive rates must be managed to maintain alert quality"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.monitoring_program.program_reviewed_annually
    msg := "LOG-11: Logging and monitoring program not reviewed at least annually for completeness and effectiveness"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.monitoring_program.coverage_gaps_identified
    msg := "LOG-11: Logging coverage gaps not systematically identified and remediated"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.data_access_logging.sensitive_data_access_logged
    msg := "LOG-12: Access to sensitive and regulated data not logged — all reads and writes to sensitive data must generate audit records"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.data_access_logging.bulk_data_access_alerted
    msg := "LOG-12: Bulk data access not alerted — large-volume data reads may indicate exfiltration and must trigger review"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.metrics_dashboards.security_dashboards_operational
    msg := "LOG-13: Security monitoring dashboards not operational — real-time visibility into security posture must be maintained"
}

violations contains msg if {
    not input.csa_ccm.logging_monitoring.metrics_dashboards.kpi_metrics_tracked
    msg := "LOG-13: Key security monitoring KPIs not tracked and reported to management regularly"
}

compliant if { count(violations) == 0 }

compliance_report := {
    "domain": "LOG — Logging & Monitoring",
    "compliant": compliant,
    "violation_count": count(violations),
    "violations": violations,
}
