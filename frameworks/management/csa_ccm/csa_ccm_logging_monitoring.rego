# METADATA
# title: "Csa Ccm Logging Monitoring"
# custom:
#   class: compliance
#   framework: csa_ccm
#   source: csa
#   domains: [cloud]
#   coverage:
#     checks: 40
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package csa_ccm.logging_monitoring

import rego.v1

default compliant := false

_base := ["csa_ccm", "logging_monitoring"]

# Evidence rule: only the boolean true passes a yes/no fact. A fact that is missing or null was not
# collected, and any other type (the strings "true" and "false", numbers) is a collection error. Both fail
# the check, and the finding names the problem. Boolean false keeps the plain finding text.
_fact(path) := object.get(_doc, array.concat(_base, path), null)

# No input document, or one that is not an object, reads as empty: every fact is then missing.
_doc := input if {
	is_object(input)
} else := {}

_field(path) := concat(".", array.concat(["input"], array.concat(_base, path)))

_finding(text, path) := text if _fact(path) == false

_finding(text, path) := sprintf("%s — evidence missing: %s not collected", [text, _field(path)]) if {
	_fact(path) == null
}

_finding(text, path) := sprintf("%s — evidence invalid: %s is not a boolean (got %s)", [text, _field(path), type_name(value)]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

violations contains msg if {
	msg := _finding("LOG-01: Audit logging policy not established — requirements for what must be logged must be formally defined", ["audit_logging", "logging_policy_established"])
}

violations contains msg if {
	msg := _finding("LOG-01: Audit logging not enabled across cloud management planes and application layers", ["audit_logging", "audit_logging_enabled"])
}

violations contains msg if {
	msg := _finding("LOG-01: Cloud control plane API logging not enabled — all API calls to cloud management APIs must be logged", ["audit_logging", "cloud_api_logging_enabled"])
}

violations contains msg if {
	msg := _finding("LOG-01: Audit log coverage not verified — gaps in logging across systems must be identified and addressed", ["audit_logging", "log_coverage_verified"])
}

violations contains msg if {
	msg := _finding("LOG-02: Log retention policy not defined — minimum retention periods must be documented per log type and regulatory requirement", ["log_retention", "retention_policy_defined"])
}

violations contains msg if {
	msg := _finding("LOG-02: Log retention period not technically enforced — automated retention and deletion controls must be configured", ["log_retention", "retention_period_enforced"])
}

violations contains msg if {
	msg := _finding("LOG-02: Log retention does not meet minimum period required by applicable regulations (typically 1 year or more)", ["log_retention", "minimum_retention_met"])
}

violations contains msg if {
	msg := _finding("LOG-02: Archived logs not protected from unauthorized modification or deletion", ["log_retention", "archived_logs_protected"])
}

violations contains msg if {
	msg := _finding("LOG-03: SIEM or centralized logging platform not deployed — logs must be aggregated for correlation and analysis", ["centralized_logging", "siem_deployed"])
}

violations contains msg if {
	msg := _finding("LOG-03: Cloud service logs not forwarded to centralized logging platform", ["centralized_logging", "cloud_logs_forwarded"])
}

violations contains msg if {
	msg := _finding("LOG-03: All critical log sources not onboarded to centralized SIEM or logging platform", ["centralized_logging", "all_critical_sources_onboarded"])
}

violations contains msg if {
	msg := _finding("LOG-03: Log parsing and normalization not configured — raw logs must be structured for effective analysis", ["centralized_logging", "log_parsing_configured"])
}

violations contains msg if {
	msg := _finding("LOG-04: Real-time security alerting not configured — critical events must trigger immediate notifications", ["real_time_alerting", "alerting_configured"])
}

violations contains msg if {
	msg := _finding("LOG-04: Alert rules not defined for security-relevant events — specific conditions requiring alerts must be documented", ["real_time_alerting", "alert_rules_defined"])
}

violations contains msg if {
	msg := _finding("LOG-04: Response time requirements for security alerts not defined by severity level", ["real_time_alerting", "alert_response_times_defined"])
}

violations contains msg if {
	msg := _finding("LOG-04: Security alerts not reviewed and actioned within defined response time requirements", ["real_time_alerting", "alerts_reviewed_and_actioned"])
}

violations contains msg if {
	msg := _finding("LOG-05: Anomaly detection not implemented — baseline behavior must be established and deviations detected", ["anomaly_detection", "anomaly_detection_implemented"])
}

violations contains msg if {
	msg := _finding("LOG-05: User and entity behavior analytics (UEBA) or equivalent not implemented for threat detection", ["anomaly_detection", "ueba_or_equivalent"])
}

violations contains msg if {
	msg := _finding("LOG-05: Cloud-specific anomalies (unusual API calls, impossible travel, credential abuse) not detected", ["anomaly_detection", "cloud_anomalies_detected"])
}

violations contains msg if {
	msg := _finding("LOG-06: Privileged user actions not logged — all administrative activities must generate audit records", ["privileged_access_logging", "privileged_actions_logged"])
}

violations contains msg if {
	msg := _finding("LOG-06: Privileged session content not captured — commands and actions during elevated sessions must be recorded", ["privileged_access_logging", "privileged_session_content_captured"])
}

violations contains msg if {
	msg := _finding("LOG-06: Privileged users not prevented from modifying or deleting their own audit logs", ["privileged_access_logging", "privileged_log_tampering_prevented"])
}

violations contains msg if {
	msg := _finding("LOG-07: Network time synchronization (NTP) not configured on cloud systems — accurate timestamps required for log correlation", ["ntp", "time_synchronization_configured"])
}

violations contains msg if {
	msg := _finding("LOG-07: Consistent time source not enforced across all systems — divergent clocks undermine log correlation", ["ntp", "single_time_source_used"])
}

violations contains msg if {
	msg := _finding("LOG-07: Time drift not monitored and alerted — clock skew must be detected and corrected", ["ntp", "time_drift_monitored"])
}

violations contains msg if {
	msg := _finding("LOG-08: Log integrity protection not implemented — logs must be protected from unauthorized modification", ["log_integrity", "logs_protected_from_tampering"])
}

violations contains msg if {
	msg := _finding("LOG-08: Immutable log storage not used — write-once storage or cryptographic verification must protect log integrity", ["log_integrity", "immutable_log_storage_used"])
}

violations contains msg if {
	msg := _finding("LOG-08: Log integrity not periodically verified — mechanisms to detect log tampering must be operational", ["log_integrity", "log_integrity_verified"])
}

violations contains msg if {
	msg := _finding("LOG-08: Log access not restricted — only authorized security personnel must be able to read or manage audit logs", ["log_integrity", "log_access_controlled"])
}

violations contains msg if {
	msg := _finding("LOG-09: All cloud environments (production, development, staging) not covered by security monitoring", ["monitoring_coverage", "all_environments_monitored"])
}

violations contains msg if {
	msg := _finding("LOG-09: Cloud network traffic monitoring not active — network-level visibility required alongside host-level logging", ["monitoring_coverage", "network_monitoring_active"])
}

violations contains msg if {
	msg := _finding("LOG-09: Application-level logging not enabled — application events must be captured alongside infrastructure logs", ["monitoring_coverage", "application_logging_enabled"])
}

violations contains msg if {
	msg := _finding("LOG-10: Threat detection use cases not defined — specific attack patterns and behaviors to detect must be documented", ["incident_detection", "detection_use_cases_defined"])
}

violations contains msg if {
	msg := _finding("LOG-10: Detection rules not regularly tuned — false positive rates must be managed to maintain alert quality", ["incident_detection", "detection_rules_tuned"])
}

violations contains msg if {
	msg := _finding("LOG-11: Logging and monitoring program not reviewed at least annually for completeness and effectiveness", ["monitoring_program", "program_reviewed_annually"])
}

violations contains msg if {
	msg := _finding("LOG-11: Logging coverage gaps not systematically identified and remediated", ["monitoring_program", "coverage_gaps_identified"])
}

violations contains msg if {
	msg := _finding("LOG-12: Access to sensitive and regulated data not logged — all reads and writes to sensitive data must generate audit records", ["data_access_logging", "sensitive_data_access_logged"])
}

violations contains msg if {
	msg := _finding("LOG-12: Bulk data access not alerted — large-volume data reads may indicate exfiltration and must trigger review", ["data_access_logging", "bulk_data_access_alerted"])
}

violations contains msg if {
	msg := _finding("LOG-13: Security monitoring dashboards not operational — real-time visibility into security posture must be maintained", ["metrics_dashboards", "security_dashboards_operational"])
}

violations contains msg if {
	msg := _finding("LOG-13: Key security monitoring KPIs not tracked and reported to management regularly", ["metrics_dashboards", "kpi_metrics_tracked"])
}

compliant if count(violations) == 0

# The control ids this module carries checks for. A control can have several checks, so the report counts
# both: violations lists one finding per failed check, failed_controls counts the controls they belong to.
_control_ids := ["LOG-01", "LOG-02", "LOG-03", "LOG-04", "LOG-05", "LOG-06", "LOG-07", "LOG-08", "LOG-09", "LOG-10", "LOG-11", "LOG-12", "LOG-13"]

failed_control_ids := sort({id |
	some msg in violations
	id := split(msg, ":")[0]
})

compliance_report := {
	"domain": "LOG — Logging & Monitoring",
	"compliant": compliant,
	"controls_checked": count(_control_ids),
	"failed_controls": count(failed_control_ids),
	"passed_controls": count(_control_ids) - count(failed_control_ids),
	"failed_control_ids": failed_control_ids,
	"checks_total": 40,
	"violation_count": count(violations),
	"violations": violations,
}
