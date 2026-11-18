# METADATA
# title: "HIPAA Security Rule — 45 CFR 164.312(b)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 23
#     cited: 1
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package hipaa.audit_controls

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(b)
# Technical Safeguard: Audit Controls
#
# Implement hardware, software, and/or procedural mechanisms that record and
# examine activity in information systems that contain or use ePHI.
#
# The regulation states the two functions (record, examine) and no event list, log fields, retention period,
# review interval or tooling. Those library choices are reported in `advisories`, which is not cited to
# 45 CFR and does not affect `compliant`. (The six-year retention in 164.316(b)(2)(i) applies to the
# documentation 164.316 requires, not to audit logs as such.)
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
		[phi_system.name],
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

advisories contains msg if {
	some phi_system in input.phi_systems
	phi_system.audit_logging_enabled
	some required_event in required_audit_events
	not required_event in phi_system.audited_events
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): ePHI system '%v' does not audit event type '%v'.",
		[phi_system.name, required_event],
	)
}

advisories contains msg if {
	not input.audit_logging.includes_user_id
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs do not capture user identity. Logs must identify who performed each action."
}

advisories contains msg if {
	not input.audit_logging.includes_timestamp
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs do not include timestamps. All log entries must be timestamped."
}

advisories contains msg if {
	not input.audit_logging.includes_source_ip
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs do not capture source IP address. Network source must be recorded for ePHI access."
}

advisories contains msg if {
	not input.audit_logging.includes_action_type
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs do not capture action type (read/write/delete). Action type must be recorded."
}

# ---------------------------------------------------------------------------
# Audit log retention
# ---------------------------------------------------------------------------

advisories contains msg if {
	is_number(input.audit_logging.retention_days)
	input.audit_logging.retention_days < 2190
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Audit log retention is %v days. HIPAA requires minimum 6 years (2190 days) for audit documentation.",
		[input.audit_logging.retention_days],
	)
}

advisories contains msg if {
	not is_number(object.get(input, ["audit_logging", "retention_days"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): evidence missing — audit_logging.retention_days not collected. HIPAA requires minimum 6 years (2190 days) for audit documentation."
}

advisories contains msg if {
	not input.audit_logging.offsite_backup_enabled
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs are not backed up offsite. Log integrity requires backup to prevent tampering or loss."
}

# ---------------------------------------------------------------------------
# Audit log integrity
# ---------------------------------------------------------------------------

advisories contains msg if {
	not input.audit_logging.tamper_evident
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs are not tamper-evident. Logs must be protected from modification or deletion."
}

advisories contains msg if {
	not input.audit_logging.centralized
	msg := "Advisory (library practice, not a 45 CFR requirement): Audit logs are not centralized. Distributed logs increase the risk of incomplete collection and tampering."
}

# ---------------------------------------------------------------------------
# Audit log review
# ---------------------------------------------------------------------------

advisories contains msg if {
	is_number(input.monitoring.audit_review_frequency_days)
	input.monitoring.audit_review_frequency_days > 7
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Audit logs are reviewed every %v days. Logs for ePHI systems should be reviewed at least weekly.",
		[input.monitoring.audit_review_frequency_days],
	)
}

# 164.312(b) requires mechanisms that record AND examine activity. Examination is evidenced by a review being
# performed or by a positive review interval; the weekly interval itself is a library advisory.
_review_evidenced if input.monitoring.audit_review_performed == true

_review_evidenced if {
	x := object.get(input, ["monitoring", "audit_review_frequency_days"], null)
	is_number(x)
	x > 0
}

violation_audit_review contains msg if {
	not _review_evidenced
	msg := "HIPAA 164.312(b): evidence missing — no examination of recorded activity is evidenced (monitoring.audit_review_performed or a positive monitoring.audit_review_frequency_days)."
}

advisories contains msg if {
	not input.monitoring.automated_alerting_enabled
	msg := "Advisory (library practice, not a 45 CFR requirement): No automated alerting on audit log anomalies. Suspicious ePHI access should trigger immediate alerts."
}

advisories contains msg if {
	not input.monitoring.unauthorized_access_alerts
	msg := "Advisory (library practice, not a 45 CFR requirement): No alerts configured for unauthorized ePHI access attempts. Failed access attempts must be monitored."
}

# ---------------------------------------------------------------------------
# Audit log for after-hours access
# ---------------------------------------------------------------------------

advisories contains msg if {
	not input.monitoring.after_hours_access_alerts
	msg := "Advisory (library practice, not a 45 CFR requirement): No monitoring for after-hours ePHI access. Unusual access times are a key indicator of unauthorized activity."
}

# ---------------------------------------------------------------------------
# All violations
# ---------------------------------------------------------------------------

violations contains msg if some msg in violation_audit_enabled
violations contains msg if some msg in violation_audit_review

# Fail-closed: no ePHI systems in scope → cannot certify this safeguard
violations contains msg if {
	count(object.get(input, "phi_systems", [])) == 0
	msg := "HIPAA 164.312(b): no ePHI systems in scope (input.phi_systems is empty) — cannot certify Audit Controls. Declare the ePHI systems to be evaluated."
}

# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "164.312(b)",
	"title": "Audit Controls",
	"required": true,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"advisories": advisories,
	"controls": {
		"audit_enabled": count(violation_audit_enabled) == 0,
		"audit_review": count(violation_audit_review) == 0,
	},
}
