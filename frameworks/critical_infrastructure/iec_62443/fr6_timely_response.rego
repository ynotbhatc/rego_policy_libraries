# METADATA
# title: "IEC 62443-3-3 FR 6 — Timely Response to Events (TRE)"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 14
#     cited: 3
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iec_62443.fr6

import rego.v1

# =============================================================================
# IEC 62443-3-3:2013 FR 6 — Timely Response to Events (TRE)
#
# Edition: IEC 62443-3-3:2013 (edition 1.0, System security requirements and
# security levels). SR and RE numbers below are that edition's.
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

# A missing measurement fails closed: an unreported retention/MTTD/MTTR does not meet the limit.
# The measurement must be a number: null and strings do not compare as numbers.
monitoring_at_most_or_least(key, "min", n) if {
	is_number(input.monitoring[key])
	input.monitoring[key] >= n
}

monitoring_at_most_or_least(key, "max", n) if {
	is_number(input.monitoring[key])
	input.monitoring[key] <= n
}

# ---------------------------------------------------------------------------
# SR 6.1 — Audit log accessibility
# Ensure audit logs are accessible to authorized personnel in a timely manner.
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.monitoring.log_access_controlled == true
	finding := "IEC 62443 SR 6.1 (TRE): IACS audit log access is not controlled. Logs must be accessible to authorized security and operations personnel while protected against unauthorized access."
	msg := concat("", [finding, _ev_input("monitoring.log_access_controlled")])
}

violations contains msg if {
	not monitoring_at_most_or_least("ics_log_retention_days", "min", 90)
	msg := sprintf(
		"IEC 62443 SR 6.1 (TRE): IACS audit logs are retained for only %v days. Minimum 90-day retention is required to support incident investigations (1 year recommended for regulatory environments).",
		[object.get(object.get(input, "monitoring", {}), "ics_log_retention_days", "not set")],
	)
}

violations contains msg if {
	some system in input.ics_systems
	not system.audit_logging_enabled == true
	finding := sprintf(
		"IEC 62443 SR 6.1 (TRE): ICS system '%v' does not have audit logging enabled. Security event logs are required to enable timely detection and response.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "audit_logging_enabled")])
}

violations contains msg if {
	not input.monitoring.incident_response_plan_for_ics == true
	finding := "IEC 62443 SR 6.1 (TRE): No ICS-specific incident response plan. OT/ICS incidents require specialized response procedures distinct from IT IR plans — a documented plan is required."
	msg := concat("", [finding, _ev_input("monitoring.incident_response_plan_for_ics")])
}

# SR 6.1 RE 1 (SL 2+): Centralized audit log access
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.monitoring.centralized_log_collection == true
	finding := sprintf(
		"IEC 62443 SR 6.1 RE 1 SL%v (TRE): Audit logs are not centrally collected. Centralized log management with correlation capability is required at Security Level 2+ for timely incident detection.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("monitoring.centralized_log_collection")])
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.monitoring.automated_alerts_configured == true
	finding := sprintf(
		"IEC 62443 SR 6.1 RE 1 SL%v (TRE): No automated security alerting configured. Automated detection and alerting on security events is required at Security Level 2+.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("monitoring.automated_alerts_configured")])
}

# ---------------------------------------------------------------------------
# SR 6.2 — Continuous monitoring
# Monitor the IACS on a continuous basis for security events.
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.monitoring.security_event_monitoring == true
	finding := "IEC 62443 SR 6.2 (TRE): No security event monitoring for IACS. Real-time or near-real-time monitoring of the IACS is required to enable timely response to incidents."
	msg := concat("", [finding, _ev_input("monitoring.security_event_monitoring")])
}

violations contains msg if {
	not input.monitoring.continuous_monitoring == true
	finding := "IEC 62443 SR 6.2 (TRE): IACS security monitoring is not continuous (24/7). Continuous monitoring is required — gaps in monitoring create windows of undetected intrusion."
	msg := concat("", [finding, _ev_input("monitoring.continuous_monitoring")])
}

# SR 6.2 RE 1 (SL 2+): Automated monitoring with alert response
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not monitoring_at_most_or_least("mean_time_to_detect_hours", "max", 24)
	msg := sprintf(
		"IEC 62443 SR 6.2 RE 1 SL%v (TRE): Mean time to detect IACS security incidents is %v hours. Target is less than 24 hours at Security Level 2+; real-time detection recommended.",
		[input.target_sl, object.get(object.get(input, "monitoring", {}), "mean_time_to_detect_hours", "not set")],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not monitoring_at_most_or_least("mean_time_to_respond_hours", "max", 4)
	msg := sprintf(
		"IEC 62443 SR 6.2 RE 1 SL%v (TRE): Mean time to respond to IACS security incidents is %v hours. Target is less than 4 hours at Security Level 2+.",
		[input.target_sl, object.get(object.get(input, "monitoring", {}), "mean_time_to_respond_hours", "not set")],
	)
}

# SR 6.2 RE 2 (SL 3+): ICS-specific SOC capability
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	not input.monitoring.ics_specific_soc_capability == true
	finding := sprintf(
		"IEC 62443 SR 6.2 RE 2 SL%v (TRE): No ICS-specific Security Operations Center (SOC) capability. At Security Level 3+, OT-aware monitoring personnel or an OT-SOC is required.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("monitoring.ics_specific_soc_capability")])
}

# SR 6.2 RE 3 (SL 3+): Threat intelligence integration
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	not input.monitoring.threat_intelligence_integrated == true
	finding := sprintf(
		"IEC 62443 SR 6.2 RE 3 SL%v (TRE): Threat intelligence is not integrated into IACS monitoring. ICS-CERT/CISA advisories and sector-specific threat feeds must be operationalized at Security Level 3+.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("monitoring.threat_intelligence_integrated")])
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 4
	not input.monitoring.anomaly_detection_enabled == true
	finding := sprintf(
		"IEC 62443 SR 6.2 RE 4 SL%v (TRE): No anomaly-based detection for IACS. Behavioral anomaly detection is required at Security Level 4 to detect sophisticated, previously unseen attacks.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("monitoring.anomaly_detection_enabled")])
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

# SL-dependent requirements are gated on target_sl. Without a number they
# silently never run, so its absence is itself a violation.
violations contains "IEC 62443 FR 6 (TRE): evidence missing - input.target_sl not provided; Security Level dependent requirements cannot be evaluated" if {
	not is_number(object.get(input, "target_sl", null))
}

compliant if count(violations) == 0

fr6_passing_srs := count([sr |
	sr := [
		count([v | some v in violations; contains(v, "SR 6.1")]) == 0,
		count([v | some v in violations; contains(v, "SR 6.2")]) == 0,
	][_]
	sr == true
])

compliance_report := {
	"foundational_requirement": "FR 6",
	"title": "Timely Response to Events (TRE)",
	"standard": "IEC 62443-3-3",
	"target_sl": object.get(input, ["target_sl"], 0),
	"total_srs": 2,
	"passing_srs": fr6_passing_srs,
	"compliant": compliant,
	"violations": violations,
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
