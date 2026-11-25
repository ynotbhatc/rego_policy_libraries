# METADATA
# title: "IEC 62443-3-3 FR 2 — Use Control (UC)"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 38
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iec_62443.fr2

import rego.v1

# =============================================================================
# IEC 62443-3-3:2013 FR 2 — Use Control (UC)
#
# Edition: IEC 62443-3-3:2013 (edition 1.0, System security requirements and
# security levels). SR and RE numbers below are that edition's.
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

# A missing setting fails closed: an unset timeout/retention is a violation.
# A value that is not a number does not meet a limit (null and strings do not compare as numbers).
lock_timeout_within(system, n) if {
	is_number(system.session_lock_timeout_minutes)
	system.session_lock_timeout_minutes <= n
}

log_retention_at_least(n) if {
	is_number(input.monitoring.ics_log_retention_days)
	input.monitoring.ics_log_retention_days >= n
}

# ---------------------------------------------------------------------------
# SR 2.1 — Authorization enforcement
# Enforce assigned authorizations; deny access by default (least privilege).
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.least_privilege_enforced == true
	finding := sprintf(
		"IEC 62443 SR 2.1 (UC): ICS system '%v' does not enforce least privilege. Users must only have the access rights required to perform their authorized functions.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "least_privilege_enforced")])
}

violations contains msg if {
	not input.authentication.audit_trail_for_privileged_access == true
	finding := "IEC 62443 SR 2.1 (UC): Privileged access is not audited. All privileged actions on IACS must generate an audit record."
	msg := concat("", [finding, _ev_input("authentication.audit_trail_for_privileged_access")])
}

# SR 2.1 RE 1 (SL 2+): Separate permission levels for different roles
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.authentication.role_based_access_control == true
	finding := sprintf(
		"IEC 62443 SR 2.1 RE 1 SL%v (UC): Role-based access control (RBAC) is not implemented. Separate authorization roles are required at Security Level 2+.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("authentication.role_based_access_control")])
}

# SR 2.1 RE 2 (SL 3+): Dual approval for high-impact actions
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	not input.authentication.dual_approval_for_critical_actions == true
	finding := sprintf(
		"IEC 62443 SR 2.1 RE 2 SL%v (UC): No dual-approval mechanism for high-impact IACS actions. Required at Security Level 3+ for critical system changes.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("authentication.dual_approval_for_critical_actions")])
}

# ---------------------------------------------------------------------------
# SR 2.2 — Wireless use control
# Authorize, monitor, and restrict wireless use in the IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	system.wireless_access == true
	not system.wireless_use_authorized == true
	finding := sprintf(
		"IEC 62443 SR 2.2 (UC): Wireless use on ICS system '%v' is not explicitly authorized. All wireless connections must be documented and approved.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "wireless_use_authorized")])
}

violations contains msg if {
	some system in input.ics_systems
	system.wireless_access == true
	not system.wireless_monitored == true
	finding := sprintf(
		"IEC 62443 SR 2.2 (UC): Wireless connections on ICS system '%v' are not monitored. Wireless activity must be continuously monitored for unauthorized access.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "wireless_monitored")])
}

# ---------------------------------------------------------------------------
# SR 2.3 — Use control for portable and mobile devices
# Enforce security controls on portable and mobile devices connected to IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.portable_device_policy == true
	finding := sprintf(
		"IEC 62443 SR 2.3 (UC): ICS system '%v' has no portable/mobile device use policy. USB drives, laptops, and tablets connecting to IACS must be governed by a formal policy.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "portable_device_policy")])
}

violations contains msg if {
	some system in input.ics_systems
	not system.removable_media_controlled == true
	finding := sprintf(
		"IEC 62443 SR 2.3 (UC): ICS system '%v' does not control removable media. Removable media must be scanned for malware before use and restricted to authorized devices.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "removable_media_controlled")])
}

# SR 2.3 RE 1 (SL 2+): Central management of portable device authorizations
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.authentication.portable_device_central_mgmt == true
	finding := sprintf(
		"IEC 62443 SR 2.3 RE 1 SL%v (UC): Portable device authorizations are not centrally managed. Centralized control is required at Security Level 2+.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("authentication.portable_device_central_mgmt")])
}

# ---------------------------------------------------------------------------
# SR 2.4 — Mobile code
# Control mobile code (scripts, macros, executables) executed in the IACS.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.mobile_code_controlled == true
	finding := sprintf(
		"IEC 62443 SR 2.4 (UC): ICS system '%v' does not control mobile code execution. Scripts, active content, and macros must be restricted to explicitly authorized code.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "mobile_code_controlled")])
}

# SR 2.4 RE 1 (SL 2+): Application whitelisting
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not system.application_whitelisting == true
	not system.malware_protection == true
	finding := sprintf(
		"IEC 62443 SR 2.4 RE 1 SL%v (UC): ICS system '%v' has neither application whitelisting nor malware protection. One of these is required at Security Level 2+.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "application_whitelisting"), _ev_item(system, "malware_protection")])
}

# ---------------------------------------------------------------------------
# SR 2.5 — Session lock
# Automatically lock sessions after a period of inactivity.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not lock_timeout_within(system, 30)
	msg := sprintf(
		"IEC 62443 SR 2.5 (UC): ICS system '%v' session lock timeout is %v minutes. Maximum inactivity timeout before lock must be 30 minutes or less.",
		[system.name, object.get(system, "session_lock_timeout_minutes", "not set")],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not lock_timeout_within(system, 15)
	msg := sprintf(
		"IEC 62443 SR 2.5 RE 1 SL%v (UC): ICS system '%v' session lock timeout is %v minutes. Maximum 15 minutes is required at Security Level 2+.",
		[input.target_sl, system.name, object.get(system, "session_lock_timeout_minutes", "not set")],
	)
}

violations contains msg if {
	some system in input.ics_systems
	not system.session_lock_enabled == true
	finding := sprintf(
		"IEC 62443 SR 2.5 (UC): ICS system '%v' does not enforce session locking. Automatic session lock after inactivity is required.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "session_lock_enabled")])
}

# ---------------------------------------------------------------------------
# SR 2.6 — Remote session termination
# Provide the capability to terminate remote sessions.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	system.remote_access_enabled == true
	not system.remote_session_termination == true
	finding := sprintf(
		"IEC 62443 SR 2.6 (UC): ICS system '%v' does not support remote session termination. Authorized users must be able to terminate remote sessions at any time.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "remote_session_termination")])
}

# ---------------------------------------------------------------------------
# SR 2.7 — Concurrent session control
# Limit the number of concurrent sessions per user or device.
# ---------------------------------------------------------------------------

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	system.concurrent_session_limit == 0
	msg := sprintf(
		"IEC 62443 SR 2.7 SL%v (UC): ICS system '%v' has no concurrent session limit. Limiting concurrent sessions reduces the risk of session hijacking.",
		[input.target_sl, system.name],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	some system in input.ics_systems
	is_number(system.concurrent_session_limit)
	system.concurrent_session_limit > 3
	msg := sprintf(
		"IEC 62443 SR 2.7 RE 1 SL%v (UC): ICS system '%v' allows up to %v concurrent sessions. Strict session limits (≤3) are recommended at Security Level 3+.",
		[input.target_sl, system.name, system.concurrent_session_limit],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not is_number(object.get(system, "concurrent_session_limit", null))
	msg := sprintf(
		"IEC 62443 SR 2.7 SL%v (UC): evidence missing - ICS system '%v' has no numeric concurrent_session_limit, so concurrent session control cannot be verified.",
		[input.target_sl, object.get(system, "name", "<unnamed>")],
	)
}

# ---------------------------------------------------------------------------
# SR 2.8 — Auditable events
# Generate audit records for defined security-relevant events.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.audit_logging_enabled == true
	finding := sprintf(
		"IEC 62443 SR 2.8 (UC): ICS system '%v' does not have audit logging enabled. Security-relevant events must be logged: login attempts, privilege use, configuration changes, and errors.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "audit_logging_enabled")])
}

violations contains msg if {
	some system in input.ics_systems
	system.audit_logging_enabled == true
	not system.audit_log_includes_required_fields == true
	finding := sprintf(
		"IEC 62443 SR 2.8 (UC): ICS system '%v' audit logs are missing required fields. Logs must include: event type, timestamp, source identity, outcome, and affected resource.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "audit_log_includes_required_fields")])
}

# SR 2.8 RE 1 (SL 2+): Centralized audit log collection
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.monitoring.centralized_log_collection == true
	finding := sprintf(
		"IEC 62443 SR 2.8 RE 1 SL%v (UC): Audit logs are not centrally collected. Centralized log aggregation is required at Security Level 2+ to enable correlation.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("monitoring.centralized_log_collection")])
}

# ---------------------------------------------------------------------------
# SR 2.9 — Audit storage capacity
# Allocate sufficient storage for audit records.
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.monitoring.audit_storage_adequate == true
	finding := "IEC 62443 SR 2.9 (UC): Audit log storage capacity is insufficient. The system must allocate sufficient storage and alert when approaching capacity limits."
	msg := concat("", [finding, _ev_input("monitoring.audit_storage_adequate")])
}

violations contains msg if {
	not log_retention_at_least(90)
	msg := sprintf(
		"IEC 62443 SR 2.9 (UC): IACS audit logs are retained for only %v days. Minimum 90-day retention is required (1 year recommended for regulatory compliance).",
		[object.get(object.get(input, "monitoring", {}), "ics_log_retention_days", "not set")],
	)
}

# ---------------------------------------------------------------------------
# SR 2.10 — Response to audit processing failures
# Alert and respond when audit processing failures occur.
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.monitoring.audit_processing_failure_alerts == true
	finding := "IEC 62443 SR 2.10 (UC): No alerting for audit processing failures. The system must alert personnel when audit subsystem failures occur (storage full, process crash, etc.)."
	msg := concat("", [finding, _ev_input("monitoring.audit_processing_failure_alerts")])
}

violations contains msg if {
	not input.monitoring.audit_failure_response_defined == true
	finding := "IEC 62443 SR 2.10 (UC): No defined response procedure for audit processing failures. A documented response procedure is required."
	msg := concat("", [finding, _ev_input("monitoring.audit_failure_response_defined")])
}

# ---------------------------------------------------------------------------
# SR 2.11 — Timestamps
# Provide reliable timestamps for all audit records.
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.monitoring.timestamps_synchronized == true
	finding := "IEC 62443 SR 2.11 (UC): IACS timestamps are not synchronized. All systems must use a reliable time source (NTP/PTP) to ensure audit record integrity."
	msg := concat("", [finding, _ev_input("monitoring.timestamps_synchronized")])
}

violations contains msg if {
	some system in input.ics_systems
	system.audit_logging_enabled == true
	not system.ntp_configured == true
	finding := sprintf(
		"IEC 62443 SR 2.11 (UC): ICS system '%v' does not have NTP configured. Accurate timestamps are required for audit trail integrity and incident correlation.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "ntp_configured")])
}

# ---------------------------------------------------------------------------
# SR 2.12 — Non-repudiation
# Ensure actions cannot be repudiated by the originator.
# ---------------------------------------------------------------------------

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not system.non_repudiation_enabled == true
	finding := sprintf(
		"IEC 62443 SR 2.12 SL%v (UC): ICS system '%v' does not provide non-repudiation. Cryptographic signing or equivalent mechanism is required at Security Level 2+ for critical actions.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "non_repudiation_enabled")])
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Evidence missing: a requirement with no evidence cannot be reported as passing
# (semantic review 2026-11-13)
# ---------------------------------------------------------------------------

violations contains "IEC 62443 SR 2.2 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.3 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.4 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.5 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.6 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.7 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.8 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 2.12 (UC): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

# SL-dependent requirements are gated on target_sl. Without a number they
# silently never run, so its absence is itself a violation.
violations contains "IEC 62443 FR 2 (UC): evidence missing - input.target_sl not provided; Security Level dependent requirements cannot be evaluated" if {
	not is_number(object.get(input, "target_sl", null))
}

compliant if count(violations) == 0

fr2_passing_srs := count([sr |
	sr := [
		count([v | some v in violations; contains(v, "SR 2.1 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.2 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.3 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.4 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.5 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.6 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.7 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.8 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.9 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.10 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.11 ")]) == 0,
		count([v | some v in violations; contains(v, "SR 2.12 ")]) == 0,
	][_]
	sr == true
])

compliance_report := {
	"foundational_requirement": "FR 2",
	"title": "Use Control (UC)",
	"standard": "IEC 62443-3-3",
	"target_sl": object.get(input, ["target_sl"], 0),
	"total_srs": 12,
	"passing_srs": fr2_passing_srs,
	"compliant": compliant,
	"violations": violations,
}

# ---------------------------------------------------------------------------
# Facts that decide whether a requirement applies, or that fail it when true,
# must be stated as booleans. "Does not apply" is the boolean false; an absent
# fact, null or a string such as "false" is an evidence problem and a finding.
# Rows: [fact, requirement, lowest target SL at which the fact is read].
# ---------------------------------------------------------------------------

_stated_system_facts := [
	["wireless_access", "SR 2.2", 1],
	["remote_access_enabled", "SR 2.6", 1],
	["application_whitelisting", "SR 2.4 RE 1", 2],
	["malware_protection", "SR 2.4 RE 1", 2],
]

_sl_at_least(n) if n <= 1

_sl_at_least(n) if {
	is_number(input.target_sl)
	input.target_sl >= n
}

violations contains msg if {
	some [fact, requirement, min_sl] in _stated_system_facts
	_sl_at_least(min_sl)
	some system in input.ics_systems
	not is_boolean(object.get(system, fact, null))
	msg := sprintf(
		"IEC 62443 %s (UC): ICS system '%v' does not state %s as true or false, so the requirement cannot be decided.%s",
		[requirement, object.get(system, "name", "<unnamed>"), fact, _ev_item(system, fact)],
	)
}

# An inventory is evidence only as a non-empty array: null, a string or an empty list is "not collected".
_ics_systems_collected if {
	is_array(input.ics_systems)
	count(input.ics_systems) > 0
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
