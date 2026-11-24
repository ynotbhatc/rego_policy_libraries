# METADATA
# title: "EU Cyber Resilience Act (CRA) — Article 14 (Regulation (EU) 2024/2847, final OJ text). Manufacturer reporting obligations for actively"
# custom:
#   class: compliance
#   framework: cra
#   source: eu
#   domains: [eu, product-security]
#   coverage:
#     checks: 19
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cra.incident_reporting

import rego.v1

# EU Cyber Resilience Act (CRA) — Article 14 (Regulation (EU) 2024/2847,
# final OJ text). Manufacturer reporting obligations for actively
# exploited vulnerabilities and severe incidents.
#
# APPLIES FROM 11 SEPTEMBER 2026 (Art. 71(2)) — these are live legal
# obligations, ahead of the general 11 December 2027 application date.
#
# Recipients (Art. 14(1)/(3)): SIMULTANEOUSLY to the CSIRT designated
# as coordinator (per Art. 14(7)) AND to ENISA, via the single
# reporting platform established by Art. 16. There is no platform
# "registration" obligation.
#
# Actively exploited vulnerability (Art. 14(2)):
#   (a) early warning within 24h of becoming aware
#   (b) vulnerability notification within 72h of becoming aware
#   (c) final report no later than 14 days after a corrective or
#       mitigating measure IS AVAILABLE (not after awareness)
# Severe incident (Art. 14(4)):
#   (a) early warning within 24h of becoming aware
#   (b) incident notification within 72h of becoming aware
#   (c) final report within 1 month after the (b) notification
#
# Art. 14(8): inform impacted users without undue delay, including
# corrective measures / mitigations — where appropriate in a
# structured, machine-readable format (e.g. CSAF).
#
# Input contract — input.incident_reporting.*
#   hours_since_aware_of_vuln / hours_since_aware_of_incident  (number)
#   days_since_corrective_measure_available  (number — the 14(2)(c) clock)
#   days_since_incident_notification         (number — the 14(4)(c) clock)
#   plus the boolean facts referenced below.

default compliant := false

# ── Art. 14(2) — actively exploited vulnerability ──────────────────────────

violation contains msg if {
	input.incident_reporting.actively_exploited_vuln_known == true
	is_number(input.incident_reporting.hours_since_aware_of_vuln)
	input.incident_reporting.hours_since_aware_of_vuln > 24
	note := _unmet(_root, ["incident_reporting", "early_warning_sent"])
	text := sprintf("CRA Art.14(2)(a): no early warning submitted to the CSIRT coordinator and ENISA within 24h of awareness (current: %dh)", [input.incident_reporting.hours_since_aware_of_vuln])
	msg := concat("", [text, note])
}

violation contains msg if {
	input.incident_reporting.actively_exploited_vuln_known == true
	is_number(input.incident_reporting.hours_since_aware_of_vuln)
	input.incident_reporting.hours_since_aware_of_vuln > 72
	note := _unmet(_root, ["incident_reporting", "vulnerability_notification_sent"])
	text := sprintf("CRA Art.14(2)(b): no vulnerability notification submitted within 72h of awareness (current: %dh)", [input.incident_reporting.hours_since_aware_of_vuln])
	msg := concat("", [text, note])
}

# The final-report clock starts when a corrective or mitigating measure
# becomes AVAILABLE — not at awareness.
violation contains msg if {
	input.incident_reporting.actively_exploited_vuln_known == true
	input.incident_reporting.corrective_measure_available == true
	is_number(input.incident_reporting.days_since_corrective_measure_available)
	input.incident_reporting.days_since_corrective_measure_available > 14
	note := _unmet(_root, ["incident_reporting", "final_vuln_report_sent"])
	text := sprintf("CRA Art.14(2)(c): final vulnerability report not submitted within 14 days of a corrective/mitigating measure becoming available (current: %dd)", [input.incident_reporting.days_since_corrective_measure_available])
	msg := concat("", [text, note])
}

# ── Art. 14(4) — severe incident ───────────────────────────────────────────

violation contains msg if {
	input.incident_reporting.severe_incident_occurred == true
	is_number(input.incident_reporting.hours_since_aware_of_incident)
	input.incident_reporting.hours_since_aware_of_incident > 24
	note := _unmet(_root, ["incident_reporting", "incident_early_warning_sent"])
	text := "CRA Art.14(4)(a): severe incident early warning not submitted to the CSIRT coordinator and ENISA within 24h of awareness"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.incident_reporting.severe_incident_occurred == true
	is_number(input.incident_reporting.hours_since_aware_of_incident)
	input.incident_reporting.hours_since_aware_of_incident > 72
	note := _unmet(_root, ["incident_reporting", "incident_notification_sent"])
	text := "CRA Art.14(4)(b): severe incident notification not submitted within 72h of awareness"
	msg := concat("", [text, note])
}

# The final-report clock starts at the Art. 14(4)(b) notification.
violation contains msg if {
	input.incident_reporting.severe_incident_occurred == true
	input.incident_reporting.incident_notification_sent == true
	is_number(input.incident_reporting.days_since_incident_notification)
	input.incident_reporting.days_since_incident_notification > 30
	note := _unmet(_root, ["incident_reporting", "incident_final_report_sent"])
	text := "CRA Art.14(4)(c): final incident report not submitted within 1 month of the incident notification"
	msg := concat("", [text, note])
}

# ── Evidence missing: a timing clock that was not supplied cannot be assumed met ─
# The clock is required whenever its obligation is switched on, whether or not the report is said to
# have been sent: a string or a missing value is not a time.

violation contains "CRA Art.14(2)(a): evidence missing — hours_since_aware_of_vuln not collected; early warning timeliness cannot be verified" if {
	input.incident_reporting.actively_exploited_vuln_known == true
	not is_number(object.get(_root, ["incident_reporting", "hours_since_aware_of_vuln"], null))
}

violation contains "CRA Art.14(2)(b): evidence missing — hours_since_aware_of_vuln not collected; vulnerability notification timeliness cannot be verified" if {
	input.incident_reporting.actively_exploited_vuln_known == true
	not is_number(object.get(_root, ["incident_reporting", "hours_since_aware_of_vuln"], null))
}

violation contains "CRA Art.14(2)(c): evidence missing — days_since_corrective_measure_available not collected; final report timeliness cannot be verified" if {
	input.incident_reporting.actively_exploited_vuln_known == true
	input.incident_reporting.corrective_measure_available == true
	not is_number(object.get(_root, ["incident_reporting", "days_since_corrective_measure_available"], null))
}

violation contains "CRA Art.14(4)(a): evidence missing — hours_since_aware_of_incident not collected; early warning timeliness cannot be verified" if {
	input.incident_reporting.severe_incident_occurred == true
	not is_number(object.get(_root, ["incident_reporting", "hours_since_aware_of_incident"], null))
}

violation contains "CRA Art.14(4)(b): evidence missing — hours_since_aware_of_incident not collected; incident notification timeliness cannot be verified" if {
	input.incident_reporting.severe_incident_occurred == true
	not is_number(object.get(_root, ["incident_reporting", "hours_since_aware_of_incident"], null))
}

violation contains "CRA Art.14(4)(c): evidence missing — days_since_incident_notification not collected; final report timeliness cannot be verified" if {
	input.incident_reporting.severe_incident_occurred == true
	input.incident_reporting.incident_notification_sent == true
	not is_number(object.get(_root, ["incident_reporting", "days_since_incident_notification"], null))
}

# ── Art. 14(8) — informing impacted users ──────────────────────────────────

violation contains msg if {
	input.incident_reporting.users_impacted == true
	note := _unmet(_root, ["incident_reporting", "affected_users_notified"])
	text := "CRA Art.14(8): impacted users not informed without undue delay about the incident/vulnerability"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.incident_reporting.users_impacted == true
	input.incident_reporting.affected_users_notified == true
	note := _unmet(_root, ["incident_reporting", "mitigation_guidance_provided"])
	text := "CRA Art.14(8): user notification did not include risk mitigations and, where appropriate, corrective measures"
	msg := concat("", [text, note])
}

violation contains msg if {
	input.incident_reporting.users_impacted == true
	input.incident_reporting.affected_users_notified == true
	note := _unmet(_root, ["incident_reporting", "notification_machine_readable_where_appropriate"])
	text := "CRA Art.14(8): user notification not provided in a structured, machine-readable format where appropriate (e.g. CSAF)"
	msg := concat("", [text, note])
}

# ── Reporting readiness (practice checks, anchored to Art. 14(1)/(7)) ──────

violation contains msg if {
	note := _unmet(_root, ["incident_reporting", "csirt_coordinator_identified"])
	text := "CRA Art.14(1)/(7) readiness: the CSIRT designated as coordinator that would receive notifications has not been identified in advance"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["incident_reporting", "process_documented"])
	text := "CRA Art.14 readiness: documented reporting process (recipients, timelines, content per notification stage) not in place"
	msg := concat("", [text, note])
}

violation contains msg if {
	note := _unmet(_root, ["incident_reporting", "process_tested_annually"])
	text := "CRA Art.14 readiness (practice, not a CRA clause): reporting process not exercised at least annually"
	msg := concat("", [text, note])
}

# ── Facts that switch an obligation on or off ───────────────────────────
# Each must be stated as true or false wherever its own condition holds. A missing, null or
# non-boolean value is an evidence problem and is reported; it is never read as "does not apply".
_conditions contains ["CRA Art.14(1)", ["incident_reporting", "actively_exploited_vuln_known"]]

_conditions contains ["CRA Art.14(2)(c)", ["incident_reporting", "corrective_measure_available"]] if input.incident_reporting.actively_exploited_vuln_known == true

_conditions contains ["CRA Art.14(3)", ["incident_reporting", "severe_incident_occurred"]]

_conditions contains ["CRA Art.14(8)", ["incident_reporting", "users_impacted"]]

violation contains msg if {
	some [cite, path] in _conditions
	msg := sprintf("%s: applicability not determined — %s", [cite, _problem(_root, path)])
}

compliant if {
	count(violation) == 0
}

compliance_report := {
	"family": "Article 14",
	"name": "Reporting obligations of manufacturers",
	"applies_from": "2026-09-11 (Art.71(2) — ahead of the general 2027-12-11 date)",
	"controls_evaluated": 12,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}

# ── Evidence helpers ─────────────────────────────────────────────────────────
# Evidence rule: only the boolean true passes a yes/no fact. _unmet is defined when the fact is not the
# boolean true; its value is appended to the finding and names the evidence problem (missing, null, or a
# value that is not a boolean, such as the strings "true" and "false"). A collected false adds nothing.
# _problem names the same evidence problem for a fact that switches an obligation on or off: such a fact
# must be stated as true or false and is never inferred from a missing field.
# The input document itself may be absent or not an object: every fact then reads as not collected.
default _root := {}

_root := input if is_object(input)

_fact(root, path) := value if {
	is_object(root)
	value := object.get(root, path, null)
} else := null

_problem(root, path) := sprintf("evidence missing: %s not collected", [concat(".", path)]) if _fact(root, path) == null

_problem(root, path) := sprintf("evidence invalid: %s is not a boolean (got %s)", [concat(".", path), type_name(_fact(root, path))]) if {
	_fact(root, path) != null
	not is_boolean(_fact(root, path))
}

_unmet(root, path) := "" if _fact(root, path) == false

_unmet(root, path) := concat("", [" — ", _problem(root, path)]) if not is_boolean(_fact(root, path))
