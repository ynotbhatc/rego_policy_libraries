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
	input.incident_reporting.hours_since_aware_of_vuln > 24
	not input.incident_reporting.early_warning_sent
	msg := sprintf("CRA Art.14(2)(a): no early warning submitted to the CSIRT coordinator and ENISA within 24h of awareness (current: %dh)", [input.incident_reporting.hours_since_aware_of_vuln])
}

violation contains msg if {
	input.incident_reporting.actively_exploited_vuln_known == true
	input.incident_reporting.hours_since_aware_of_vuln > 72
	not input.incident_reporting.vulnerability_notification_sent
	msg := sprintf("CRA Art.14(2)(b): no vulnerability notification submitted within 72h of awareness (current: %dh)", [input.incident_reporting.hours_since_aware_of_vuln])
}

# The final-report clock starts when a corrective or mitigating measure
# becomes AVAILABLE — not at awareness.
violation contains msg if {
	input.incident_reporting.actively_exploited_vuln_known == true
	input.incident_reporting.corrective_measure_available == true
	input.incident_reporting.days_since_corrective_measure_available > 14
	not input.incident_reporting.final_vuln_report_sent
	msg := sprintf("CRA Art.14(2)(c): final vulnerability report not submitted within 14 days of a corrective/mitigating measure becoming available (current: %dd)", [input.incident_reporting.days_since_corrective_measure_available])
}

# ── Art. 14(4) — severe incident ───────────────────────────────────────────

violation contains msg if {
	input.incident_reporting.severe_incident_occurred == true
	input.incident_reporting.hours_since_aware_of_incident > 24
	not input.incident_reporting.incident_early_warning_sent
	msg := "CRA Art.14(4)(a): severe incident early warning not submitted to the CSIRT coordinator and ENISA within 24h of awareness"
}

violation contains msg if {
	input.incident_reporting.severe_incident_occurred == true
	input.incident_reporting.hours_since_aware_of_incident > 72
	not input.incident_reporting.incident_notification_sent
	msg := "CRA Art.14(4)(b): severe incident notification not submitted within 72h of awareness"
}

# The final-report clock starts at the Art. 14(4)(b) notification.
violation contains msg if {
	input.incident_reporting.severe_incident_occurred == true
	input.incident_reporting.incident_notification_sent == true
	input.incident_reporting.days_since_incident_notification > 30
	not input.incident_reporting.incident_final_report_sent
	msg := "CRA Art.14(4)(c): final incident report not submitted within 1 month of the incident notification"
}

# ── Art. 14(8) — informing impacted users ──────────────────────────────────

violation contains msg if {
	input.incident_reporting.users_impacted == true
	not input.incident_reporting.affected_users_notified
	msg := "CRA Art.14(8): impacted users not informed without undue delay about the incident/vulnerability"
}

violation contains msg if {
	input.incident_reporting.users_impacted == true
	input.incident_reporting.affected_users_notified == true
	not input.incident_reporting.mitigation_guidance_provided
	msg := "CRA Art.14(8): user notification did not include risk mitigations and, where appropriate, corrective measures"
}

violation contains msg if {
	input.incident_reporting.users_impacted == true
	input.incident_reporting.affected_users_notified == true
	not input.incident_reporting.notification_machine_readable_where_appropriate
	msg := "CRA Art.14(8): user notification not provided in a structured, machine-readable format where appropriate (e.g. CSAF)"
}

# ── Reporting readiness (practice checks, anchored to Art. 14(1)/(7)) ──────

violation contains msg if {
	not input.incident_reporting.csirt_coordinator_identified
	msg := "CRA Art.14(1)/(7) readiness: the CSIRT designated as coordinator that would receive notifications has not been identified in advance"
}

violation contains msg if {
	not input.incident_reporting.process_documented
	msg := "CRA Art.14 readiness: documented reporting process (recipients, timelines, content per notification stage) not in place"
}

violation contains msg if {
	not input.incident_reporting.process_tested_annually
	msg := "CRA Art.14 readiness (practice, not a CRA clause): reporting process not exercised at least annually"
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
