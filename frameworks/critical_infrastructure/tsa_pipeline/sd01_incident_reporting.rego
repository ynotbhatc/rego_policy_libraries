package tsa_pipeline.sd01_reporting

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-01G — "Enhancing Pipeline Cybersecurity"
# Section II.C — Reporting Cybersecurity Incidents
#
# Directive:  SD Pipeline-2021-01G
# Effective:  January 16, 2026 through January 15, 2027
#
# Requirements evaluated: II.C.2 through II.C.5 (16 subparagraphs)
#
# NOTE: Section II.C of the published directive has no subparagraph "1" — the
# section begins at II.C.2. Citations below reflect the directive as published.
#
# THE CLOCK: II.C.3 requires reporting "as soon as practicable, but no later
# than 72 hours after the Owner/Operator identifies a cybersecurity incident."
# II.C.5.f requires supplemental information within 24 hours of it becoming
# available when the initial report was incomplete. Secondary summaries citing
# a 12-hour deadline are wrong; 72 hours is the directive text.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.incident_reporting: {
#   "procedure_documented":         boolean,
#   "reports_to_cisa_central":      boolean,  # CISA Incident Reporting System
#                                             # (cisa.gov/report) or 844-729-2472
#   "covered_incident_categories":  [string], # see required_categories below
#   "required_report_fields":       [string], # see required_report_fields below
#   "supplemental_within_24h_procedure": boolean,
#   "incidents": [ {
#       "id":                 string,
#       "identified_at":      string,   # RFC3339
#       "hours_to_report":    number,   # identification -> CISA report
#       "reported_to_cisa":   boolean,
#       "sd_reporting_stated": boolean, # report explicitly states it is filed to
#                                       # satisfy this SD's requirements (II.C.5.a)
#       "initial_report_incomplete":       boolean,
#       "supplemental_hours_after_available": number
#   } ]
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd01_reporting
# =============================================================================

# `input` is UNDEFINED (not {}) when OPA receives an empty request body. Routing
# every lookup through this defaulted alias makes an absent fact evaluate to the
# fail-closed default instead of silently skipping the violation rule entirely.
default facts := {}

facts := input

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Reference sets (II.C.2.a–e and II.C.5.a–f) ───────────────────────────────

required_categories := {
	"unauthorized_access": "II.C.2.a: Unauthorized access of an Information or Operational Technology system",
	"malicious_software": "II.C.2.b: Discovery of malicious software on an Information or Operational Technology system",
	"denial_of_service": "II.C.2.c: Activity resulting in a denial of service to any Information or Operational Technology system",
	"physical_attack": "II.C.2.d: A physical attack against the Owner/Operator's network infrastructure",
	"operational_disruption_potential": "II.C.2.e: Any other cybersecurity incident that results in, or has the potential to result in, operational disruption",
}

required_report_fields := {
	"reporter_contact": "II.C.5.a: Name of the reporting individual and contact information",
	"affected_assets": "II.C.5.b: The affected pipeline(s) and/or facilities, including identifying information and location",
	"threat_description": "II.C.5.c: Description of the threat, incident, or activity (earliest known date of compromise, date of detection, who was notified, observed indicators, known threat information)",
	"impact_assessment": "II.C.5.d: Description of the incident's impact or potential impact on Information or Operational Technology systems and operations",
	"planned_response": "II.C.5.e: Description of all responses planned or under consideration",
	"additional_information": "II.C.5.f: Any additional relevant information",
}

declared_categories := {c | some c in object.get(facts, ["incident_reporting", "covered_incident_categories"], [])}

declared_report_fields := {f | some f in object.get(facts, ["incident_reporting", "required_report_fields"], [])}

incidents := [i |
	some i in object.get(facts, ["incident_reporting", "incidents"], [])
	is_object(i)
]

incident_id(i) := id if {
	id := object.get(i, "id", "unidentified")
}

# ── II.C.2 — Reportable incident categories ──────────────────────────────────

violations contains msg if {
	object.get(facts, ["incident_reporting", "procedure_documented"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.C: No documented procedure for reporting cybersecurity incidents to CISA for systems the Owner/Operator has responsibility to operate and/or maintain"
}

violations contains msg if {
	some category, description in required_categories
	not category in declared_categories
	msg := sprintf("TSA SD Pipeline-2021-01G %s — this incident category is not covered by the Owner/Operator's CISA reporting procedure", [description])
}

# ── II.C.3 — 72-hour reporting deadline ──────────────────────────────────────

violations contains msg if {
	some i in incidents
	object.get(i, "reported_to_cisa", false) == false
	msg := sprintf("TSA SD Pipeline-2021-01G II.C.3: Cybersecurity incident '%s' was never reported to CISA — reporting is mandatory for all incidents described in Section II.C.2", [incident_id(i)])
}

violations contains msg if {
	some i in incidents
	object.get(i, "reported_to_cisa", false) == true
	hours := object.get(i, "hours_to_report", 0)
	is_number(hours)
	hours > 72
	msg := sprintf("TSA SD Pipeline-2021-01G II.C.3: Cybersecurity incident '%s' was reported to CISA %v hours after identification — reports must be made as soon as practicable but no later than 72 hours", [incident_id(i), hours])
}

# ── II.C.4 — Reporting channel ───────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["incident_reporting", "reports_to_cisa_central"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.C.4: Reports are not made to CISA Central using CISA's Incident Reporting System (https://www.cisa.gov/report) or by calling (844) 729-2472"
}

# ── II.C.5 — Required report content ─────────────────────────────────────────

violations contains msg if {
	some field, description in required_report_fields
	not field in declared_report_fields
	msg := sprintf("TSA SD Pipeline-2021-01G %s — this element is not included in the Owner/Operator's CISA report content", [description])
}

violations contains msg if {
	some i in incidents
	object.get(i, "reported_to_cisa", false) == true
	object.get(i, "sd_reporting_stated", false) == false
	msg := sprintf("TSA SD Pipeline-2021-01G II.C.5.a: Report for incident '%s' does not explicitly specify that the information is being reported to satisfy the reporting requirements in this Security Directive", [incident_id(i)])
}

# ── II.C.5.f — 24-hour supplemental reporting ────────────────────────────────

violations contains msg if {
	object.get(facts, ["incident_reporting", "supplemental_within_24h_procedure"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.C.5.f: No procedure to submit an initial report within the required timeframe and provide supplemental information within 24 hours of it becoming available"
}

violations contains msg if {
	some i in incidents
	object.get(i, "initial_report_incomplete", false) == true
	hours := object.get(i, "supplemental_hours_after_available", 0)
	is_number(hours)
	hours > 24
	msg := sprintf("TSA SD Pipeline-2021-01G II.C.5.f: Supplemental information for incident '%s' was provided %v hours after becoming available — it must be provided within 24 hours", [incident_id(i), hours])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-01G",
	"section": "II.C",
	"name": "Reporting Cybersecurity Incidents",
	"reporting_deadline_hours": 72,
	"supplemental_deadline_hours": 24,
	"requirements_evaluated": 16,
	"incidents_assessed": count(incidents),
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}
