# METADATA
# title: "TSA Security Directive Pipeline-2021-01G — \"Enhancing Pipeline Cybersecurity\""
# custom:
#   class: ot
#   framework: tsa_pipeline
#   source: tsa
#   domains: [ot, pipeline]
#   coverage:
#     checks: 16
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package tsa_pipeline.sd01_coordinator

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-01G — "Enhancing Pipeline Cybersecurity"
# Section II.B — Cybersecurity Coordinator
#
# Directive:  SD Pipeline-2021-01G
# Effective:  January 16, 2026 through January 15, 2027
# Supersedes: SD Pipeline-2021-01F
# Authority:  49 U.S.C. 114(d), (f), (l), and (m)
# Applies to: Owner/Operators of a hazardous liquid and natural gas pipeline or
#             a liquefied natural gas facility notified by TSA that their
#             pipeline system or facility is critical
#
# Requirements evaluated: II.B.1.a through II.B.2.d (12 subparagraphs)
#
# NOTE ON THE 01G REVISION: Section II.B.1.c is the substantive change in this
# revision. Any non-U.S. citizen serving as a primary or alternate Cybersecurity
# Coordinator must be a current member of NEXUS, Global Entry, or another
# program TSA determines includes a comparable security threat assessment.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.cybersecurity_coordinator: {
#   "primary": {
#     "name":                     string,
#     "title":                    string,
#     "phone":                    string,
#     "email":                    string,
#     "corporate_level":          boolean,   # designated at the corporate level
#     "us_citizen":               boolean,
#     "clearance_eligible":       boolean,   # eligible for a security clearance
#     "trusted_traveler_program": string,    # "NEXUS" | "Global Entry" | other
#     "known_traveler_number":    string     # NEXUS PASS ID / KTN
#   },
#   "alternates": [ { ...same shape... } ],
#   "submitted_to_tsa":                     boolean,
#   "information_current":                  boolean,
#   "days_since_information_change":        number,   # days since new operations
#                                                    # commenced or info changed
#   "us_citizen_primary_intelligence_contact": boolean,
#   "us_person_restricted_info_procedures":    boolean,
#   "primary_contact_for_tsa_cisa":            boolean,
#   "available_24x7":                          boolean,
#   "internal_coordination_documented":        boolean,
#   "law_enforcement_liaison_established":     boolean
# }
#
# NO PUBLISHED FACT SOURCE EXISTS YET. Nothing in this library emits
# input.cybersecurity_coordinator — these are attestation/document facts, not
# host facts. Absent input this module reports fully non-compliant, which is
# the correct fail-closed behavior for an audit framework. Do not present it as
# a working assessment until a fact source is wired up.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd01_coordinator
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

# ── Coordinator roster helpers ───────────────────────────────────────────────

# Total: an absent or non-object "primary" yields an empty array, not undefined.
primary_list := [c |
	some c in [object.get(facts, ["cybersecurity_coordinator", "primary"], null)]
	is_object(c)
]

alternate_list := [c |
	some c in object.get(facts, ["cybersecurity_coordinator", "alternates"], [])
	is_object(c)
]

all_coordinators := array.concat(primary_list, alternate_list)

coordinator_name(c) := name if {
	name := object.get(c, "name", "unnamed")
}

# A coordinator counts as a trusted-traveler member only with a non-empty
# program AND a non-empty identifier — a program name alone proves nothing.
has_trusted_traveler_membership(c) if {
	object.get(c, "trusted_traveler_program", "") != ""
	object.get(c, "known_traveler_number", "") != ""
}

us_citizen_clearance_eligible_present if {
	some c in all_coordinators
	object.get(c, "us_citizen", false) == true
	object.get(c, "clearance_eligible", false) == true
}

# ── II.B.1.a — Designation ───────────────────────────────────────────────────

violations contains msg if {
	count(primary_list) == 0
	msg := "TSA SD Pipeline-2021-01G II.B.1.a: No primary Cybersecurity Coordinator designated — Owner/Operators must designate and use a primary Cybersecurity Coordinator at the corporate level"
}

violations contains msg if {
	count(alternate_list) == 0
	msg := "TSA SD Pipeline-2021-01G II.B.1.a: No alternate Cybersecurity Coordinator designated — at least one alternate is required at the corporate level"
}

violations contains msg if {
	some c in all_coordinators
	not object.get(c, "corporate_level", null) == true
	finding := sprintf("TSA SD Pipeline-2021-01G II.B.1.a: Cybersecurity Coordinator '%s' is not designated at the corporate level", [coordinator_name(c)])
	msg := concat("", [finding, _ev_item(c, "corporate_level")])
}

# ── II.B.1.b — U.S. citizen eligible for a security clearance ────────────────

violations contains msg if {
	count(all_coordinators) > 0
	not us_citizen_clearance_eligible_present
	msg := "TSA SD Pipeline-2021-01G II.B.1.b: Neither the Cybersecurity Coordinator nor any alternate is a U.S. citizen eligible for a security clearance"
}

# ── II.B.1.c — Non-U.S. citizen coordinators ─────────────────────────────────

# A coordinator not shown to be a U.S. citizen (false, absent or not a boolean) counts as a non-U.S. citizen.
non_us_citizen_designated if {
	some c in all_coordinators
	not object.get(c, "us_citizen", null) == true
}

violations contains msg if {
	non_us_citizen_designated
	not object.get(facts, ["cybersecurity_coordinator", "us_citizen_primary_intelligence_contact"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.1.c.i: A non-U.S. citizen is designated as a Cybersecurity Coordinator, but the U.S. citizen Coordinator is not established as the primary contact for cyber-related intelligence information restricted to U.S. persons"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.us_citizen_primary_intelligence_contact")])
}

violations contains msg if {
	some c in all_coordinators
	not object.get(c, "us_citizen", null) == true
	not has_trusted_traveler_membership(c)
	finding := sprintf("TSA SD Pipeline-2021-01G II.B.1.c.ii: Cybersecurity Coordinator '%s' is a non-U.S. citizen but is not a current member of NEXUS, Global Entry, or another TSA-determined comparable security threat assessment program", [coordinator_name(c)])
	msg := concat("", [finding, _ev_item(c, "us_citizen")])
}

violations contains msg if {
	non_us_citizen_designated
	not object.get(facts, ["cybersecurity_coordinator", "us_person_restricted_info_procedures"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.1.c.iii: No established and implemented procedures ensuring U.S.-person-restricted information is not shared with, or maintained on any system accessible by, a non-U.S. person"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.us_person_restricted_info_procedures")])
}

# ── II.B.1.d — Written submission to TSA ─────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["cybersecurity_coordinator", "submitted_to_tsa"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.1.d: Cybersecurity Coordinator information not provided in writing to TSA (SurfOps-SD@tsa.dhs.gov) — names, titles, phone numbers, and email addresses are required for all primary and alternate Coordinators"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.submitted_to_tsa")])
}

violations contains msg if {
	some c in all_coordinators
	some field in ["name", "title", "phone", "email"]
	object.get(c, field, "") == ""
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.d: Cybersecurity Coordinator '%s' is missing required submission field '%s'", [coordinator_name(c), field])
}

violations contains msg if {
	some c in all_coordinators
	not object.get(c, "us_citizen", null) == true
	object.get(c, "known_traveler_number", "") == ""
	finding := sprintf("TSA SD Pipeline-2021-01G II.B.1.d: Non-U.S. citizen Cybersecurity Coordinator '%s' has no NEXUS PASS ID (Known Traveler Number) or other applicable program number on file with TSA", [coordinator_name(c)])
	msg := concat("", [finding, _ev_item(c, "us_citizen")])
}

# ── II.B.1.e — Currency of information (7-day deadline) ──────────────────────

violations contains msg if {
	not object.get(facts, ["cybersecurity_coordinator", "information_current"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.1.e: Cybersecurity Coordinator information on file with TSA is not current"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.information_current")])
}

violations contains msg if {
	days := object.get(facts, ["cybersecurity_coordinator", "days_since_information_change"], 0)
	is_number(days)
	days > 7
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.e: Cybersecurity Coordinator information change is %d days old — updates must be provided to TSA within 7 days of the commencement of new operations or a change in any required information", [days])
}

# ── II.B.2 — Coordinator duties ──────────────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["cybersecurity_coordinator", "primary_contact_for_tsa_cisa"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.2.a: Cybersecurity Coordinator is not established as the primary contact for cybersecurity-related activities and communications with TSA and CISA"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.primary_contact_for_tsa_cisa")])
}

violations contains msg if {
	not object.get(facts, ["cybersecurity_coordinator", "available_24x7"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.2.b: Cybersecurity Coordinator and alternate(s) are not accessible to TSA and CISA 24 hours a day, seven days a week, including when the U.S. Government is closed"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.available_24x7")])
}

violations contains msg if {
	not object.get(facts, ["cybersecurity_coordinator", "internal_coordination_documented"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.2.c: No documented process for the Cybersecurity Coordinator to coordinate cyber and related security practices and procedures internally"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.internal_coordination_documented")])
}

violations contains msg if {
	not object.get(facts, ["cybersecurity_coordinator", "law_enforcement_liaison_established"], null) == true
	finding := "TSA SD Pipeline-2021-01G II.B.2.d: Cybersecurity Coordinator has no established working relationship with appropriate law enforcement and emergency response agencies"
	msg := concat("", [finding, _ev_input("cybersecurity_coordinator.law_enforcement_liaison_established")])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-01G",
	"section": "II.B",
	"name": "Cybersecurity Coordinator",
	"effective_date": "2026-01-16",
	"expiration_date": "2027-01-15",
	"requirements_evaluated": 12,
	"coordinators_designated": count(all_coordinators),
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}

# ---------------------------------------------------------------------------
# Stated facts. A fact that decides whether a requirement applies must be the
# boolean true or false, and a measured value must be a number: an absent fact,
# null or a string is an evidence problem and a finding, never a silent pass.
# Rows: [path under input, directive paragraph].
# ---------------------------------------------------------------------------

_required_numbers := [
	[["cybersecurity_coordinator", "days_since_information_change"], "II.B.1.e"],
]

violations contains msg if {
	some [path, paragraph] in _required_numbers
	value := object.get(facts, path, null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-01G %s: evidence missing - input.%s is not a number (got %s), so the limit cannot be checked", [paragraph, concat(".", path), type_name(value)])
}

violations contains msg if {
	some c in all_coordinators
	not is_boolean(object.get(c, "us_citizen", null))
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.b: Cybersecurity Coordinator '%s' does not state us_citizen as true or false, so the requirement cannot be decided%s", [coordinator_name(c), _ev_item(c, "us_citizen")])
}

violations contains msg if {
	some c in all_coordinators
	not is_boolean(object.get(c, "clearance_eligible", null))
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.b: Cybersecurity Coordinator '%s' does not state clearance_eligible as true or false, so the requirement cannot be decided%s", [coordinator_name(c), _ev_item(c, "clearance_eligible")])
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
