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
	object.get(c, "corporate_level", false) == false
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.a: Cybersecurity Coordinator '%s' is not designated at the corporate level", [coordinator_name(c)])
}

# ── II.B.1.b — U.S. citizen eligible for a security clearance ────────────────

violations contains msg if {
	count(all_coordinators) > 0
	not us_citizen_clearance_eligible_present
	msg := "TSA SD Pipeline-2021-01G II.B.1.b: Neither the Cybersecurity Coordinator nor any alternate is a U.S. citizen eligible for a security clearance"
}

# ── II.B.1.c — Non-U.S. citizen coordinators ─────────────────────────────────

non_us_citizen_designated if {
	some c in all_coordinators
	object.get(c, "us_citizen", false) == false
}

violations contains msg if {
	non_us_citizen_designated
	object.get(facts, ["cybersecurity_coordinator", "us_citizen_primary_intelligence_contact"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.1.c.i: A non-U.S. citizen is designated as a Cybersecurity Coordinator, but the U.S. citizen Coordinator is not established as the primary contact for cyber-related intelligence information restricted to U.S. persons"
}

violations contains msg if {
	some c in all_coordinators
	object.get(c, "us_citizen", false) == false
	not has_trusted_traveler_membership(c)
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.c.ii: Cybersecurity Coordinator '%s' is a non-U.S. citizen but is not a current member of NEXUS, Global Entry, or another TSA-determined comparable security threat assessment program", [coordinator_name(c)])
}

violations contains msg if {
	non_us_citizen_designated
	object.get(facts, ["cybersecurity_coordinator", "us_person_restricted_info_procedures"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.1.c.iii: No established and implemented procedures ensuring U.S.-person-restricted information is not shared with, or maintained on any system accessible by, a non-U.S. person"
}

# ── II.B.1.d — Written submission to TSA ─────────────────────────────────────

violations contains msg if {
	object.get(facts, ["cybersecurity_coordinator", "submitted_to_tsa"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.1.d: Cybersecurity Coordinator information not provided in writing to TSA (SurfOps-SD@tsa.dhs.gov) — names, titles, phone numbers, and email addresses are required for all primary and alternate Coordinators"
}

violations contains msg if {
	some c in all_coordinators
	some field in ["name", "title", "phone", "email"]
	object.get(c, field, "") == ""
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.d: Cybersecurity Coordinator '%s' is missing required submission field '%s'", [coordinator_name(c), field])
}

violations contains msg if {
	some c in all_coordinators
	object.get(c, "us_citizen", false) == false
	object.get(c, "known_traveler_number", "") == ""
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.d: Non-U.S. citizen Cybersecurity Coordinator '%s' has no NEXUS PASS ID (Known Traveler Number) or other applicable program number on file with TSA", [coordinator_name(c)])
}

# ── II.B.1.e — Currency of information (7-day deadline) ──────────────────────

violations contains msg if {
	object.get(facts, ["cybersecurity_coordinator", "information_current"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.1.e: Cybersecurity Coordinator information on file with TSA is not current"
}

violations contains msg if {
	days := object.get(facts, ["cybersecurity_coordinator", "days_since_information_change"], 0)
	is_number(days)
	days > 7
	msg := sprintf("TSA SD Pipeline-2021-01G II.B.1.e: Cybersecurity Coordinator information change is %d days old — updates must be provided to TSA within 7 days of the commencement of new operations or a change in any required information", [days])
}

# ── II.B.2 — Coordinator duties ──────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["cybersecurity_coordinator", "primary_contact_for_tsa_cisa"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.2.a: Cybersecurity Coordinator is not established as the primary contact for cybersecurity-related activities and communications with TSA and CISA"
}

violations contains msg if {
	object.get(facts, ["cybersecurity_coordinator", "available_24x7"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.2.b: Cybersecurity Coordinator and alternate(s) are not accessible to TSA and CISA 24 hours a day, seven days a week, including when the U.S. Government is closed"
}

violations contains msg if {
	object.get(facts, ["cybersecurity_coordinator", "internal_coordination_documented"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.2.c: No documented process for the Cybersecurity Coordinator to coordinate cyber and related security practices and procedures internally"
}

violations contains msg if {
	object.get(facts, ["cybersecurity_coordinator", "law_enforcement_liaison_established"], false) == false
	msg := "TSA SD Pipeline-2021-01G II.B.2.d: Cybersecurity Coordinator has no established working relationship with appropriate law enforcement and emergency response agencies"
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
