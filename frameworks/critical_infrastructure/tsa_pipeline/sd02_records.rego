package tsa_pipeline.sd02_records

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section IV — Records
# Section V  — Procedures for Security Directives
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: IV.A, IV.B.1–2, IV.C.1, IV.C.2.a–f, V.A.1–2
#                         (11 subparagraphs)
#
# Section IV governs what TSA can demand and how it must be protected. All
# information required to be reported or submitted under this Security Directive
# is Sensitive Security Information subject to 49 CFR part 1520.
#
# Note IV.C.2.e.ii: packet captures are bounded — "not to exceed a period of
# twenty-four hours, as identified and directed by TSA."
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.records: {
#   "previous_materials_relied_upon": boolean,   # IV.A
#   "index_maintained":               boolean,
#   "index_ordered_by_requirement":   boolean,
#   "incorporated_by_reference":      boolean,
#   "ssi_protection": {                          # IV.B
#       "plans_and_reports":     boolean,
#       "assessment_results":    boolean
#   },
#   "available_to_tsa_on_request":    boolean,   # IV.C.1
#   "retrievable_document_types":     [string],  # IV.C.2 — see required_types
#   "activity_snapshot": {                       # IV.C.2.e
#       "log_files":              boolean,
#       "packet_capture_capable": boolean,
#       "packet_capture_max_hours": number,      # must be <= 24
#       "east_west_traffic":      boolean,
#       "north_south_traffic":    boolean
#   },
#   "directive_procedures": {                    # V.A
#       "receipt_confirmed":      boolean,
#       "disseminated_to_senior_management": boolean,
#       "disseminated_to_implementers":     boolean
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_records
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

required_document_types := {
	"asset_inventory": "IV.C.2.a: Hardware/software asset inventory, including supervisory control and data acquisition systems",
	"firewall_rules": "IV.C.2.b: Firewall rules",
	"network_diagrams": "IV.C.2.c: Network diagrams, switch and router configurations, architecture diagrams, publicly routable internet protocol addresses, and Virtual Local Area Networks",
	"policy_documents": "IV.C.2.d: Policy, procedural, and other documents that informed the development and documented implementation of the Cybersecurity Implementation Plan, Cybersecurity Incident Response Plan, Cybersecurity Assessment Plan, and assessment or audit results",
	"activity_snapshot": "IV.C.2.e: Data providing a 'snapshot' of activity on and between Information and Operational Technology systems",
}

declared_document_types := {t | some t in object.get(facts, ["records", "retrievable_document_types"], [])}

# ── IV.A — Use of previous plans, assessments, tests, and evaluations ────────

violations contains msg if {
	object.get(facts, ["records", "previous_materials_relied_upon"], false) == true
	object.get(facts, ["records", "index_maintained"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.A: Previously developed plans, assessments, tests, or evaluations are relied upon to meet this Security Directive's requirements, but no index of the records and their location is maintained"
}

violations contains msg if {
	object.get(facts, ["records", "previous_materials_relied_upon"], false) == true
	object.get(facts, ["records", "index_ordered_by_requirement"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.A: The index of previously developed materials is not organized in the same sequence as the requirements in this Security Directive"
}

violations contains msg if {
	object.get(facts, ["records", "previous_materials_relied_upon"], false) == true
	object.get(facts, ["records", "incorporated_by_reference"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.A: Previously developed materials are not explicitly incorporated by reference into the Cybersecurity Implementation Plan"
}

# ── IV.B — Protection of Sensitive Security Information ──────────────────────

violations contains msg if {
	object.get(facts, ["records", "ssi_protection", "plans_and_reports"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.B.1: Plans and reports required by this Security Directive are not stored and transmitted consistent with the Sensitive Security Information requirements in 49 CFR part 1520"
}

violations contains msg if {
	object.get(facts, ["records", "ssi_protection", "assessment_results"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.B.2: Audit, testing, or assessment results are not stored and transmitted consistent with the Sensitive Security Information requirements in 49 CFR part 1520"
}

# ── IV.C — Documentation to establish compliance ─────────────────────────────

violations contains msg if {
	object.get(facts, ["records", "available_to_tsa_on_request"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.C.1: Records necessary to establish compliance are not made available to TSA upon request for inspection and/or copying"
}

violations contains msg if {
	some doc_type, description in required_document_types
	not doc_type in declared_document_types
	msg := sprintf("TSA SD Pipeline-2021-02G %s — this record type cannot be produced for TSA inspection", [description])
}

# ── IV.C.2.e — Activity snapshot data ────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["records", "activity_snapshot", "log_files"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.C.2.e.i: Log files providing a snapshot of activity on and between Information and Operational Technology systems cannot be produced"
}

violations contains msg if {
	object.get(facts, ["records", "activity_snapshot", "packet_capture_capable"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.C.2.e.ii: No capability to produce a capture of network traffic (packet capture) as identified and directed by TSA"
}

violations contains msg if {
	hours := object.get(facts, ["records", "activity_snapshot", "packet_capture_max_hours"], 0)
	is_number(hours)
	hours > 24
	msg := sprintf("TSA SD Pipeline-2021-02G IV.C.2.e.ii: Packet capture is configured for a %v-hour period — captures produced for TSA must not exceed a period of twenty-four hours", [hours])
}

violations contains msg if {
	object.get(facts, ["records", "activity_snapshot", "east_west_traffic"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.C.2.e.iii: 'East-West Traffic' of Operational Technology systems, sites, and environments within the scope of this Security Directive cannot be produced"
}

violations contains msg if {
	object.get(facts, ["records", "activity_snapshot", "north_south_traffic"], false) == false
	msg := "TSA SD Pipeline-2021-02G IV.C.2.e.iv: 'North-South Traffic' between Information and Operational Technology systems, and the perimeter boundaries between them, cannot be produced"
}

# ── V.A — General procedures ─────────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["records", "directive_procedures", "receipt_confirmed"], false) == false
	msg := "TSA SD Pipeline-2021-02G V.A.1: Written confirmation of receipt of this Security Directive was not immediately provided to TSA (SurfOps-SD@tsa.dhs.gov)"
}

violations contains msg if {
	object.get(facts, ["records", "directive_procedures", "disseminated_to_senior_management"], false) == false
	msg := "TSA SD Pipeline-2021-02G V.A.2: The information and measures in this Security Directive were not immediately disseminated to corporate senior management and security management representatives"
}

violations contains msg if {
	object.get(facts, ["records", "directive_procedures", "disseminated_to_implementers"], false) == false
	msg := "TSA SD Pipeline-2021-02G V.A.2: The applicable security measures were not provided to the direct employees and authorized representatives responsible for implementing them"
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "IV / V",
	"name": "Records, SSI Protection, and Directive Procedures",
	"packet_capture_max_hours": 24,
	"requirements_evaluated": 11,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}
