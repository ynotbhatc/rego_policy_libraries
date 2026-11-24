# METADATA
# title: "TSA Security Directive Pipeline-2021-02G"
# custom:
#   class: ot
#   framework: tsa_pipeline
#   source: tsa
#   domains: [ot, pipeline]
#   coverage:
#     checks: 19
#     cited: 12
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package tsa_pipeline.sd02_incident_response_plan

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section III.F — Cybersecurity Incident Response Plan
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: III.F.1.a–e (incl. b.i–iv, e.i–ii), III.F.2
#                         (13 subparagraphs)
#
# III.F requires an up-to-date Cybersecurity Incident Response Plan for the
# Critical Cyber Systems "that include measures to reduce the risk of
# operational disruption, or the risk of other significant impacts on business
# critical functions should the covered pipeline or facility experience a
# cybersecurity incident."
#
# THE EXERCISE CLOCK (III.F.1.e): exercises must be held no less than annually,
# must test at least TWO of the objectives in III.F.1.a–III.F.1.d, and must
# include the employees identified by position in III.F.2 as active participants.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.incident_response_plan: {
#   "exists":       boolean,
#   "up_to_date":   boolean,
#   "covers_critical_cyber_systems": boolean,
#   "objectives": {
#       "prompt_containment":  boolean,   # III.F.1.a
#       "segregation": {                  # III.F.1.b
#           "infected_devices":        boolean,   # b.i
#           "shared_network_devices":  boolean,   # b.ii
#           "volatile_memory_preserved": boolean, # b.iii
#           "isolation_and_labeling":  boolean    # b.iv
#       },
#       "backup_integrity": {             # III.F.1.c
#           "backups_secured":        boolean,
#           "stored_separately":      boolean,
#           "malicious_code_free_verified": boolean
#       },
#       "it_ot_isolation_governance": boolean  # III.F.1.d
#   },
#   "exercises": {                        # III.F.1.e
#       "conducted_within_last_12_months": boolean,
#       "months_since_last_exercise":      number,
#       "objectives_tested":               number,   # must be >= 2
#       "responsible_personnel_participated": boolean
#   },
#   "responsibilities": {                 # III.F.2
#       "assigned_by_position": boolean,
#       "resources_identified": boolean
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_incident_response_plan
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

irp_flag(path) := value if {
	value := object.get(facts, array.concat(["incident_response_plan"], path), false)
}

# ── III.F.1 — Plan exists and is current ─────────────────────────────────────

violations contains msg if {
	not irp_flag(["exists"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1: No Cybersecurity Incident Response Plan for the Critical Cyber Systems"
	msg := concat("", [finding, _ev_input("incident_response_plan.exists")])
}

violations contains msg if {
	not irp_flag(["up_to_date"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1: The Cybersecurity Incident Response Plan is not up to date"
	msg := concat("", [finding, _ev_input("incident_response_plan.up_to_date")])
}

violations contains msg if {
	not irp_flag(["covers_critical_cyber_systems"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1: The Cybersecurity Incident Response Plan does not cover the Owner/Operator's Critical Cyber Systems"
	msg := concat("", [finding, _ev_input("incident_response_plan.covers_critical_cyber_systems")])
}

# ── III.F.1.a — Prompt containment ───────────────────────────────────────────

violations contains msg if {
	not irp_flag(["objectives", "prompt_containment"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.a: The Cybersecurity Incident Response Plan provides no specific measures for prompt containment of an infected server or device"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.prompt_containment")])
}

# ── III.F.1.b — Segregation of the infected network or devices ───────────────

violations contains msg if {
	not irp_flag(["objectives", "segregation", "infected_devices"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.b.i: No measures for segregating (removing from the network) infected devices"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.segregation.infected_devices")])
}

violations contains msg if {
	not irp_flag(["objectives", "segregation", "shared_network_devices"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.b.ii: No measures for segregating other devices that shared a network with the infected device(s)"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.segregation.shared_network_devices")])
}

violations contains msg if {
	not irp_flag(["objectives", "segregation", "volatile_memory_preserved"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.b.iii: No measures for preserving volatile memory by collecting a forensic memory image of affected device(s) before powering off or moving them"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.segregation.volatile_memory_preserved")])
}

violations contains msg if {
	not irp_flag(["objectives", "segregation", "isolation_and_labeling"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.b.iv: No measures for isolating and securing all infected and potentially infected devices, including clearly labeling equipment affected by malicious code"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.segregation.isolation_and_labeling")])
}

# ── III.F.1.c — Security and integrity of backed-up data ─────────────────────

violations contains msg if {
	not irp_flag(["objectives", "backup_integrity", "backups_secured"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.c: No measures to secure backups as part of ensuring the security and integrity of backed-up data"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.backup_integrity.backups_secured")])
}

violations contains msg if {
	not irp_flag(["objectives", "backup_integrity", "stored_separately"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.c: Backup data is not stored separate from the system"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.backup_integrity.stored_separately")])
}

violations contains msg if {
	not irp_flag(["objectives", "backup_integrity", "malicious_code_free_verified"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.c: No procedures to ensure backup data is free of known malicious code both when the backup is made and when it is tested for restoral"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.backup_integrity.malicious_code_free_verified")])
}

# ── III.F.1.d — IT/OT isolation capability and governance ────────────────────

violations contains msg if {
	not irp_flag(["objectives", "it_ot_isolation_governance"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.d: No established capability and governance for isolating the Information and Operational Technology systems in the event of a cybersecurity incident that results, or could result, in operational disruption"
	msg := concat("", [finding, _ev_input("incident_response_plan.objectives.it_ot_isolation_governance")])
}

# ── III.F.1.e — Annual exercises ─────────────────────────────────────────────

violations contains msg if {
	not irp_flag(["exercises", "conducted_within_last_12_months"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.e: No exercise conducted to test the effectiveness of the Cybersecurity Incident Response Plan procedures and personnel — exercises are required no less than annually"
	msg := concat("", [finding, _ev_input("incident_response_plan.exercises.conducted_within_last_12_months")])
}

violations contains msg if {
	months := object.get(facts, ["incident_response_plan", "exercises", "months_since_last_exercise"], 0)
	is_number(months)
	months > 12
	msg := sprintf("TSA SD Pipeline-2021-02G III.F.1.e: The last Cybersecurity Incident Response Plan exercise was %v months ago — exercises must be conducted no less than annually", [months])
}

violations contains msg if {
	tested := object.get(facts, ["incident_response_plan", "exercises", "objectives_tested"], 0)
	is_number(tested)
	tested < 2
	msg := sprintf("TSA SD Pipeline-2021-02G III.F.1.e.i: Annual exercises tested %v of the objectives required by III.F.1.a through III.F.1.d — at least two objectives must be tested no less than annually", [tested])
}

violations contains msg if {
	not irp_flag(["exercises", "responsible_personnel_participated"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.1.e.ii: The employees identified by position in Section III.F.2 did not participate in the exercises as active participants"
	msg := concat("", [finding, _ev_input("incident_response_plan.exercises.responsible_personnel_participated")])
}

# ── III.F.2 — Assigned responsibility and resources ──────────────────────────

violations contains msg if {
	not irp_flag(["responsibilities", "assigned_by_position"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.2: The Cybersecurity Incident Response Plan does not identify who, by position, is responsible for implementing its specific measures"
	msg := concat("", [finding, _ev_input("incident_response_plan.responsibilities.assigned_by_position")])
}

violations contains msg if {
	not irp_flag(["responsibilities", "resources_identified"]) == true
	finding := "TSA SD Pipeline-2021-02G III.F.2: The Cybersecurity Incident Response Plan does not identify the resources necessary to implement its measures"
	msg := concat("", [finding, _ev_input("incident_response_plan.responsibilities.resources_identified")])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "III.F",
	"name": "Cybersecurity Incident Response Plan",
	"exercise_frequency": "no less than annually",
	"minimum_objectives_per_exercise": 2,
	"requirements_evaluated": 13,
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
	[["incident_response_plan", "exercises", "months_since_last_exercise"], "III.F.1.e"],
	[["incident_response_plan", "exercises", "objectives_tested"], "III.F.1.e.i"],
]

violations contains msg if {
	some [path, paragraph] in _required_numbers
	value := object.get(facts, path, null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-02G %s: evidence missing - input.%s is not a number (got %s), so the limit cannot be checked", [paragraph, concat(".", path), type_name(value)])
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
