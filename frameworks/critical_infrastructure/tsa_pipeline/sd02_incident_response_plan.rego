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
	irp_flag(["exists"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1: No Cybersecurity Incident Response Plan for the Critical Cyber Systems"
}

violations contains msg if {
	irp_flag(["up_to_date"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1: The Cybersecurity Incident Response Plan is not up to date"
}

violations contains msg if {
	irp_flag(["covers_critical_cyber_systems"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1: The Cybersecurity Incident Response Plan does not cover the Owner/Operator's Critical Cyber Systems"
}

# ── III.F.1.a — Prompt containment ───────────────────────────────────────────

violations contains msg if {
	irp_flag(["objectives", "prompt_containment"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.a: The Cybersecurity Incident Response Plan provides no specific measures for prompt containment of an infected server or device"
}

# ── III.F.1.b — Segregation of the infected network or devices ───────────────

violations contains msg if {
	irp_flag(["objectives", "segregation", "infected_devices"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.b.i: No measures for segregating (removing from the network) infected devices"
}

violations contains msg if {
	irp_flag(["objectives", "segregation", "shared_network_devices"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.b.ii: No measures for segregating other devices that shared a network with the infected device(s)"
}

violations contains msg if {
	irp_flag(["objectives", "segregation", "volatile_memory_preserved"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.b.iii: No measures for preserving volatile memory by collecting a forensic memory image of affected device(s) before powering off or moving them"
}

violations contains msg if {
	irp_flag(["objectives", "segregation", "isolation_and_labeling"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.b.iv: No measures for isolating and securing all infected and potentially infected devices, including clearly labeling equipment affected by malicious code"
}

# ── III.F.1.c — Security and integrity of backed-up data ─────────────────────

violations contains msg if {
	irp_flag(["objectives", "backup_integrity", "backups_secured"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.c: No measures to secure backups as part of ensuring the security and integrity of backed-up data"
}

violations contains msg if {
	irp_flag(["objectives", "backup_integrity", "stored_separately"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.c: Backup data is not stored separate from the system"
}

violations contains msg if {
	irp_flag(["objectives", "backup_integrity", "malicious_code_free_verified"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.c: No procedures to ensure backup data is free of known malicious code both when the backup is made and when it is tested for restoral"
}

# ── III.F.1.d — IT/OT isolation capability and governance ────────────────────

violations contains msg if {
	irp_flag(["objectives", "it_ot_isolation_governance"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.d: No established capability and governance for isolating the Information and Operational Technology systems in the event of a cybersecurity incident that results, or could result, in operational disruption"
}

# ── III.F.1.e — Annual exercises ─────────────────────────────────────────────

violations contains msg if {
	irp_flag(["exercises", "conducted_within_last_12_months"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.e: No exercise conducted to test the effectiveness of the Cybersecurity Incident Response Plan procedures and personnel — exercises are required no less than annually"
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
	irp_flag(["exercises", "responsible_personnel_participated"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.1.e.ii: The employees identified by position in Section III.F.2 did not participate in the exercises as active participants"
}

# ── III.F.2 — Assigned responsibility and resources ──────────────────────────

violations contains msg if {
	irp_flag(["responsibilities", "assigned_by_position"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.2: The Cybersecurity Incident Response Plan does not identify who, by position, is responsible for implementing its specific measures"
}

violations contains msg if {
	irp_flag(["responsibilities", "resources_identified"]) == false
	msg := "TSA SD Pipeline-2021-02G III.F.2: The Cybersecurity Incident Response Plan does not identify the resources necessary to implement its measures"
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
