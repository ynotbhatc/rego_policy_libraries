# METADATA
# title: "TSA Security Directive Pipeline-2021-02G"
# custom:
#   class: ot
#   framework: tsa_pipeline
#   source: tsa
#   domains: [ot, pipeline]
#   coverage:
#     checks: 20
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package tsa_pipeline.sd02_implementation_plan

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section II.B — Cybersecurity Implementation Plan
# Section VI  — Amendments to Cybersecurity Implementation Plan
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: II.B.1, II.B.2, VI.A, VI.B.1–2, VI.C, VI.D, VI.F
#                         (8 subparagraphs)
#
# The Cybersecurity Implementation Plan is the spine of this directive: it "sets
# the security measures and requirements against which TSA inspects for
# compliance" (§I). It must provide the information required by Sections III.A
# through III.E and describe in detail the Owner/Operator's defense-in-depth
# plan, including physical AND logical security controls.
#
# THE AMENDMENT CLOCKS:
#   VI.C — a "permanent change" is one intended to be in effect for 45 or more
#          calendar days
#   VI.D — the amendment request must be filed with TSA no later than 50
#          calendar days after the permanent change takes effect, unless TSA
#          allows a longer period
#   VI.F — a petition for reconsideration of a denial must be filed no later
#          than 30 calendar days after receiving the denial (49 CFR 1570.119)
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.implementation_plan: {
#   "exists":                 boolean,
#   "tsa_approved":           boolean,
#   "covers_sections_iii_a_to_iii_e": boolean,
#   "defense_in_depth_described":     boolean,
#   "physical_controls_described":    boolean,
#   "logical_controls_described":     boolean,
#   "measures_implemented":           boolean,   # II.B.2
#   "schedule_met":                   boolean,   # II.B.2
#   "amendments": {
#       "ownership_or_control_changed":   boolean,   # VI.A
#       "ownership_amendment_requested":  boolean,
#       "measure_determined_ineffective": boolean,   # VI.B.1
#       "ineffective_amendment_requested": boolean,
#       "new_capabilities_obtained":      boolean,   # VI.B.2
#       "new_capability_amendment_requested": boolean,
#       "pending_permanent_changes": [ {
#           "description":              string,
#           "duration_days":            number,   # >= 45 makes it "permanent"
#           "days_since_effective":     number,   # request due within 50 days
#           "amendment_filed":          boolean
#       } ],
#       "denials": [ {
#           "description":                string,
#           "days_since_denial":          number,   # petition due within 30 days
#           "petition_filed":             boolean,
#           "reconsideration_intended":   boolean
#       } ]
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_implementation_plan
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

cip_flag(path) := value if {
	value := object.get(facts, array.concat(["implementation_plan"], path), false)
}

pending_changes := [c |
	some c in object.get(facts, ["implementation_plan", "amendments", "pending_permanent_changes"], [])
	is_object(c)
]

denials := [d |
	some d in object.get(facts, ["implementation_plan", "amendments", "denials"], [])
	is_object(d)
]

# ── II.B.1 — Plan contents ───────────────────────────────────────────────────

violations contains msg if {
	not cip_flag(["exists"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.1: No Cybersecurity Implementation Plan — all covered Owner/Operators must submit one for TSA approval"
	msg := concat("", [finding, _ev_input("implementation_plan.exists")])
}

violations contains msg if {
	not cip_flag(["tsa_approved"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.2: The Cybersecurity Implementation Plan has not been approved by TSA"
	msg := concat("", [finding, _ev_input("implementation_plan.tsa_approved")])
}

violations contains msg if {
	not cip_flag(["covers_sections_iii_a_to_iii_e"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.1: The Cybersecurity Implementation Plan does not provide the information required by Sections III.A through III.E of the Security Directive"
	msg := concat("", [finding, _ev_input("implementation_plan.covers_sections_iii_a_to_iii_e")])
}

violations contains msg if {
	not cip_flag(["defense_in_depth_described"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.1: The Cybersecurity Implementation Plan does not describe in detail the Owner/Operator's defense-in-depth plan for meeting the requirements in Sections III.A through III.E"
	msg := concat("", [finding, _ev_input("implementation_plan.defense_in_depth_described")])
}

violations contains msg if {
	not cip_flag(["physical_controls_described"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.1: The Cybersecurity Implementation Plan's defense-in-depth description omits physical security controls"
	msg := concat("", [finding, _ev_input("implementation_plan.physical_controls_described")])
}

violations contains msg if {
	not cip_flag(["logical_controls_described"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.1: The Cybersecurity Implementation Plan's defense-in-depth description omits logical security controls"
	msg := concat("", [finding, _ev_input("implementation_plan.logical_controls_described")])
}

# ── II.B.2 — Implementation and maintenance ──────────────────────────────────

violations contains msg if {
	cip_flag(["tsa_approved"]) == true
	not cip_flag(["measures_implemented"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.2: Not all measures in the TSA-approved Cybersecurity Implementation Plan are implemented and maintained"
	msg := concat("", [finding, _ev_input("implementation_plan.measures_implemented")])
}

violations contains msg if {
	cip_flag(["tsa_approved"]) == true
	not cip_flag(["schedule_met"]) == true
	finding := "TSA SD Pipeline-2021-02G II.B.2: The schedule stipulated in the TSA-approved Cybersecurity Implementation Plan is not being met"
	msg := concat("", [finding, _ev_input("implementation_plan.schedule_met")])
}

# ── VI.A — Changes to ownership or control ───────────────────────────────────

violations contains msg if {
	cip_flag(["amendments", "ownership_or_control_changed"]) == true
	not cip_flag(["amendments", "ownership_amendment_requested"]) == true
	finding := "TSA SD Pipeline-2021-02G VI.A: Ownership or control of the operation changed after approval, but no request to amend the Cybersecurity Implementation Plan has been submitted"
	msg := concat("", [finding, _ev_input("implementation_plan.amendments.ownership_amendment_requested")])
}

# ── VI.B — Changes to conditions affecting security ──────────────────────────

violations contains msg if {
	cip_flag(["amendments", "measure_determined_ineffective"]) == true
	not cip_flag(["amendments", "ineffective_amendment_requested"]) == true
	finding := "TSA SD Pipeline-2021-02G VI.B.1: A policy, procedure, or measure in the Cybersecurity Implementation Plan was determined ineffective based on the audits and assessments required under Section III.G, but no amendment has been requested"
	msg := concat("", [finding, _ev_input("implementation_plan.amendments.ineffective_amendment_requested")])
}

violations contains msg if {
	cip_flag(["amendments", "new_capabilities_obtained"]) == true
	not cip_flag(["amendments", "new_capability_amendment_requested"]) == true
	finding := "TSA SD Pipeline-2021-02G VI.B.2: New or additional capabilities for meeting the Security Directive's requirements were identified or obtained but not previously approved by TSA, and no amendment has been requested"
	msg := concat("", [finding, _ev_input("implementation_plan.amendments.new_capability_amendment_requested")])
}

# ── VI.C / VI.D — Permanent change definition and 50-day filing deadline ─────

violations contains msg if {
	some c in pending_changes
	duration := object.get(c, "duration_days", 0)
	is_number(duration)
	duration >= 45
	not object.get(c, "amendment_filed", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G VI.C: Change '%s' is intended to be in effect for %v days, making it a permanent change requiring a Cybersecurity Implementation Plan amendment — none has been filed", [object.get(c, "description", "unnamed"), duration])
	msg := concat("", [finding, _ev_item(c, "amendment_filed")])
}

violations contains msg if {
	some c in pending_changes
	duration := object.get(c, "duration_days", 0)
	is_number(duration)
	duration >= 45
	elapsed := object.get(c, "days_since_effective", 0)
	is_number(elapsed)
	elapsed > 50
	msg := sprintf("TSA SD Pipeline-2021-02G VI.D: The amendment request for permanent change '%s' is %v days past the change taking effect — it must be filed with TSA no later than 50 calendar days", [object.get(c, "description", "unnamed"), elapsed])
}

# ── VI.F — Petition for reconsideration (30 days) ────────────────────────────

violations contains msg if {
	some d in denials
	object.get(d, "reconsideration_intended", false) == true
	not object.get(d, "petition_filed", null) == true
	days := object.get(d, "days_since_denial", 0)
	is_number(days)
	days > 30
	finding := sprintf("TSA SD Pipeline-2021-02G VI.F: A petition for reconsideration of the denied amendment '%s' was not filed within 30 calendar days of receiving the denial (%v days elapsed) — see 49 CFR 1570.119", [object.get(d, "description", "unnamed"), days])
	msg := concat("", [finding, _ev_item(d, "petition_filed")])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "II.B / VI",
	"name": "Cybersecurity Implementation Plan and Amendments",
	"permanent_change_threshold_days": 45,
	"amendment_filing_deadline_days": 50,
	"reconsideration_petition_deadline_days": 30,
	"requirements_evaluated": 8,
	"pending_changes_assessed": count(pending_changes),
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

_stated_booleans := [
	[["implementation_plan", "amendments", "ownership_or_control_changed"], "VI.A"],
	[["implementation_plan", "amendments", "measure_determined_ineffective"], "VI.B.1"],
	[["implementation_plan", "amendments", "new_capabilities_obtained"], "VI.B.2"],
]

violations contains msg if {
	some [path, paragraph] in _stated_booleans
	not is_boolean(object.get(facts, path, null))
	msg := sprintf("TSA SD Pipeline-2021-02G %s: input.%s is not stated as true or false, so the requirement cannot be decided%s", [paragraph, concat(".", path), _ev_input(concat(".", path))])
}

violations contains msg if {
	some c in pending_changes
	value := object.get(c, "duration_days", null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-02G VI.C: evidence missing - change '%s' has no numeric duration_days (got %s), so the limit cannot be checked", [object.get(c, "description", "unnamed"), type_name(value)])
}

violations contains msg if {
	some c in pending_changes
	is_number(c.duration_days)
	c.duration_days >= 45
	value := object.get(c, "days_since_effective", null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-02G VI.D: evidence missing - permanent change '%s' has no numeric days_since_effective (got %s), so the limit cannot be checked", [object.get(c, "description", "unnamed"), type_name(value)])
}

violations contains msg if {
	some d in denials
	not is_boolean(object.get(d, "reconsideration_intended", null))
	msg := sprintf("TSA SD Pipeline-2021-02G VI.F: denied amendment '%s' does not state reconsideration_intended as true or false, so the requirement cannot be decided%s", [object.get(d, "description", "unnamed"), _ev_item(d, "reconsideration_intended")])
}

violations contains msg if {
	some d in denials
	object.get(d, "reconsideration_intended", null) == true
	not is_boolean(object.get(d, "petition_filed", null))
	msg := sprintf("TSA SD Pipeline-2021-02G VI.F: denied amendment '%s' does not state petition_filed as true or false, so the requirement cannot be decided%s", [object.get(d, "description", "unnamed"), _ev_item(d, "petition_filed")])
}

violations contains msg if {
	some d in denials
	object.get(d, "reconsideration_intended", null) == true
	value := object.get(d, "days_since_denial", null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-02G VI.F: evidence missing - denied amendment '%s' has no numeric days_since_denial (got %s), so the limit cannot be checked", [object.get(d, "description", "unnamed"), type_name(value)])
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
