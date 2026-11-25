# METADATA
# title: "TSA Security Directive Pipeline-2021-02G — \"Pipeline Cybersecurity Mitigation"
# custom:
#   class: ot
#   framework: tsa_pipeline
#   source: tsa
#   domains: [ot, pipeline]
#   coverage:
#     checks: 15
#     cited: 5
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package tsa_pipeline.sd02_critical_cyber_systems

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G — "Pipeline Cybersecurity Mitigation
# Actions, Contingency Planning, and Testing"
# Sections II.A.3–II.A.5 and III.A — Scope and Critical Cyber System identification
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
# Supersedes: SD Pipeline-2021-02F
# Authority:  49 U.S.C. 114(d), (f), (l), and (m)
#
# Requirements evaluated: II.A.3, II.A.4, II.A.5, III.A (7 subparagraphs)
#
# DEFINITION (§VII.C): "Critical Cyber System means any Information or
# Operational Technology system or data that, if compromised or exploited,
# could result in operational disruption. Critical Cyber Systems include
# business services that, if compromised or exploited, could result in
# operational disruption."
#
# The requirements of SD Pipeline-2021-02G apply to the covered Owner/Operator's
# Critical Cyber Systems (§II.A.5). An Owner/Operator determining it has NO
# Critical Cyber Systems must notify TSA in writing within 60 days of the
# effective date, and must re-evaluate and notify within 60 days of any change
# in its method of operations.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.critical_cyber_systems: {
#   "identified":            boolean,
#   "identification_methodology_documented": boolean,
#   "systems": [ {
#       "name":              string,
#       "type":              string,   # "information_technology" | "operational_technology"
#       "operational_disruption_impact": boolean,
#       "included_in_implementation_plan": boolean
#   } ],
#   "business_services_evaluated": boolean,
#   "none_determination": {
#       "declared":                    boolean,
#       "tsa_notified_in_writing":     boolean,
#       "days_since_effective_date":   number,
#       "operations_changed":          boolean,
#       "days_since_operations_change": number,
#       "reevaluated_after_change":    boolean
#   },
#   "managed_security_service_providers": [ {
#       "name":                       string,
#       "responsibility_retained":    boolean   # Owner/Operator retains sole
#                                               # responsibility for compliance
#   } ],
#   "authorized_representatives": [ {
#       "name":                    string,
#       "liability_acknowledged":  boolean
#   } ]
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_critical_cyber_systems
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

ccs_systems := [s |
	some s in object.get(facts, ["critical_cyber_systems", "systems"], [])
	is_object(s)
]

mssps := [m |
	some m in object.get(facts, ["critical_cyber_systems", "managed_security_service_providers"], [])
	is_object(m)
]

authorized_representatives := [a |
	some a in object.get(facts, ["critical_cyber_systems", "authorized_representatives"], [])
	is_object(a)
]

# MUST be defaulted: none_declared is referenced directly in compliance_report,
# and an undefined field collapses the entire object to {} at the endpoint.
default none_declared := false

none_declared if {
	object.get(facts, ["critical_cyber_systems", "none_determination", "declared"], false) == true
}

# ── III.A — Identification of Critical Cyber Systems ─────────────────────────

violations contains msg if {
	not none_declared
	not object.get(facts, ["critical_cyber_systems", "identified"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.A: Critical Cyber Systems have not been identified as defined in Section VII of the Security Directive"
	msg := concat("", [finding, _ev_input("critical_cyber_systems.identified")])
}

violations contains msg if {
	not none_declared
	count(ccs_systems) == 0
	msg := "TSA SD Pipeline-2021-02G III.A: No Critical Cyber Systems are enumerated, and no written determination of 'no Critical Cyber Systems' has been declared under Section II.A.5"
}

violations contains msg if {
	not object.get(facts, ["critical_cyber_systems", "identification_methodology_documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.A: The methodology and rationale used to identify Critical Cyber Systems are not documented — TSA may require this information if it disagrees with the Owner/Operator's determination"
	msg := concat("", [finding, _ev_input("critical_cyber_systems.identification_methodology_documented")])
}

# Per §VII.C, business services that could result in operational disruption are
# themselves Critical Cyber Systems — a scope that is routinely missed.
violations contains msg if {
	not none_declared
	not object.get(facts, ["critical_cyber_systems", "business_services_evaluated"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.A (see VII.C): Business services were not evaluated for inclusion as Critical Cyber Systems — the definition includes business services that, if compromised or exploited, could result in operational disruption"
	msg := concat("", [finding, _ev_input("critical_cyber_systems.business_services_evaluated")])
}

violations contains msg if {
	some s in ccs_systems
	not object.get(s, "included_in_implementation_plan", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.A: Critical Cyber System '%s' is identified but is not included in the Cybersecurity Implementation Plan", [object.get(s, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(s, "included_in_implementation_plan")])
}

# ── II.A.5 Note — "No Critical Cyber Systems" determination ──────────────────

violations contains msg if {
	none_declared
	not object.get(facts, ["critical_cyber_systems", "none_determination", "tsa_notified_in_writing"], null) == true
	finding := "TSA SD Pipeline-2021-02G II.A.5: The Owner/Operator determined it has no Critical Cyber Systems but has not notified TSA in writing"
	msg := concat("", [finding, _ev_input("critical_cyber_systems.none_determination.tsa_notified_in_writing")])
}

violations contains msg if {
	none_declared
	days := object.get(facts, ["critical_cyber_systems", "none_determination", "days_since_effective_date"], 0)
	is_number(days)
	days > 60
	msg := sprintf("TSA SD Pipeline-2021-02G II.A.5: A 'no Critical Cyber Systems' determination must be notified to TSA in writing within 60 days of the Security Directive's effective date — %d days have elapsed", [days])
}

violations contains msg if {
	none_declared
	object.get(facts, ["critical_cyber_systems", "none_determination", "operations_changed"], false) == true
	not object.get(facts, ["critical_cyber_systems", "none_determination", "reevaluated_after_change"], null) == true
	finding := "TSA SD Pipeline-2021-02G II.A.5: The Owner/Operator's method of operations changed but Critical Cyber Systems were not re-evaluated"
	msg := concat("", [finding, _ev_input("critical_cyber_systems.none_determination.reevaluated_after_change")])
}

violations contains msg if {
	none_declared
	object.get(facts, ["critical_cyber_systems", "none_determination", "operations_changed"], false) == true
	days := object.get(facts, ["critical_cyber_systems", "none_determination", "days_since_operations_change"], 0)
	is_number(days)
	days > 60
	msg := sprintf("TSA SD Pipeline-2021-02G II.A.5: TSA must be notified within 60 days of a change in method of operations to determine the compliance schedule — %d days have elapsed", [days])
}

# ── II.A.3 — Managed Security Service Providers ──────────────────────────────

violations contains msg if {
	some m in mssps
	not object.get(m, "responsibility_retained", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G II.A.3: Security measures are delegated to or shared with Managed Security Service Provider '%s' without the Owner/Operator documenting that it retains sole responsibility for compliance with its TSA-approved Cybersecurity Implementation Plan", [object.get(m, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(m, "responsibility_retained")])
}

# ── II.A.4 — Authorized Representatives ──────────────────────────────────────

violations contains msg if {
	some a in authorized_representatives
	not object.get(a, "liability_acknowledged", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G II.A.4: Authorized Representative '%s' has no documented acknowledgement of liability — both the Owner/Operator and the Authorized Representative are liable for non-compliance", [object.get(a, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(a, "liability_acknowledged")])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "II.A / III.A",
	"name": "Scope and Critical Cyber System Identification",
	"effective_date": "2026-05-03",
	"expiration_date": "2027-05-02",
	"requirements_evaluated": 7,
	"critical_cyber_systems_identified": count(ccs_systems),
	"no_critical_cyber_systems_declared": none_declared,
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
	[["critical_cyber_systems", "none_determination", "declared"], "II.A.5"],
]

violations contains msg if {
	some [path, paragraph] in _stated_booleans
	not is_boolean(object.get(facts, path, null))
	msg := sprintf("TSA SD Pipeline-2021-02G %s: input.%s is not stated as true or false, so the requirement cannot be decided%s", [paragraph, concat(".", path), _ev_input(concat(".", path))])
}

# Read only under a "no Critical Cyber Systems" determination.
violations contains msg if {
	none_declared
	value := object.get(facts, ["critical_cyber_systems", "none_determination", "days_since_effective_date"], null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-02G II.A.5: evidence missing - input.critical_cyber_systems.none_determination.days_since_effective_date is not a number (got %s), so the 60-day notification cannot be checked", [type_name(value)])
}

violations contains msg if {
	none_declared
	not is_boolean(object.get(facts, ["critical_cyber_systems", "none_determination", "operations_changed"], null))
	msg := concat("", ["TSA SD Pipeline-2021-02G II.A.5: input.critical_cyber_systems.none_determination.operations_changed is not stated as true or false, so the re-evaluation requirement cannot be decided", _ev_input("critical_cyber_systems.none_determination.operations_changed")])
}

violations contains msg if {
	none_declared
	object.get(facts, ["critical_cyber_systems", "none_determination", "operations_changed"], null) == true
	value := object.get(facts, ["critical_cyber_systems", "none_determination", "days_since_operations_change"], null)
	not is_number(value)
	msg := sprintf("TSA SD Pipeline-2021-02G II.A.5: evidence missing - input.critical_cyber_systems.none_determination.days_since_operations_change is not a number (got %s), so the 60-day notification cannot be checked", [type_name(value)])
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
