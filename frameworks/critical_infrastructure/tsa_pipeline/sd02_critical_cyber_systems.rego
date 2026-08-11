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
	object.get(facts, ["critical_cyber_systems", "identified"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.A: Critical Cyber Systems have not been identified as defined in Section VII of the Security Directive"
}

violations contains msg if {
	not none_declared
	count(ccs_systems) == 0
	msg := "TSA SD Pipeline-2021-02G III.A: No Critical Cyber Systems are enumerated, and no written determination of 'no Critical Cyber Systems' has been declared under Section II.A.5"
}

violations contains msg if {
	object.get(facts, ["critical_cyber_systems", "identification_methodology_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.A: The methodology and rationale used to identify Critical Cyber Systems are not documented — TSA may require this information if it disagrees with the Owner/Operator's determination"
}

# Per §VII.C, business services that could result in operational disruption are
# themselves Critical Cyber Systems — a scope that is routinely missed.
violations contains msg if {
	not none_declared
	object.get(facts, ["critical_cyber_systems", "business_services_evaluated"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.A (see VII.C): Business services were not evaluated for inclusion as Critical Cyber Systems — the definition includes business services that, if compromised or exploited, could result in operational disruption"
}

violations contains msg if {
	some s in ccs_systems
	object.get(s, "included_in_implementation_plan", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.A: Critical Cyber System '%s' is identified but is not included in the Cybersecurity Implementation Plan", [object.get(s, "name", "unnamed")])
}

# ── II.A.5 Note — "No Critical Cyber Systems" determination ──────────────────

violations contains msg if {
	none_declared
	object.get(facts, ["critical_cyber_systems", "none_determination", "tsa_notified_in_writing"], false) == false
	msg := "TSA SD Pipeline-2021-02G II.A.5: The Owner/Operator determined it has no Critical Cyber Systems but has not notified TSA in writing"
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
	object.get(facts, ["critical_cyber_systems", "none_determination", "reevaluated_after_change"], false) == false
	msg := "TSA SD Pipeline-2021-02G II.A.5: The Owner/Operator's method of operations changed but Critical Cyber Systems were not re-evaluated"
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
	object.get(m, "responsibility_retained", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G II.A.3: Security measures are delegated to or shared with Managed Security Service Provider '%s' without the Owner/Operator documenting that it retains sole responsibility for compliance with its TSA-approved Cybersecurity Implementation Plan", [object.get(m, "name", "unnamed")])
}

# ── II.A.4 — Authorized Representatives ──────────────────────────────────────

violations contains msg if {
	some a in authorized_representatives
	object.get(a, "liability_acknowledged", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G II.A.4: Authorized Representative '%s' has no documented acknowledgement of liability — both the Owner/Operator and the Authorized Representative are liable for non-compliance", [object.get(a, "name", "unnamed")])
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
