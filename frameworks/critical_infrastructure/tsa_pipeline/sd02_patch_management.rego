package tsa_pipeline.sd02_patch_management

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section III.E — Application of Security Patches and Updates
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: III.E.1, III.E.2.a–b, III.E.3 (4 subparagraphs)
#
# III.E requires the Owner/Operator to "reduce the risk of exploitation of
# unpatched systems through the application of security patches and updates for
# operating systems, applications, drivers, and firmware on Critical Cyber
# Systems consistent with the Owner/Operator's risk-based methodology."
#
# III.E.3 is the OT carve-out: where patches cannot be applied without causing
# a severe degradation of operational capability to meet business critical
# functions, the strategy must include a description AND timeline of additional
# mitigations addressing the risk created by not installing the patch.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.patch_management: {
#   "strategy_documented":       boolean,
#   "critical_patches_current":  boolean,
#   "scope": [string],   # "operating_systems" | "applications" | "drivers"
#                        # | "firmware"
#   "risk_methodology": {                             # III.E.2.a
#       "categorization_defined":   boolean,
#       "criticality_determined":   boolean,
#       "implementation_timeline_defined": boolean
#   },
#   "cisa_kev_prioritized":      boolean,             # III.E.2.b
#   "unpatchable_systems": [ {                        # III.E.3
#       "name":                    string,
#       "severe_degradation_justified": boolean,
#       "mitigations_described":   boolean,
#       "mitigation_timeline_defined": boolean
#   } ]
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_patch_management
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

required_scope := {
	"operating_systems": "operating systems",
	"applications": "applications",
	"drivers": "drivers",
	"firmware": "firmware",
}

declared_scope := {s | some s in object.get(facts, ["patch_management", "scope"], [])}

unpatchable_systems := [u |
	some u in object.get(facts, ["patch_management", "unpatchable_systems"], [])
	is_object(u)
]

# ── III.E.1 — Patch management strategy ──────────────────────────────────────

violations contains msg if {
	object.get(facts, ["patch_management", "strategy_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.E.1: No patch management strategy ensuring all critical security patches and updates on Critical Cyber Systems are current"
}

violations contains msg if {
	object.get(facts, ["patch_management", "critical_patches_current"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.E.1: Critical security patches and updates on Critical Cyber Systems are not current"
}

violations contains msg if {
	some scope, label in required_scope
	not scope in declared_scope
	msg := sprintf("TSA SD Pipeline-2021-02G III.E: The patch management strategy does not cover %s on Critical Cyber Systems", [label])
}

# ── III.E.2.a — Risk methodology ─────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["patch_management", "risk_methodology", "categorization_defined"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.E.2.a: The patch management strategy defines no risk methodology for categorizing patches and updates"
}

violations contains msg if {
	object.get(facts, ["patch_management", "risk_methodology", "criticality_determined"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.E.2.a: The patch management strategy defines no risk methodology for determining the criticality of patches and updates"
}

violations contains msg if {
	object.get(facts, ["patch_management", "risk_methodology", "implementation_timeline_defined"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.E.2.a: The patch management strategy defines no implementation timeline based on patch categorization and criticality"
}

# ── III.E.2.b — CISA Known Exploited Vulnerabilities Catalog ─────────────────

violations contains msg if {
	object.get(facts, ["patch_management", "cisa_kev_prioritized"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.E.2.b: The patch management strategy does not prioritize all security patches and updates on CISA's Known Exploited Vulnerabilities Catalog"
}

# ── III.E.3 — Systems that cannot be patched ─────────────────────────────────

violations contains msg if {
	some u in unpatchable_systems
	object.get(u, "severe_degradation_justified", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.E.3: Operational Technology system '%s' is exempted from patching without a documented justification that patching would cause a severe degradation of operational capability to meet business critical functions", [object.get(u, "name", "unnamed")])
}

violations contains msg if {
	some u in unpatchable_systems
	object.get(u, "mitigations_described", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.E.3: Operational Technology system '%s' cannot be patched, but the strategy includes no description of additional mitigations addressing the risk created by not installing the patch or update", [object.get(u, "name", "unnamed")])
}

violations contains msg if {
	some u in unpatchable_systems
	object.get(u, "mitigation_timeline_defined", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.E.3: Operational Technology system '%s' cannot be patched, but the strategy includes no timeline for the additional mitigations", [object.get(u, "name", "unnamed")])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "III.E",
	"name": "Application of Security Patches and Updates",
	"requirements_evaluated": 4,
	"unpatchable_systems_assessed": count(unpatchable_systems),
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
}
