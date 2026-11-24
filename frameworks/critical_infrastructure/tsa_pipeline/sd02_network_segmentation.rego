# METADATA
# title: "TSA Security Directive Pipeline-2021-02G"
# custom:
#   class: ot
#   framework: tsa_pipeline
#   source: tsa
#   domains: [ot, pipeline]
#   coverage:
#     checks: 11
#     cited: 7
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package tsa_pipeline.sd02_network_segmentation

import rego.v1

# =============================================================================
# TSA Security Directive Pipeline-2021-02G
# Section III.B — Network Segmentation Policies and Controls
#
# Directive:  SD Pipeline-2021-02G
# Effective:  May 3, 2026 through May 2, 2027
#
# Requirements evaluated: III.B.1.a–c, III.B.2.a–b (5 subparagraphs)
#
# III.B requires network segmentation policies and controls "designed to prevent
# operational disruption to the Operational Technology system if the Information
# Technology system is compromised or vice versa."
#
# Note the direction of III.B.2.b: OT system services must be prohibited from
# traversing the IT system UNLESS the content of the OT system is encrypted
# while in transit.
#
# --- INPUT CONTRACT ----------------------------------------------------------
# input.network_segmentation: {
#   "policy_documented":              boolean,
#   "it_ot_interdependencies_documented": boolean,   # III.B.1.a
#   "external_connections": {                        # III.B.1.b
#       "documented":  boolean,
#       "connections": [ { "name": string, "described": boolean } ]
#   },
#   "zones": {                                       # III.B.1.c
#       "documented":            boolean,
#       "boundaries":            [ { "name": string,
#                                    "unauthorized_comms_prevented": boolean,
#                                    "controls_described":           boolean } ],
#       "classification_basis":  [string]  # "criticality" | "consequence"
#                                          # | "operational_necessity"
#   },
#   "ot_services_traversing_it": {                    # III.B.2.b
#       "occurs":              boolean,
#       "encrypted_in_transit": boolean
#   }
# }
#
# NO FACT SOURCE EXISTS YET — see sd01_cybersecurity_coordinator.rego.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/sd02_network_segmentation
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

required_zone_classification_basis := {"criticality", "consequence", "operational_necessity"}

declared_classification_basis := {b |
	some b in object.get(facts, ["network_segmentation", "zones", "classification_basis"], [])
}

zone_boundaries := [z |
	some z in object.get(facts, ["network_segmentation", "zones", "boundaries"], [])
	is_object(z)
]

external_connections := [c |
	some c in object.get(facts, ["network_segmentation", "external_connections", "connections"], [])
	is_object(c)
]

# ── III.B — Policy exists ────────────────────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["network_segmentation", "policy_documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.B: No documented network segmentation policies and controls designed to prevent operational disruption to the Operational Technology system if the Information Technology system is compromised, or vice versa"
	msg := concat("", [finding, _ev_input("network_segmentation.policy_documented")])
}

# ── III.B.1.a — IT/OT interdependencies ──────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["network_segmentation", "it_ot_interdependencies_documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.B.1.a: No list and description of Information Technology and Operational Technology system interdependencies"
	msg := concat("", [finding, _ev_input("network_segmentation.it_ot_interdependencies_documented")])
}

# ── III.B.1.b — External connections to the OT system ────────────────────────

violations contains msg if {
	not object.get(facts, ["network_segmentation", "external_connections", "documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.B.1.b: No list and description of all external connections to the Operational Technology system"
	msg := concat("", [finding, _ev_input("network_segmentation.external_connections.documented")])
}

violations contains msg if {
	some c in external_connections
	not object.get(c, "described", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.B.1.b: External connection to the Operational Technology system '%s' is listed but not described", [object.get(c, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(c, "described")])
}

# ── III.B.1.c — Zone boundaries ──────────────────────────────────────────────

violations contains msg if {
	not object.get(facts, ["network_segmentation", "zones", "documented"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.B.1.c: No list and description of zone boundaries, including how Information Technology and Operational Technology systems are defined and organized into logical zones"
	msg := concat("", [finding, _ev_input("network_segmentation.zones.documented")])
}

violations contains msg if {
	some basis in required_zone_classification_basis
	not basis in declared_classification_basis
	msg := sprintf("TSA SD Pipeline-2021-02G III.B.1.c: Logical zones are not organized on the basis of '%s' — zones must be based on criticality, consequence, and operational necessity", [basis])
}

# ── III.B.2 — Securing and defending zone boundaries ─────────────────────────

violations contains msg if {
	count(zone_boundaries) == 0
	msg := "TSA SD Pipeline-2021-02G III.B.2: No identification or description of measures for securing and defending zone boundaries"
}

violations contains msg if {
	some z in zone_boundaries
	not object.get(z, "controls_described", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.B.2: Zone boundary '%s' has no described security controls for securing and defending the boundary", [object.get(z, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(z, "controls_described")])
}

violations contains msg if {
	some z in zone_boundaries
	not object.get(z, "unauthorized_comms_prevented", null) == true
	finding := sprintf("TSA SD Pipeline-2021-02G III.B.2.a: Zone boundary '%s' has no security control to prevent unauthorized communications between zones", [object.get(z, "name", "unnamed")])
	msg := concat("", [finding, _ev_item(z, "unauthorized_comms_prevented")])
}

# ── III.B.2.b — OT services traversing the IT system ─────────────────────────

violations contains msg if {
	object.get(facts, ["network_segmentation", "ot_services_traversing_it", "occurs"], false) == true
	not object.get(facts, ["network_segmentation", "ot_services_traversing_it", "encrypted_in_transit"], null) == true
	finding := "TSA SD Pipeline-2021-02G III.B.2.b: Operational Technology system services traverse the Information Technology system without the Operational Technology system content being encrypted while in transit"
	msg := concat("", [finding, _ev_input("network_segmentation.ot_services_traversing_it.encrypted_in_transit")])
}

# ── Compliance report ────────────────────────────────────────────────────────

compliance_report := {
	"directive": "TSA SD Pipeline-2021-02G",
	"section": "III.B",
	"name": "Network Segmentation Policies and Controls",
	"requirements_evaluated": 5,
	"zone_boundaries_assessed": count(zone_boundaries),
	"external_connections_assessed": count(external_connections),
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
	[["network_segmentation", "ot_services_traversing_it", "occurs"], "III.B.2.b"],
]

violations contains msg if {
	some [path, paragraph] in _stated_booleans
	not is_boolean(object.get(facts, path, null))
	msg := sprintf("TSA SD Pipeline-2021-02G %s: input.%s is not stated as true or false, so the requirement cannot be decided%s", [paragraph, concat(".", path), _ev_input(concat(".", path))])
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
