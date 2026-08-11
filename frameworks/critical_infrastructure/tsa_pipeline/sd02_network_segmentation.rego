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
	object.get(facts, ["network_segmentation", "policy_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.B: No documented network segmentation policies and controls designed to prevent operational disruption to the Operational Technology system if the Information Technology system is compromised, or vice versa"
}

# ── III.B.1.a — IT/OT interdependencies ──────────────────────────────────────

violations contains msg if {
	object.get(facts, ["network_segmentation", "it_ot_interdependencies_documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.B.1.a: No list and description of Information Technology and Operational Technology system interdependencies"
}

# ── III.B.1.b — External connections to the OT system ────────────────────────

violations contains msg if {
	object.get(facts, ["network_segmentation", "external_connections", "documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.B.1.b: No list and description of all external connections to the Operational Technology system"
}

violations contains msg if {
	some c in external_connections
	object.get(c, "described", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.B.1.b: External connection to the Operational Technology system '%s' is listed but not described", [object.get(c, "name", "unnamed")])
}

# ── III.B.1.c — Zone boundaries ──────────────────────────────────────────────

violations contains msg if {
	object.get(facts, ["network_segmentation", "zones", "documented"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.B.1.c: No list and description of zone boundaries, including how Information Technology and Operational Technology systems are defined and organized into logical zones"
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
	object.get(z, "controls_described", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.B.2: Zone boundary '%s' has no described security controls for securing and defending the boundary", [object.get(z, "name", "unnamed")])
}

violations contains msg if {
	some z in zone_boundaries
	object.get(z, "unauthorized_comms_prevented", false) == false
	msg := sprintf("TSA SD Pipeline-2021-02G III.B.2.a: Zone boundary '%s' has no security control to prevent unauthorized communications between zones", [object.get(z, "name", "unnamed")])
}

# ── III.B.2.b — OT services traversing the IT system ─────────────────────────

violations contains msg if {
	object.get(facts, ["network_segmentation", "ot_services_traversing_it", "occurs"], false) == true
	object.get(facts, ["network_segmentation", "ot_services_traversing_it", "encrypted_in_transit"], false) == false
	msg := "TSA SD Pipeline-2021-02G III.B.2.b: Operational Technology system services traverse the Information Technology system without the Operational Technology system content being encrypted while in transit"
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
