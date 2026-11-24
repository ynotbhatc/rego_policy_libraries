# METADATA
# title: "IEC 62443-3-3 FR 5 — Restricted Data Flow (RDF)"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 24
#     cited: 5
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package iec_62443.fr5

import rego.v1

# =============================================================================
# IEC 62443-3-3:2013 FR 5 — Restricted Data Flow (RDF)
#
# Edition: IEC 62443-3-3:2013 (edition 1.0, System security requirements and
# security levels). SR and RE numbers below are that edition's.
#
# Purpose: Restrict and control the flow of information within and between
# IACS zones and conduits, and between the IACS and external networks.
# The zone and conduit model is the cornerstone of IEC 62443 network architecture.
#
# Security Requirements (SRs):
#   SR 5.1 — Network segmentation
#   SR 5.2 — Zone boundary protection
#   SR 5.3 — General purpose person-to-person communication restrictions
#   SR 5.4 — Application partitioning
#
# Input shape:
#   input.target_sl                             - int (1–4)
#   input.zones[]
#     .name                                     - string
#     .security_level_defined                   - bool
#     .security_level                           - int
#     .type                                     - optional "it" | "ot" (else inferred from the name)
#     .assets_inventoried                       - bool
#   input.conduits[]
#     .source_zone                              - string
#     .dest_zone                                - string
#     .firewall_or_dmz                          - bool
#     .unidirectional_gateway                   - bool
#     .encrypted                                - bool
#     .traffic_filtered                         - bool
#   input.network
#     .it_ot_segmentation                       - bool
#     .direct_internet_connectivity_to_ics      - bool
#     .dmz_implemented                          - bool
#     .network_inventory_documented             - bool
#     .wireless_policy_documented               - bool
# =============================================================================

default compliant := false

# Zone class for the IT/OT boundary check. An explicit zones[].type wins; else the
# name is normalised (lower case, spaces/hyphens to underscores) and matched
# against common IT and OT zone names, so "Corporate-IT" / "OT" / "scada" work.
it_zone_names := {"corporate_it", "it", "enterprise", "corporate", "business"}

ot_zone_names := {"ics_control", "ot", "ics", "control", "scada", "process", "ot_control"}

_norm(name) := replace(replace(lower(sprintf("%v", [name])), " ", "_"), "-", "_")

zone_class(name) := z.type if {
	some z in input.zones
	z.name == name
	z.type in {"it", "ot"}
} else := "it" if {
	_norm(name) in it_zone_names
} else := "ot" if {
	_norm(name) in ot_zone_names
}

# ---------------------------------------------------------------------------
# SR 5.1 — Network segmentation
# Segment the IACS network into zones and define conduits between zones.
# ---------------------------------------------------------------------------

violations contains msg if {
	not _zones_collected
	msg := "IEC 62443 SR 5.1 (RDF): No network zones defined. IEC 62443 requires the IACS to be segmented into security zones with clearly defined boundaries."
}

violations contains msg if {
	not input.network.it_ot_segmentation == true
	finding := "IEC 62443 SR 5.1 (RDF): IT and OT networks are not segmented. Industrial control systems must be isolated from corporate IT networks to prevent lateral movement."
	msg := concat("", [finding, _ev_input("network.it_ot_segmentation")])
}

violations contains msg if {
	not input.network.network_inventory_documented == true
	finding := "IEC 62443 SR 5.1 (RDF): Network inventory is not documented. A complete inventory of all IACS network assets and their zone assignments is required."
	msg := concat("", [finding, _ev_input("network.network_inventory_documented")])
}

violations contains msg if {
	input.network.direct_internet_connectivity_to_ics == true
	msg := "IEC 62443 SR 5.1 (RDF): ICS systems have direct Internet connectivity. IACS must never be directly accessible from the Internet — air-gap or multi-layer DMZ is required."
}

# SR 5.1 RE 1 (SL 2+): Independence of security zones
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not _three_zones_defined
	msg := sprintf(
		"IEC 62443 SR 5.1 RE 1 SL%v (RDF): Insufficient zone segmentation. At Security Level 2+, at minimum three distinct zones are required: corporate IT, DMZ, and OT/ICS control.",
		[input.target_sl],
	)
}

# ---------------------------------------------------------------------------
# SR 5.2 — Zone boundary protection
# Protect zone boundaries through security controls on all conduits.
# ---------------------------------------------------------------------------

violations contains msg if {
	some zone in input.zones
	not zone.security_level_defined == true
	finding := sprintf(
		"IEC 62443 SR 5.2 (RDF): Zone '%v' does not have a defined security level. Every zone must have an assigned Security Level (SL) target and capability documented.",
		[zone.name],
	)
	msg := concat("", [finding, _ev_item(zone, "security_level_defined")])
}

violations contains msg if {
	some conduit in input.conduits
	not conduit.firewall_or_dmz == true
	finding := sprintf(
		"IEC 62443 SR 5.2 (RDF): Conduit between zones '%v' and '%v' has no firewall or DMZ. Every zone boundary must be protected by a firewall or equivalent boundary control.",
		[conduit.source_zone, conduit.dest_zone],
	)
	msg := concat("", [finding, _ev_item(conduit, "firewall_or_dmz")])
}

violations contains msg if {
	some conduit in input.conduits
	not conduit.traffic_filtered == true
	finding := sprintf(
		"IEC 62443 SR 5.2 (RDF): Conduit between zones '%v' and '%v' does not filter traffic. Only explicitly authorized traffic flows must be permitted across zone boundaries.",
		[conduit.source_zone, conduit.dest_zone],
	)
	msg := concat("", [finding, _ev_item(conduit, "traffic_filtered")])
}

# IT/OT boundary requires unidirectional gateway at SL 3+
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	some conduit in input.conduits
	zone_class(conduit.source_zone) == "it"
	zone_class(conduit.dest_zone) == "ot"
	not conduit.unidirectional_gateway == true
	finding := sprintf(
		"IEC 62443 SR 5.2 RE 1 SL%v (RDF): The IT/OT boundary between corporate and ICS control zones lacks a unidirectional gateway (data diode). Required at Security Level 3+ for critical infrastructure.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_item(conduit, "unidirectional_gateway")])
}

violations contains msg if {
	not input.network.dmz_implemented == true
	finding := "IEC 62443 SR 5.2 (RDF): No DMZ is implemented between corporate IT and OT networks. A DMZ with controlled ingress/egress is required to isolate IACS from external networks."
	msg := concat("", [finding, _ev_input("network.dmz_implemented")])
}

# SR 5.2 RE 2 (SL 3+): Encrypted zone-to-zone communications
violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	some conduit in input.conduits
	not conduit.encrypted == true
	finding := sprintf(
		"IEC 62443 SR 5.2 RE 2 SL%v (RDF): Conduit between zones '%v' and '%v' is not encrypted. All inter-zone IACS communications must be encrypted at Security Level 3+.",
		[input.target_sl, conduit.source_zone, conduit.dest_zone],
	)
	msg := concat("", [finding, _ev_item(conduit, "encrypted")])
}

# ---------------------------------------------------------------------------
# SR 5.3 — General purpose person-to-person communication restrictions
# Restrict general-purpose communication (email, chat) within IACS zones.
# ---------------------------------------------------------------------------

violations contains msg if {
	some zone in input.zones
	is_number(zone.security_level)
	zone.security_level >= 2
	zone.general_purpose_comms_unrestricted == true
	msg := sprintf(
		"IEC 62443 SR 5.3 (RDF): Zone '%v' (SL %v) permits unrestricted general-purpose communications (email, instant messaging). These must be restricted or prohibited within high-security IACS zones.",
		[zone.name, zone.security_level],
	)
}

violations contains msg if {
	some zone in input.zones
	zone.general_purpose_comms_unrestricted == true
	not is_number(object.get(zone, "security_level", null))
	msg := sprintf(
		"IEC 62443 SR 5.3 (RDF): evidence missing - zone '%v' permits unrestricted general-purpose communications and has no numeric security_level, so the restriction cannot be evaluated.",
		[object.get(zone, "name", "<unnamed>")],
	)
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	not input.network.general_purpose_comms_policy == true
	finding := sprintf(
		"IEC 62443 SR 5.3 SL%v (RDF): No policy governing general-purpose communications within IACS zones. Permitted communication types must be explicitly defined and restricted.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("network.general_purpose_comms_policy")])
}

# ---------------------------------------------------------------------------
# SR 5.4 — Application partitioning
# Separate IACS applications from non-IACS applications.
# ---------------------------------------------------------------------------

violations contains msg if {
	some system in input.ics_systems
	not system.application_partitioning == true
	finding := sprintf(
		"IEC 62443 SR 5.4 (RDF): ICS system '%v' does not partition IACS applications from general-purpose applications. Business applications must not run on the same platform as control applications.",
		[system.name],
	)
	msg := concat("", [finding, _ev_item(system, "application_partitioning")])
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 2
	some system in input.ics_systems
	not system.virtualization_isolation == true
	system.uses_shared_platform == true
	finding := sprintf(
		"IEC 62443 SR 5.4 RE 1 SL%v (RDF): ICS system '%v' uses a shared platform without virtualization isolation. Hypervisor-based isolation is required when IACS and non-IACS workloads share hardware at SL 2+.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "virtualization_isolation")])
}

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	some system in input.ics_systems
	not system.dedicated_hardware == true
	system.criticality == "high"
	finding := sprintf(
		"IEC 62443 SR 5.4 RE 2 SL%v (RDF): High-criticality ICS system '%v' does not run on dedicated hardware. Physical hardware separation from non-IACS workloads is required for high-criticality systems at SL 3+.",
		[input.target_sl, system.name],
	)
	msg := concat("", [finding, _ev_item(system, "dedicated_hardware")])
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Evidence missing: a requirement with no evidence cannot be reported as passing
# (semantic review 2026-11-13)
# ---------------------------------------------------------------------------

violations contains "IEC 62443 SR 5.4 (RDF): evidence missing — input.ics_systems not collected, so this requirement cannot be verified" if {
	not _ics_systems_collected
}

violations contains "IEC 62443 SR 5.3 (RDF): evidence missing — input.network not collected, so this requirement cannot be verified" if {
	not input.network
}

# SL-dependent requirements are gated on target_sl. Without a number they
# silently never run, so its absence is itself a violation.
violations contains "IEC 62443 FR 5 (RDF): evidence missing - input.target_sl not provided; Security Level dependent requirements cannot be evaluated" if {
	not is_number(object.get(input, "target_sl", null))
}

compliant if count(violations) == 0

fr5_passing_srs := count([sr |
	sr := [
		count([v | some v in violations; contains(v, "SR 5.1")]) == 0,
		count([v | some v in violations; contains(v, "SR 5.2")]) == 0,
		count([v | some v in violations; contains(v, "SR 5.3")]) == 0,
		count([v | some v in violations; contains(v, "SR 5.4")]) == 0,
	][_]
	sr == true
])

compliance_report := {
	"foundational_requirement": "FR 5",
	"title": "Restricted Data Flow (RDF)",
	"standard": "IEC 62443-3-3",
	"target_sl": object.get(input, ["target_sl"], 0),
	"total_srs": 4,
	"passing_srs": fr5_passing_srs,
	"compliant": compliant,
	"violations": violations,
}

# ---------------------------------------------------------------------------
# Facts that decide whether a requirement applies, or that fail it when true,
# must be stated as booleans. "Does not apply" is the boolean false; an absent
# fact, null or a string such as "false" is an evidence problem and a finding.
# Rows: [fact, requirement, lowest target SL at which the fact is read].
# ---------------------------------------------------------------------------

_stated_system_facts := [
	["uses_shared_platform", "SR 5.4 RE 1", 2],
]

_sl_at_least(n) if n <= 1

_sl_at_least(n) if {
	is_number(input.target_sl)
	input.target_sl >= n
}

violations contains msg if {
	some [fact, requirement, min_sl] in _stated_system_facts
	_sl_at_least(min_sl)
	some system in input.ics_systems
	not is_boolean(object.get(system, fact, null))
	msg := sprintf(
		"IEC 62443 %s (RDF): ICS system '%v' does not state %s as true or false, so the requirement cannot be decided.%s",
		[requirement, object.get(system, "name", "<unnamed>"), fact, _ev_item(system, fact)],
	)
}

violations contains msg if {
	some zone in input.zones
	not is_boolean(object.get(zone, "general_purpose_comms_unrestricted", null))
	msg := sprintf(
		"IEC 62443 SR 5.3 (RDF): zone '%v' does not state general_purpose_comms_unrestricted as true or false, so the requirement cannot be decided.%s",
		[object.get(zone, "name", "<unnamed>"), _ev_item(zone, "general_purpose_comms_unrestricted")],
	)
}

violations contains msg if {
	not is_boolean(object.get(_facts, ["network", "direct_internet_connectivity_to_ics"], null))
	msg := concat("", ["IEC 62443 SR 5.1 (RDF): input.network.direct_internet_connectivity_to_ics is not stated as true or false, so direct Internet connectivity of the IACS cannot be ruled out.", _ev_input("network.direct_internet_connectivity_to_ics")])
}

# An inventory is evidence only as a non-empty array: null, a string or an empty list is "not collected".
_ics_systems_collected if {
	is_array(input.ics_systems)
	count(input.ics_systems) > 0
}

# The zone inventory is evidence only as a non-empty array (null or a string is "not collected").
_zones_collected if {
	is_array(input.zones)
	count(input.zones) > 0
}

_three_zones_defined if {
	is_array(input.zones)
	count(input.zones) >= 3
}

# SR 5.2 is decided per conduit: without the conduit inventory the zone boundaries cannot be verified.
violations contains "IEC 62443 SR 5.2 (RDF): evidence missing - input.conduits not collected (absent, not an array or empty), so zone boundary protection cannot be verified" if {
	not _conduits_collected
}

_conduits_collected if {
	is_array(input.conduits)
	count(input.conduits) > 0
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
