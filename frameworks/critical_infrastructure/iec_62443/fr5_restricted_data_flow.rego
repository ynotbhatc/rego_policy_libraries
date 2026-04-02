package iec_62443.fr5

import rego.v1

# =============================================================================
# IEC 62443-3-3 FR 5 — Restricted Data Flow (RDF)
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

# ---------------------------------------------------------------------------
# SR 5.1 — Network segmentation
# Segment the IACS network into zones and define conduits between zones.
# ---------------------------------------------------------------------------

violations contains msg if {
    count(input.zones) == 0
    msg := "IEC 62443 SR 5.1 (RDF): No network zones defined. IEC 62443 requires the IACS to be segmented into security zones with clearly defined boundaries."
}

violations contains msg if {
    not input.network.it_ot_segmentation
    msg := "IEC 62443 SR 5.1 (RDF): IT and OT networks are not segmented. Industrial control systems must be isolated from corporate IT networks to prevent lateral movement."
}

violations contains msg if {
    not input.network.network_inventory_documented
    msg := "IEC 62443 SR 5.1 (RDF): Network inventory is not documented. A complete inventory of all IACS network assets and their zone assignments is required."
}

violations contains msg if {
    input.network.direct_internet_connectivity_to_ics
    msg := "IEC 62443 SR 5.1 (RDF): ICS systems have direct Internet connectivity. IACS must never be directly accessible from the Internet — air-gap or multi-layer DMZ is required."
}

# SR 5.1 RE 1 (SL 2+): Independence of security zones
violations contains msg if {
    input.target_sl >= 2
    count(input.zones) < 3
    msg := sprintf(
        "IEC 62443 SR 5.1 RE 1 SL%v (RDF): Insufficient zone segmentation. At Security Level 2+, at minimum three distinct zones are required: corporate IT, DMZ, and OT/ICS control.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 5.2 — Zone boundary protection
# Protect zone boundaries through security controls on all conduits.
# ---------------------------------------------------------------------------

violations contains msg if {
    some zone in input.zones
    not zone.security_level_defined
    msg := sprintf(
        "IEC 62443 SR 5.2 (RDF): Zone '%v' does not have a defined security level. Every zone must have an assigned Security Level (SL) target and capability documented.",
        [zone.name]
    )
}

violations contains msg if {
    some conduit in input.conduits
    not conduit.firewall_or_dmz
    msg := sprintf(
        "IEC 62443 SR 5.2 (RDF): Conduit between zones '%v' and '%v' has no firewall or DMZ. Every zone boundary must be protected by a firewall or equivalent boundary control.",
        [conduit.source_zone, conduit.dest_zone]
    )
}

violations contains msg if {
    some conduit in input.conduits
    not conduit.traffic_filtered
    msg := sprintf(
        "IEC 62443 SR 5.2 (RDF): Conduit between zones '%v' and '%v' does not filter traffic. Only explicitly authorized traffic flows must be permitted across zone boundaries.",
        [conduit.source_zone, conduit.dest_zone]
    )
}

# IT/OT boundary requires unidirectional gateway at SL 3+
violations contains msg if {
    input.target_sl >= 3
    some conduit in input.conduits
    conduit.source_zone == "corporate_it"
    conduit.dest_zone == "ics_control"
    not conduit.unidirectional_gateway
    msg := sprintf(
        "IEC 62443 SR 5.2 RE 1 SL%v (RDF): The IT/OT boundary between corporate and ICS control zones lacks a unidirectional gateway (data diode). Required at Security Level 3+ for critical infrastructure.",
        [input.target_sl]
    )
}

violations contains msg if {
    not input.network.dmz_implemented
    msg := "IEC 62443 SR 5.2 (RDF): No DMZ is implemented between corporate IT and OT networks. A DMZ with controlled ingress/egress is required to isolate IACS from external networks."
}

# SR 5.2 RE 2 (SL 3+): Encrypted zone-to-zone communications
violations contains msg if {
    input.target_sl >= 3
    some conduit in input.conduits
    not conduit.encrypted
    msg := sprintf(
        "IEC 62443 SR 5.2 RE 2 SL%v (RDF): Conduit between zones '%v' and '%v' is not encrypted. All inter-zone IACS communications must be encrypted at Security Level 3+.",
        [input.target_sl, conduit.source_zone, conduit.dest_zone]
    )
}

# ---------------------------------------------------------------------------
# SR 5.3 — General purpose person-to-person communication restrictions
# Restrict general-purpose communication (email, chat) within IACS zones.
# ---------------------------------------------------------------------------

violations contains msg if {
    some zone in input.zones
    zone.security_level >= 2
    zone.general_purpose_comms_unrestricted
    msg := sprintf(
        "IEC 62443 SR 5.3 (RDF): Zone '%v' (SL %v) permits unrestricted general-purpose communications (email, instant messaging). These must be restricted or prohibited within high-security IACS zones.",
        [zone.name, zone.security_level]
    )
}

violations contains msg if {
    input.target_sl >= 2
    not input.network.general_purpose_comms_policy
    msg := sprintf(
        "IEC 62443 SR 5.3 SL%v (RDF): No policy governing general-purpose communications within IACS zones. Permitted communication types must be explicitly defined and restricted.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# SR 5.4 — Application partitioning
# Separate IACS applications from non-IACS applications.
# ---------------------------------------------------------------------------

violations contains msg if {
    some system in input.ics_systems
    not system.application_partitioning
    msg := sprintf(
        "IEC 62443 SR 5.4 (RDF): ICS system '%v' does not partition IACS applications from general-purpose applications. Business applications must not run on the same platform as control applications.",
        [system.name]
    )
}

violations contains msg if {
    input.target_sl >= 2
    some system in input.ics_systems
    not system.virtualization_isolation
    system.uses_shared_platform
    msg := sprintf(
        "IEC 62443 SR 5.4 RE 1 SL%v (RDF): ICS system '%v' uses a shared platform without virtualization isolation. Hypervisor-based isolation is required when IACS and non-IACS workloads share hardware at SL 2+.",
        [input.target_sl, system.name]
    )
}

violations contains msg if {
    input.target_sl >= 3
    some system in input.ics_systems
    not system.dedicated_hardware
    system.criticality == "high"
    msg := sprintf(
        "IEC 62443 SR 5.4 RE 2 SL%v (RDF): High-criticality ICS system '%v' does not run on dedicated hardware. Physical hardware separation from non-IACS workloads is required for high-criticality systems at SL 3+.",
        [input.target_sl, system.name]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

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
    "title":                    "Restricted Data Flow (RDF)",
    "standard":                 "IEC 62443-3-3",
    "target_sl":                input.target_sl,
    "total_srs":                4,
    "passing_srs":              fr5_passing_srs,
    "compliant":                compliant,
    "violations":               violations,
}
