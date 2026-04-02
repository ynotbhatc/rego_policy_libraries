package iec_62443.part3_2

import rego.v1

# =============================================================================
# IEC 62443-3-2 — Security Risk Assessment for System Design
#
# Purpose: Define a methodology for conducting security risk assessments for
# IACS systems. This standard bridges the gap between the high-level CSMS
# requirements (Part 2-1) and the system-level security requirements (Part 3-3)
# by providing a structured approach to identifying zones, conduits, target
# security levels, and residual risk.
#
# Key Requirement Areas:
#   - System partitioning (zone and conduit definition)
#   - Target security level (SL-T) assignment
#   - Risk assessment methodology
#   - Residual risk evaluation
#   - High-level security requirements derivation
#
# Input shape:
#   input.risk_assessment
#     .conducted                              - bool
#     .cyber_risk_identified                  - bool
#     .threat_modeling_performed              - bool
#     .vulnerability_assessment_performed     - bool
#     .residual_risk_accepted                 - bool
#     .review_frequency_months                - int
#     .asset_inventory_complete               - bool
#     .consequence_analysis_performed         - bool
#     .zones_and_conduits_defined             - bool
#     .target_sl_assigned_per_zone            - bool
#     .high_level_security_requirements       - bool
#     .third_party_review                     - bool
#   input.zones[]
#     .name                                   - string
#     .security_level_defined                 - bool
#     .security_level                         - int
#     .risk_assessment_documented             - bool
#   input.target_sl                           - int (1–4)
# =============================================================================

default compliant := false

# ---------------------------------------------------------------------------
# Initial Cybersecurity Risk Assessment (ZCR 1)
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.risk_assessment.conducted
    msg := "IEC 62443-3-2 ZCR 1: No cybersecurity risk assessment has been conducted. A formal risk assessment is the foundation for all IEC 62443 security decisions and must precede system design or security level assignment."
}

violations contains msg if {
    not input.risk_assessment.asset_inventory_complete
    msg := "IEC 62443-3-2 ZCR 1: Asset inventory is incomplete. A complete inventory of all IACS assets (hardware, software, firmware, communication paths) is a prerequisite for risk assessment."
}

violations contains msg if {
    not input.risk_assessment.threat_modeling_performed
    msg := "IEC 62443-3-2 ZCR 1: No threat modeling performed. Threat modeling (identifying threat actors, threat vectors, and attack scenarios) is required to understand the IACS threat landscape."
}

violations contains msg if {
    not input.risk_assessment.consequence_analysis_performed
    msg := "IEC 62443-3-2 ZCR 1: No consequence analysis performed. The impact of potential cyber incidents on safety, operations, environment, financial, and reputation must be analyzed."
}

violations contains msg if {
    not input.risk_assessment.vulnerability_assessment_performed
    msg := "IEC 62443-3-2 ZCR 1: No vulnerability assessment performed. Identify vulnerabilities in IACS components through analysis of known CVEs, configuration weaknesses, and architectural gaps."
}

violations contains msg if {
    not input.risk_assessment.cyber_risk_identified
    msg := "IEC 62443-3-2 ZCR 1: IACS cybersecurity risks have not been formally identified and documented. Risk register with likelihood, consequence, and risk rating is required."
}

# ---------------------------------------------------------------------------
# System Partitioning — Zone and Conduit Definition (ZCR 2)
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.risk_assessment.zones_and_conduits_defined
    msg := "IEC 62443-3-2 ZCR 2: Zones and conduits have not been formally defined. Partitioning the IACS into security zones and defining conduits between zones is a core IEC 62443 architectural requirement."
}

violations contains msg if {
    count(input.zones) == 0
    msg := "IEC 62443-3-2 ZCR 2: No security zones defined. The IACS must be divided into security zones based on criticality, function, and required security level."
}

violations contains msg if {
    some zone in input.zones
    not zone.risk_assessment_documented
    msg := sprintf(
        "IEC 62443-3-2 ZCR 2: Zone '%v' has no documented risk assessment. Each zone must have a zone-specific risk assessment driving its target security level assignment.",
        [zone.name]
    )
}

# ---------------------------------------------------------------------------
# Target Security Level Assignment (ZCR 3)
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.risk_assessment.target_sl_assigned_per_zone
    msg := "IEC 62443-3-2 ZCR 3: Target security levels (SL-T) have not been assigned per zone. Each zone must have a SL-T derived from the risk assessment results (SL 1–4)."
}

violations contains msg if {
    some zone in input.zones
    not zone.security_level_defined
    msg := sprintf(
        "IEC 62443-3-2 ZCR 3: Zone '%v' does not have a defined security level. All zones must have an explicit SL-T (1–4) based on the zone risk assessment.",
        [zone.name]
    )
}

# Validate that high-criticality zones have appropriate SL
violations contains msg if {
    some zone in input.zones
    zone.criticality == "high"
    zone.security_level < 2
    msg := sprintf(
        "IEC 62443-3-2 ZCR 3: High-criticality zone '%v' has Security Level %v. High-criticality IACS zones should have SL-T of at least 2 (SL 3 or 4 recommended for BES and safety-critical systems).",
        [zone.name, zone.security_level]
    )
}

# ---------------------------------------------------------------------------
# High-Level Security Requirements (ZCR 4)
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.risk_assessment.high_level_security_requirements
    msg := "IEC 62443-3-2 ZCR 4: High-level security requirements (HLSRs) have not been derived from the risk assessment. HLSRs form the basis for selecting and implementing specific security controls (mapped to IEC 62443-3-3 SRs)."
}

# ---------------------------------------------------------------------------
# Residual Risk Evaluation (ZCR 5)
# ---------------------------------------------------------------------------

violations contains msg if {
    not input.risk_assessment.residual_risk_accepted
    msg := "IEC 62443-3-2 ZCR 5: Residual risk after security control implementation has not been formally evaluated and accepted. Senior management must accept documented residual risk."
}

# ---------------------------------------------------------------------------
# Periodic Review
# ---------------------------------------------------------------------------

violations contains msg if {
    input.risk_assessment.conducted
    input.risk_assessment.review_frequency_months > 24
    msg := sprintf(
        "IEC 62443-3-2: Risk assessment review cycle is %v months. IACS risk assessments must be reviewed at least every 24 months and after significant changes (new systems, topology changes, incident).",
        [input.risk_assessment.review_frequency_months]
    )
}

# ---------------------------------------------------------------------------
# Third-Party Review (recommended for SL 3+)
# ---------------------------------------------------------------------------

violations contains msg if {
    input.target_sl >= 3
    not input.risk_assessment.third_party_review
    msg := sprintf(
        "IEC 62443-3-2 (SL%v): Risk assessment has not been reviewed by an independent third party. At Security Level 3+, an independent review by a qualified ICS security assessor is strongly recommended.",
        [input.target_sl]
    )
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

compliant if { count(violations) == 0 }

compliance_report := {
    "part":       "IEC 62443-3-2",
    "title":      "Security Risk Assessment for System Design",
    "standard":   "IEC 62443-3-2",
    "target_sl":  input.target_sl,
    "compliant":  compliant,
    "violations": violations,
}
