# METADATA
# title: "IEC 62443-3-2 — Security Risk Assessment for System Design"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 19
#     cited: 6
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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
	not input.risk_assessment.conducted == true
	finding := "IEC 62443-3-2 ZCR 1: No cybersecurity risk assessment has been conducted. A formal risk assessment is the foundation for all IEC 62443 security decisions and must precede system design or security level assignment."
	msg := concat("", [finding, _ev_input("risk_assessment.conducted")])
}

violations contains msg if {
	not input.risk_assessment.asset_inventory_complete == true
	finding := "IEC 62443-3-2 ZCR 1: Asset inventory is incomplete. A complete inventory of all IACS assets (hardware, software, firmware, communication paths) is a prerequisite for risk assessment."
	msg := concat("", [finding, _ev_input("risk_assessment.asset_inventory_complete")])
}

violations contains msg if {
	not input.risk_assessment.threat_modeling_performed == true
	finding := "IEC 62443-3-2 ZCR 1: No threat modeling performed. Threat modeling (identifying threat actors, threat vectors, and attack scenarios) is required to understand the IACS threat landscape."
	msg := concat("", [finding, _ev_input("risk_assessment.threat_modeling_performed")])
}

violations contains msg if {
	not input.risk_assessment.consequence_analysis_performed == true
	finding := "IEC 62443-3-2 ZCR 1: No consequence analysis performed. The impact of potential cyber incidents on safety, operations, environment, financial, and reputation must be analyzed."
	msg := concat("", [finding, _ev_input("risk_assessment.consequence_analysis_performed")])
}

violations contains msg if {
	not input.risk_assessment.vulnerability_assessment_performed == true
	finding := "IEC 62443-3-2 ZCR 1: No vulnerability assessment performed. Identify vulnerabilities in IACS components through analysis of known CVEs, configuration weaknesses, and architectural gaps."
	msg := concat("", [finding, _ev_input("risk_assessment.vulnerability_assessment_performed")])
}

violations contains msg if {
	not input.risk_assessment.cyber_risk_identified == true
	finding := "IEC 62443-3-2 ZCR 1: IACS cybersecurity risks have not been formally identified and documented. Risk register with likelihood, consequence, and risk rating is required."
	msg := concat("", [finding, _ev_input("risk_assessment.cyber_risk_identified")])
}

# ---------------------------------------------------------------------------
# System Partitioning — Zone and Conduit Definition (ZCR 2)
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.risk_assessment.zones_and_conduits_defined == true
	finding := "IEC 62443-3-2 ZCR 2: Zones and conduits have not been formally defined. Partitioning the IACS into security zones and defining conduits between zones is a core IEC 62443 architectural requirement."
	msg := concat("", [finding, _ev_input("risk_assessment.zones_and_conduits_defined")])
}

violations contains msg if {
	count(object.get(input, "zones", [])) == 0
	msg := "IEC 62443-3-2 ZCR 2: No security zones defined. The IACS must be divided into security zones based on criticality, function, and required security level."
}

violations contains msg if {
	some zone in input.zones
	not zone.risk_assessment_documented == true
	finding := sprintf(
		"IEC 62443-3-2 ZCR 2: Zone '%v' has no documented risk assessment. Each zone must have a zone-specific risk assessment driving its target security level assignment.",
		[object.get(zone, "name", "<unnamed>")],
	)
	msg := concat("", [finding, _ev_item(zone, "risk_assessment_documented")])
}

# ---------------------------------------------------------------------------
# Target Security Level Assignment (ZCR 3)
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.risk_assessment.target_sl_assigned_per_zone == true
	finding := "IEC 62443-3-2 ZCR 3: Target security levels (SL-T) have not been assigned per zone. Each zone must have a SL-T derived from the risk assessment results (SL 1–4)."
	msg := concat("", [finding, _ev_input("risk_assessment.target_sl_assigned_per_zone")])
}

violations contains msg if {
	some zone in input.zones
	not zone.security_level_defined == true
	finding := sprintf(
		"IEC 62443-3-2 ZCR 3: Zone '%v' does not have a defined security level. All zones must have an explicit SL-T (1–4) based on the zone risk assessment.",
		[object.get(zone, "name", "<unnamed>")],
	)
	msg := concat("", [finding, _ev_item(zone, "security_level_defined")])
}

# Validate that high-criticality zones have appropriate SL
violations contains msg if {
	some zone in input.zones
	zone.criticality == "high"
	is_number(zone.security_level)
	zone.security_level < 2
	msg := sprintf(
		"IEC 62443-3-2 ZCR 3: High-criticality zone '%v' has Security Level %v. High-criticality IACS zones should have SL-T of at least 2 (SL 3 or 4 recommended for BES and safety-critical systems).",
		[object.get(zone, "name", "<unnamed>"), zone.security_level],
	)
}

# Every zone: the SL-T itself is evidence, and it must be a number (a string such as "3" is a collection error).
violations contains msg if {
	some zone in input.zones
	not is_number(object.get(zone, "security_level", null))
	msg := sprintf(
		"IEC 62443-3-2 ZCR 3: evidence missing - zone '%v' has no numeric security_level (got %s), so its SL-T cannot be verified.",
		[object.get(zone, "name", "<unnamed>"), type_name(object.get(zone, "security_level", null))],
	)
}

# ---------------------------------------------------------------------------
# High-Level Security Requirements (ZCR 4)
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.risk_assessment.high_level_security_requirements == true
	finding := "IEC 62443-3-2 ZCR 4: High-level security requirements (HLSRs) have not been derived from the risk assessment. HLSRs form the basis for selecting and implementing specific security controls (mapped to IEC 62443-3-3 SRs)."
	msg := concat("", [finding, _ev_input("risk_assessment.high_level_security_requirements")])
}

# ---------------------------------------------------------------------------
# Residual Risk Evaluation (ZCR 5)
# ---------------------------------------------------------------------------

violations contains msg if {
	not input.risk_assessment.residual_risk_accepted == true
	finding := "IEC 62443-3-2 ZCR 5: Residual risk after security control implementation has not been formally evaluated and accepted. Senior management must accept documented residual risk."
	msg := concat("", [finding, _ev_input("risk_assessment.residual_risk_accepted")])
}

# ---------------------------------------------------------------------------
# Periodic Review
# ---------------------------------------------------------------------------

violations contains msg if {
	input.risk_assessment.conducted == true
	is_number(input.risk_assessment.review_frequency_months)
	input.risk_assessment.review_frequency_months > 24
	msg := sprintf(
		"IEC 62443-3-2: Risk assessment review cycle is %v months. IACS risk assessments must be reviewed at least every 24 months and after significant changes (new systems, topology changes, incident).",
		[input.risk_assessment.review_frequency_months],
	)
}

violations contains "IEC 62443-3-2: evidence missing - input.risk_assessment.review_frequency_months is not a number" if {
	input.risk_assessment.conducted == true
	not is_number(object.get(input, ["risk_assessment", "review_frequency_months"], null))
}

# ---------------------------------------------------------------------------
# Third-Party Review (recommended for SL 3+)
# ---------------------------------------------------------------------------

violations contains msg if {
	is_number(input.target_sl)
	input.target_sl >= 3
	not input.risk_assessment.third_party_review == true
	finding := sprintf(
		"IEC 62443-3-2 (SL%v): Risk assessment has not been reviewed by an independent third party. At Security Level 3+, an independent review by a qualified ICS security assessor is strongly recommended.",
		[input.target_sl],
	)
	msg := concat("", [finding, _ev_input("risk_assessment.third_party_review")])
}

# ---------------------------------------------------------------------------
# Compliance Aggregation
# ---------------------------------------------------------------------------

# SL-dependent requirements are gated on target_sl. Without a number they
# silently never run, so its absence is itself a violation.
violations contains "IEC 62443-3-2: evidence missing - input.target_sl not provided; Security Level dependent requirements cannot be evaluated" if {
	not is_number(object.get(input, "target_sl", null))
}

compliant if count(violations) == 0

compliance_report := {
	"part": "IEC 62443-3-2",
	"title": "Security Risk Assessment for System Design",
	"standard": "IEC 62443-3-2",
	"target_sl": object.get(input, "target_sl", 0),
	"compliant": compliant,
	"violations": violations,
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
