# NIST SP 800-160 Vol. 2 Rev. 1 — Developing Cyber-Resilient Systems: A Systems Security Engineering Approach
# One attested row per cyber resiliency implementation approach (Appendix D, Table D-4): 50 approaches under 14 techniques.
#
# Source of truth: NIST SP 800-160 Vol. 2 Rev. 1, December 2021 (PDF, 310 pages),
#   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v2r1.pdf
#   sha256 d3e9830faadfd1e7a43392194320c5203935c3d7f30f78896b55a8a53e0f0b15, retrieved 2026-10-14.
# NIST text is public domain. Every name, definition and mapping below was copied from the PDF by a generator
# (PyMuPDF line/word coordinates, footnote superscripts dropped); nothing is paraphrased.
#
# Where each construct comes from (printed page numbers):
#   approaches          Table D-4 (pp. 93-106): the row text is the approach's 'Definition:' verbatim; the informal
#                       description, discussion and examples are not carried.
#   techniques          Section 2.1.3 numbered list (p. 13), definitions verbatim. Table D-4 words three of them
#                       differently (Diversity 'that exploit' for 'exploiting'; Privilege Restriction without the comma
#                       before 'as well as'; Realignment 'to meet' for 'to align with' and 'the technical' for
#                       'technical'); §2.1.3 is used.
#   objectives per approach  Table D-13 (pp. 133-135), read by X position against the table's column rules. Check:
#                       every technique row equals the union of its approaches' rows (14 of 14 agree).
#   goals               Table 2 (p. 10); objectives Table 3 (pp. 11-12); goals per objective Table D-12 (p. 132).
#   design principles   Table D-6 strategic (5) and Table D-9 structural (14), names as printed.
#   sp800_53            Table E-1 (pp. 140-154), 'RESILIENCY TECHNIQUE [APPROACHES]' column: each control or
#                       enhancement listed against an approach of that technique. Data only: no control is evaluated here.
#
# Id rule. The publication prints no technique abbreviations and no approach identifiers (checked: §2.1.3, Figure 1,
# Tables D-2, D-3, D-4, D-13, E-1, F-3, and the Appendix B abbreviation list), so ids are derived, never invented:
#   technique id = technique name as printed in §2.1.3, lower-cased, every run of non-alphanumerics -> '-'
#                  (adaptive-response, non-persistence, substantiated-integrity)
#   approach id  = <technique id> '.' <approach name as printed in Table D-13, same slug rule>
#                  (adaptive-response.dynamic-reconfiguration, coordinated-protection.calibrated-defense-in-depth)
#   objective/goal/design-principle ids follow the same slug rule on the printed name (prevent-or-avoid, re-architect).
#
# Techniques (approaches per technique; Table E-1 control mappings per technique):
#    1 adaptive-response           3 approaches,  30 control mappings
#    2 analytic-monitoring         3 approaches,  58 control mappings
#    3 contextual-awareness        3 approaches,  20 control mappings
#    4 coordinated-protection      4 approaches,  35 control mappings
#    5 deception                   4 approaches,  23 control mappings
#    6 diversity                   6 approaches,  23 control mappings
#    7 dynamic-positioning         5 approaches,  10 control mappings
#    8 non-persistence             3 approaches,  16 control mappings
#    9 privilege-restriction       3 approaches,  38 control mappings
#   10 realignment                 6 approaches,  33 control mappings
#   11 redundancy                  3 approaches,  16 control mappings
#   12 segmentation                2 approaches,  46 control mappings
#   13 substantiated-integrity     3 approaches,  62 control mappings
#   14 unpredictability            2 approaches,   8 control mappings
#   total                          50 approaches, 418 (control, approach) mapping rows over 265 Table E-1 controls
#
# Source irregularities, kept out of the data rather than corrected:
#   Table E-1 SI-19(6) lists 'Uncertainty [Contextual Uncertainty]' — no such technique/approach; not mapped.
#   Table E-1 SC-7(15) lists 'Privilege Restriction [Trust-Based Privileged Management]' — not an approach name; not mapped
#     (its other approaches are mapped).
#   Table E-1 SR-7 lists 'Deception [Obfuscation, Disinformation, Self-Challenge]' — Self-Challenge is a Coordinated
#     Protection approach; the Deception/Self-Challenge pair is not mapped (Obfuscation, Disinformation are).
#   Table E-1 CM-5(6) prints 'Privilege Restriction Trust-Based Privilege Management]' without the opening bracket;
#     the name matches exactly, so it is mapped to privilege-restriction.trust-based-privilege-management.
#   Figure 1 labels the Substantiated Integrity approach 'Behavioral Validation'; Tables D-4, D-13 and E-1 print
#     'Behavior Validation', which is used.
#
# Input: input.nist_sp_800_160v2.approaches["<approach id>"] == true means the organisation attests that the
# approach is implemented for the system of interest.
# Gate: input.nist_sp_800_160v2.scope.techniques_selected — optional list of technique ids. Absent: all 14 techniques
# (all 50 approaches) are evaluated. Present: only the approaches of the listed techniques are evaluated; the others are
# reported 'not_selected' and are not violations. An empty list, a non-list, a non-string or unknown technique id is a
# violation and the gate is then ignored (all approaches evaluated). Any other key under scope is an undeclared gate
# flag and a violation; a non-object scope is a violation.
# Fail-closed: a missing or non-object approaches container is a FAIL-CLOSED violation; an in-scope approach that is
# missing, false or not exactly true is a violation; an unknown approach id is a violation even when the gate is set.
#
# Query: POST /v1/data/nist/sp800_160v2/main/compliance_report

# METADATA
# title: "NIST SP 800-160 Vol. 2 Rev. 1 — 50 cyber resiliency implementation approaches (Table D-4), attested"
# custom:
#   class: compliance
#   framework: nist_sp_800_160v2
#   source: nist
#   domains: [us-federal, secure-development]
#   coverage:
#     checks: 57
#     cited: 52
#     expected: 50
#     found: 52
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_160v2.main

import rego.v1

source := {
	"publication": "NIST SP 800-160 Vol. 2 Rev. 1, Developing Cyber-Resilient Systems: A Systems Security Engineering Approach",
	"date": "December 2021",
	"url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-160v2r1.pdf",
	"sha256": "d3e9830faadfd1e7a43392194320c5203935c3d7f30f78896b55a8a53e0f0b15",
	"retrieved": "2026-10-14",
}

# Table 2 — the 4 cyber resiliency goals (description verbatim)
goals := {
	"anticipate": "Maintain a state of informed preparedness for adversity.",
	"withstand": "Continue essential mission or business functions despite adversity.",
	"recover": "Restore mission or business functions during and after adversity.",
	"adapt": "Modify mission or business functions and/or supporting capabilities in response to predicted changes in the technical, operational, or threat environments.",
}

# Table 2 goal names as printed
goal_names := {
	"anticipate": "ANTICIPATE",
	"withstand": "WITHSTAND",
	"recover": "RECOVER",
	"adapt": "ADAPT",
}

# Table 3 — the 8 cyber resiliency objectives (description verbatim)
objectives := {
	"prevent-or-avoid": "Preclude the successful execution of an attack or the realization of adverse conditions.",
	"prepare": "Maintain a set of realistic courses of action that address predicted or anticipated adversity.",
	"continue": "Maximize the duration and viability of essential mission or business functions during adversity.",
	"constrain": "Limit damage from adversity.",
	"reconstitute": "Restore as much mission or business functionality as possible after adversity.",
	"understand": "Maintain useful representations of mission and business dependencies and the status of resources with respect to possible adversity.",
	"transform": "Modify mission or business functions and supporting processes to handle adversity and address environmental changes more effectively.",
	"re-architect": "Modify architectures to handle adversity and address environmental changes more effectively.",
}

# Table 3 objective names as printed
objective_names := {
	"prevent-or-avoid": "PREVENT OR AVOID",
	"prepare": "PREPARE",
	"continue": "CONTINUE",
	"constrain": "CONSTRAIN",
	"reconstitute": "RECONSTITUTE",
	"understand": "UNDERSTAND",
	"transform": "TRANSFORM",
	"re-architect": "RE-ARCHITECT",
}

# Table D-12 — goals each objective supports
objective_goals := {
	"prevent-or-avoid": ["anticipate", "withstand"],
	"prepare": ["anticipate", "withstand", "recover", "adapt"],
	"continue": ["withstand", "recover"],
	"constrain": ["withstand", "recover"],
	"reconstitute": ["recover"],
	"understand": ["anticipate", "withstand", "recover", "adapt"],
	"transform": ["recover", "adapt"],
	"re-architect": ["recover", "adapt"],
}

# Section 2.1.3 — the 14 cyber resiliency techniques (names as printed, in the document's order)
techniques := {
	"adaptive-response": "Adaptive Response",
	"analytic-monitoring": "Analytic Monitoring",
	"contextual-awareness": "Contextual Awareness",
	"coordinated-protection": "Coordinated Protection",
	"deception": "Deception",
	"diversity": "Diversity",
	"dynamic-positioning": "Dynamic Positioning",
	"non-persistence": "Non-Persistence",
	"privilege-restriction": "Privilege Restriction",
	"realignment": "Realignment",
	"redundancy": "Redundancy",
	"segmentation": "Segmentation",
	"substantiated-integrity": "Substantiated Integrity",
	"unpredictability": "Unpredictability",
}

# Section 2.1.3 technique definitions verbatim
technique_definitions := {
	"adaptive-response": "Implement agile courses of action to manage risks.",
	"analytic-monitoring": "Monitor and analyze a wide range of properties and behaviors on an ongoing basis and in a coordinated way.",
	"contextual-awareness": "Construct and maintain current representations of the posture of missions or business functions while considering threat events and courses of action.",
	"coordinated-protection": "Ensure that protection mechanisms operate in a coordinated and effective manner.",
	"deception": "Mislead, confuse, hide critical assets from, or expose covertly tainted assets to the adversary.",
	"diversity": "Use heterogeneity to minimize common mode failures, particularly threat events exploiting common vulnerabilities.",
	"dynamic-positioning": "Distribute and dynamically relocate functionality or system resources.",
	"non-persistence": "Generate and retain resources as needed or for a limited time.",
	"privilege-restriction": "Restrict privileges based on attributes of users and system elements, as well as on environmental factors.",
	"realignment": "Structure systems and resource uses to align with mission or business function needs, reduce current and anticipated risks, and accommodate the evolution of technical, operational, and threat environments.",
	"redundancy": "Provide multiple protected instances of critical resources.",
	"segmentation": "Define and separate system elements based on criticality and trustworthiness.",
	"substantiated-integrity": "Ascertain whether critical system elements have been corrupted.",
	"unpredictability": "Make changes randomly or unpredictably.",
}

# Table D-13 — objectives marked on each technique's own row
technique_objectives := {
	"adaptive-response": ["prevent-or-avoid", "prepare", "continue", "constrain", "reconstitute", "understand"],
	"analytic-monitoring": ["continue", "constrain", "reconstitute", "understand"],
	"contextual-awareness": ["prepare", "continue", "reconstitute", "understand"],
	"coordinated-protection": ["prevent-or-avoid", "prepare", "continue", "reconstitute", "understand", "transform", "re-architect"],
	"deception": ["prevent-or-avoid", "understand"],
	"diversity": ["prevent-or-avoid", "prepare", "continue", "constrain", "re-architect"],
	"dynamic-positioning": ["prevent-or-avoid", "continue", "constrain", "reconstitute", "understand"],
	"non-persistence": ["prevent-or-avoid", "constrain", "transform", "re-architect"],
	"privilege-restriction": ["prevent-or-avoid", "constrain", "reconstitute"],
	"realignment": ["prevent-or-avoid", "transform", "re-architect"],
	"redundancy": ["prevent-or-avoid", "prepare", "continue", "reconstitute", "transform", "re-architect"],
	"segmentation": ["prevent-or-avoid", "constrain", "reconstitute", "re-architect"],
	"substantiated-integrity": ["continue", "constrain", "reconstitute", "understand"],
	"unpredictability": ["prevent-or-avoid", "constrain"],
}

# Table D-6 — strategic cyber resiliency design principles (names as printed)
strategic_design_principles := {
	"focus-on-common-critical-assets": "FOCUS ON COMMON CRITICAL ASSETS.",
	"support-agility-and-architect-for-adaptability": "SUPPORT AGILITY AND ARCHITECT FOR ADAPTABILITY.",
	"reduce-attack-surfaces": "REDUCE ATTACK SURFACES.",
	"assume-compromised-resources": "ASSUME COMPROMISED RESOURCES.",
	"expect-adversaries-to-evolve": "EXPECT ADVERSARIES TO EVOLVE.",
}

# Table D-9 — structural cyber resiliency design principles (names as printed)
structural_design_principles := {
	"limit-the-need-for-trust": "LIMIT THE NEED FOR TRUST.",
	"control-visibility-and-use": "CONTROL VISIBILITY AND USE.",
	"contain-and-exclude-behaviors": "CONTAIN AND EXCLUDE BEHAVIORS.",
	"layer-defenses-and-partition-resources": "LAYER DEFENSES AND PARTITION RESOURCES.",
	"plan-and-manage-diversity": "PLAN AND MANAGE DIVERSITY.",
	"maintain-redundancy": "MAINTAIN REDUNDANCY.",
	"make-resources-location-versatile": "MAKE RESOURCES LOCATION-VERSATILE.",
	"leverage-health-and-status-data": "LEVERAGE HEALTH AND STATUS DATA.",
	"maintain-situational-awareness": "MAINTAIN SITUATIONAL AWARENESS.",
	"manage-resources-risk-adaptively": "MANAGE RESOURCES (RISK-) ADAPTIVELY.",
	"maximize-transience": "MAXIMIZE TRANSIENCE.",
	"determine-ongoing-trustworthiness": "DETERMINE ONGOING TRUSTWORTHINESS.",
	"change-or-disrupt-the-attack-surface": "CHANGE OR DISRUPT THE ATTACK SURFACE.",
	"make-the-effects-of-deception-and-unpredictability-user-transparent": "MAKE THE EFFECTS OF DECEPTION AND UNPREDICTABILITY USER-TRANSPARENT.",
}

# Table D-4 — the 50 implementation approaches. text = the approach 'Definition:' verbatim; objectives from Table D-13;
# sp800_53 = SP 800-53 Rev 5 controls/enhancements Table E-1 maps to the approach (data only, in table order).
approaches := {
	"adaptive-response.dynamic-reconfiguration": {
		"technique": "adaptive-response",
		"name": "Dynamic Reconfiguration",
		"text": "Make changes to individual systems, system elements, components, or sets of resources to change functionality or behavior without interrupting service.",
		"objectives": ["prevent-or-avoid", "continue", "constrain", "reconstitute", "understand"],
		"sp800_53": ["AC-2(6)", "AC-2(8)", "AC-4(3)", "CP-2(5)", "IR-4(2)", "IR-4(3)", "IR-4(9)", "IR-4(11)", "SC-7(20)"],
		"page": "93",
	},
	"adaptive-response.dynamic-resource-allocation": {
		"technique": "adaptive-response",
		"name": "Dynamic Resource Allocation",
		"text": "Change the allocation of resources to tasks or functions without terminating critical functions or processes.",
		"objectives": ["prevent-or-avoid", "continue", "constrain", "reconstitute"],
		"sp800_53": ["AC-2(8)", "AU-5(3)", "SC-5(2)"],
		"page": "93",
	},
	"adaptive-response.adaptive-management": {
		"technique": "adaptive-response",
		"name": "Adaptive Management",
		"text": "Change how mechanisms are used based on changes in the operational environment as well as changes in the threat environment.",
		"objectives": ["prevent-or-avoid", "prepare", "continue", "constrain", "reconstitute", "understand"],
		"sp800_53": ["AC-2(8)", "AC-4(3)", "AU-5(3)", "AU-6", "AU-13", "CP-2(5)", "CP-12", "CP-13", "IA-10", "IR-4(3)", "IR-4(11)", "PE-6(2)", "RA-3(3)", "SA-8(16)", "SC-36(1)", "SI-4(3)", "SI-4(7)", "SI-7(5)"],
		"page": "93",
	},
	"analytic-monitoring.monitoring-and-damage-assessment": {
		"technique": "analytic-monitoring",
		"name": "Monitoring and Damage Assessment",
		"text": "Monitor and analyze behavior and characteristics of components and resources to look for indicators of adversary activity or precursor conditions or indications of other threat events and to detect and assess damage from adversity.",
		"objectives": ["continue", "constrain", "reconstitute", "understand"],
		"sp800_53": ["AC-2(12)", "AC-23", "AU-6", "AU-6(8)", "AU-13", "AU-13(3)", "CA-7(6)", "CM-2(7)", "CM-8(3)", "IR-4(13)", "IR-5", "PE-6", "PE-6(2)", "PE-6(4)", "PM-31", "RA-5(4)", "RA-5(5)", "RA-10", "SC-5(3)", "SC-7(10)", "SC-26", "SC-35", "SI-4(2)", "SI-4(4)", "SI-4(7)", "SI-4(10)", "SI-4(11)", "SI-4(13)", "SI-4(18)", "SI-4(24)", "SI-4(25)", "SI-7(7)", "SR-6(1)", "SR-10"],
		"page": "93",
	},
	"analytic-monitoring.sensor-fusion-and-analysis": {
		"technique": "analytic-monitoring",
		"name": "Sensor Fusion and Analysis",
		"text": "Fuse and analyze monitoring data and analysis results from different information sources or at different times together with externally provided threat intelligence.",
		"objectives": ["understand"],
		"sp800_53": ["AU-6(3)", "AU-6(5)", "AU-6(6)", "AU-6(9)", "IR-4(4)", "PM-31", "RA-5(6)", "RA-5(8)", "RA-5(10)", "SI-4(1)", "SI-4(3)", "SI-4(16)", "SI-4(17)", "SI-4(24)", "SI-4(25)"],
		"page": "94",
	},
	"analytic-monitoring.forensic-and-behavioral-analysis": {
		"technique": "analytic-monitoring",
		"name": "Forensic and Behavioral Analysis",
		"text": "Analyze indicators and adversary TTPs, including observed behavior, malware, and other artifacts left behind by adverse events.",
		"objectives": ["understand"],
		"sp800_53": ["CM-2(7)", "IR-4(11)", "IR-4(12)", "IR-5", "SC-26", "SC-35", "SC-44", "SI-3(10)", "SR-10"],
		"page": "94",
	},
	"contextual-awareness.dynamic-resource-awareness": {
		"technique": "contextual-awareness",
		"name": "Dynamic Resource Awareness",
		"text": "Maintain current information about resources, the status of resources, and resource connectivity.",
		"objectives": ["prepare", "understand"],
		"sp800_53": ["CA-7(3)", "SI-4(16)", "SI-4(17)"],
		"page": "94",
	},
	"contextual-awareness.dynamic-threat-awareness": {
		"technique": "contextual-awareness",
		"name": "Dynamic Threat Awareness",
		"text": "Maintain current information about threat actors, indicators, and potential, predicted, and observed adverse events.",
		"objectives": ["understand"],
		"sp800_53": ["AT-2(1)", "AT-2(3)", "AT-2(5)", "AT-3(3)", "CA-7(3)", "IR-4(4)", "PM-16", "PM-16(1)", "RA-3(2)", "RA-3(3)", "RA-3(4)", "RA-10", "SA-11(2)"],
		"page": "94",
	},
	"contextual-awareness.mission-dependency-and-status-visualization": {
		"technique": "contextual-awareness",
		"name": "Mission Dependency and Status Visualization",
		"text": "Maintain current information about the status of missions or business functions, dependencies on resources, and the status of those resources with respect to threats.",
		"objectives": ["prepare", "continue", "reconstitute", "understand"],
		"sp800_53": ["CP-2(8)", "RA-9", "SI-4(1)", "SI-4(2)"],
		"page": "95",
	},
	"coordinated-protection.calibrated-defense-in-depth": {
		"technique": "coordinated-protection",
		"name": "Calibrated Defense-in-Depth",
		"text": "Provide complementary protective mechanisms at different architectural layers or in different locations, calibrating the strength and number of mechanisms to resource value.",
		"objectives": ["prevent-or-avoid", "prepare", "reconstitute"],
		"sp800_53": ["IA-2(6)", "IA-2(13)", "IA-10", "PE-6(4)", "PL-8(1)", "SA-8(3)"],
		"page": "95",
	},
	"coordinated-protection.consistency-analysis": {
		"technique": "coordinated-protection",
		"name": "Consistency Analysis",
		"text": "Determine whether and how protections can be applied in a coordinated, consistent way that minimizes interference, potential cascading failures, or coverage gaps.",
		"objectives": ["prevent-or-avoid", "prepare", "reconstitute", "understand", "transform", "re-architect"],
		"sp800_53": ["AC-6(7)", "CA-7(5)", "CP-2(1)", "SA-8(4)"],
		"page": "95",
	},
	"coordinated-protection.orchestration": {
		"technique": "coordinated-protection",
		"name": "Orchestration",
		"text": "Coordinate modifications to and the ongoing behavior of mechanisms and processes at different layers, in different locations, or implemented for different aspects of trustworthiness to avoid causing cascading failures, interference, or coverage gaps.",
		"objectives": ["prevent-or-avoid", "prepare", "continue", "reconstitute", "understand", "transform", "re-architect"],
		"sp800_53": ["AC-4(29)", "CP-2(5)", "IA-2(6)", "IA-2(13)", "IR-4(3)", "IR-4(4)", "IR-4(10)", "IR-4(11)", "PE-6(2)", "SA-8(8)", "SA-17(8)", "SC-3(5)", "SC-36(2)"],
		"page": "96",
	},
	"coordinated-protection.self-challenge": {
		"technique": "coordinated-protection",
		"name": "Self-Challenge",
		"text": "Affect mission or business processes or system elements adversely in a controlled manner to validate the effectiveness of protections and enable proactive response and improvement.",
		"objectives": ["prepare", "understand"],
		"sp800_53": ["AT-2(1)", "AT-3(3)", "CA-8", "CA-8(1)", "CA-8(2)", "CA-8(3)", "CP-4(5)", "CP-9(1)", "SA-11(5)", "SC-7(10)", "SI-19(8)", "SR-6(1)"],
		"page": "96",
	},
	"deception.obfuscation": {
		"technique": "deception",
		"name": "Obfuscation",
		"text": "Hide, transform, or otherwise obscure the contents, properties, or presence of information or other assets from the adversary.",
		"objectives": ["prevent-or-avoid"],
		"sp800_53": ["CP-9(8)", "IA-3(1)", "SC-7(16)", "SC-8(1)", "SC-8(4)", "SC-28(1)", "SC-30", "SC-30(5)", "SC-40(2)", "SC-40(3)", "SI-19(4)", "SI-19(6)", "SR-3(2)", "SR-5", "SR-7", "SR-9(1)"],
		"page": "96",
	},
	"deception.disinformation": {
		"technique": "deception",
		"name": "Disinformation",
		"text": "Provide deliberately misleading information to adversaries.",
		"objectives": ["prevent-or-avoid"],
		"sp800_53": ["SC-30(4)", "SR-7"],
		"page": "97",
	},
	"deception.misdirection": {
		"technique": "deception",
		"name": "Misdirection",
		"text": "Maintain deception resources or environments, and direct adversary activities there.",
		"objectives": ["prevent-or-avoid", "understand"],
		"sp800_53": ["SC-26", "SC-30", "SC-35", "SC-44"],
		"page": "97",
	},
	"deception.tainting": {
		"technique": "deception",
		"name": "Tainting",
		"text": "Embed covert capabilities in resources.",
		"objectives": ["understand"],
		"sp800_53": ["SI-20"],
		"page": "97",
	},
	"diversity.architectural-diversity": {
		"technique": "diversity",
		"name": "Architectural Diversity",
		"text": "Use multiple sets of technical standards, different technologies, and different architectural patterns.",
		"objectives": ["prepare", "continue", "re-architect"],
		"sp800_53": ["AU-9(7)", "CP-8(3)", "CP-11", "CP-13", "SC-27", "SC-29", "SC-29(1)"],
		"page": "98",
	},
	"diversity.design-diversity": {
		"technique": "diversity",
		"name": "Design Diversity",
		"text": "Use different designs within a given architecture to meet the same requirements or provide equivalent functionality.",
		"objectives": ["prepare", "continue", "re-architect"],
		"sp800_53": ["AC-4(27)", "AC-4(30)", "CP-11", "CP-13", "SA-17(9)"],
		"page": "98",
	},
	"diversity.synthetic-diversity": {
		"technique": "diversity",
		"name": "Synthetic Diversity",
		"text": "Transform implementations of software to produce a variety of instances.",
		"objectives": ["prevent-or-avoid", "prepare", "continue", "constrain"],
		"sp800_53": ["SI-16"],
		"page": "98",
	},
	"diversity.information-diversity": {
		"technique": "diversity",
		"name": "Information Diversity",
		"text": "Provide information from different sources or transform information in different ways.",
		"objectives": ["prepare", "continue", "re-architect"],
		"sp800_53": ["SI-22"],
		"page": "98",
	},
	"diversity.path-diversity": {
		"technique": "diversity",
		"name": "Path Diversity",
		"text": "Provide multiple independent paths for command, control, and communications.",
		"objectives": ["prepare", "continue", "re-architect"],
		"sp800_53": ["AC-7(4)", "IA-2(6)", "IA-2(13)", "SC-37", "SC-47"],
		"page": "98",
	},
	"diversity.supply-chain-diversity": {
		"technique": "diversity",
		"name": "Supply Chain Diversity",
		"text": "Use multiple independent supply chains for critical components.",
		"objectives": ["prepare", "continue", "re-architect"],
		"sp800_53": ["PL-8(2)", "SR-3(1)", "SR-3(2)", "SR-5(1)"],
		"page": "99",
	},
	"dynamic-positioning.functional-relocation-of-sensors": {
		"technique": "dynamic-positioning",
		"name": "Functional Relocation of Sensors",
		"text": "Relocate sensors or reallocate responsibility for specific sensing tasks to look for indicators of adverse events.",
		"objectives": ["reconstitute", "understand"],
		"sp800_53": ["IR-4(2)", "SC-48", "SC-48(1)"],
		"page": "99",
	},
	"dynamic-positioning.functional-relocation-of-cyber-resources": {
		"technique": "dynamic-positioning",
		"name": "Functional Relocation of Cyber Resources",
		"text": "Change the location of cyber resources that provide functionality or information, either by moving the assets or by transferring functional responsibility.",
		"objectives": ["prevent-or-avoid", "continue", "constrain"],
		"sp800_53": ["SC-7(16)", "SC-30(3)", "SC-36"],
		"page": "99",
	},
	"dynamic-positioning.asset-mobility": {
		"technique": "dynamic-positioning",
		"name": "Asset Mobility",
		"text": "Securely move physical resources.",
		"objectives": ["prevent-or-avoid", "continue", "constrain"],
		"sp800_53": ["SC-30(3)"],
		"page": "99",
	},
	"dynamic-positioning.fragmentation": {
		"technique": "dynamic-positioning",
		"name": "Fragmentation",
		"text": "Partition information and distribute it across multiple components.",
		"objectives": ["prevent-or-avoid", "reconstitute"],
		"sp800_53": ["SI-23"],
		"page": "99",
	},
	"dynamic-positioning.distributed-functionality": {
		"technique": "dynamic-positioning",
		"name": "Distributed Functionality",
		"text": "Decompose a function or application into smaller functions, and distribute those functions across multiple components.",
		"objectives": ["prevent-or-avoid", "reconstitute"],
		"sp800_53": ["SA-8(17)", "SC-36"],
		"page": "100",
	},
	"non-persistence.non-persistent-information": {
		"technique": "non-persistence",
		"name": "Non-Persistent Information",
		"text": "Refresh information periodically, or generate information on demand and delete it when no longer needed.",
		"objectives": ["prevent-or-avoid", "constrain", "transform", "re-architect"],
		"sp800_53": ["SC-7(10)", "SC-23(3)", "SC-25", "SC-34(1)", "SI-14(1)", "SI-14(2)", "SI-21"],
		"page": "100",
	},
	"non-persistence.non-persistent-services": {
		"technique": "non-persistence",
		"name": "Non-Persistent Services",
		"text": "Refresh services periodically, or generate services on demand and terminate services when no longer needed.",
		"objectives": ["prevent-or-avoid", "constrain", "transform", "re-architect"],
		"sp800_53": ["AC-12", "SC-25", "SC-29(1)", "SI-14", "SI-14(1)"],
		"page": "100",
	},
	"non-persistence.non-persistent-connectivity": {
		"technique": "non-persistence",
		"name": "Non-Persistent Connectivity",
		"text": "Establish connections on demand, and terminate connections when no longer needed.",
		"objectives": ["prevent-or-avoid", "constrain", "transform", "re-architect"],
		"sp800_53": ["SC-7(10)", "SC-10", "SC-15(1)", "SI-14(3)"],
		"page": "100",
	},
	"privilege-restriction.trust-based-privilege-management": {
		"technique": "privilege-restriction",
		"name": "Trust-Based Privilege Management",
		"text": "Define, assign, and maintain privileges based on established trust criteria consistent with the principles of least privilege.",
		"objectives": ["prevent-or-avoid", "constrain"],
		"sp800_53": ["AC-3(2)", "AC-6", "AC-6(2)", "AC-6(3)", "AC-6(4)", "AC-6(5)", "AC-6(6)", "AC-6(7)", "AC-6(10)", "AC-23", "AU-9(5)", "AU-9(6)", "CM-5(4)", "CM-5(5)", "CM-5(6)", "CM-7(5)", "CM-7(6)", "CP-9(7)", "SA-8(15)"],
		"page": "100",
	},
	"privilege-restriction.attribute-based-usage-restriction": {
		"technique": "privilege-restriction",
		"name": "Attribute-Based Usage Restriction",
		"text": "Define, assign, maintain, and apply usage restrictions on cyber resources based on the criticality of missions or business functions and other attributes (e.g., data sensitivity).",
		"objectives": ["prevent-or-avoid", "reconstitute"],
		"sp800_53": ["AC-3(7)", "AC-3(11)", "AC-3(12)", "AC-3(13)", "AC-6", "AC-6(1)", "AC-6(4)", "AC-6(8)", "AC-6(10)", "AC-23", "AU-9(6)", "RA-5(5)", "SA-8(15)", "SA-8(18)"],
		"page": "101",
	},
	"privilege-restriction.dynamic-privileges": {
		"technique": "privilege-restriction",
		"name": "Dynamic Privileges",
		"text": "Elevate or decrease privileges assigned to a user, process, or service based on transient or contextual factors.",
		"objectives": ["prevent-or-avoid", "constrain", "reconstitute"],
		"sp800_53": ["AC-2(6)", "AC-2(8)", "AC-6(8)", "AC-23", "IA-10"],
		"page": "101",
	},
	"realignment.purposing": {
		"technique": "realignment",
		"name": "Purposing",
		"text": "Ensure that cyber resources are used consistently with mission or business function purposes and approved uses, thereby avoiding unnecessary sharing and complexity.",
		"objectives": ["prevent-or-avoid", "re-architect"],
		"sp800_53": ["AC-6(2)", "CM-7(4)", "CM-7(5)", "PM-32", "SA-8(6)", "SA-8(7)", "SA-8(13)"],
		"page": "101",
	},
	"realignment.offloading": {
		"technique": "realignment",
		"name": "Offloading",
		"text": "Offload supportive but nonessential functions to other systems or to an external provider that is better able to perform the functions securely.",
		"objectives": ["transform", "re-architect"],
		"sp800_53": ["PM-7(1)", "RA-9", "SA-8(2)", "SC-3(5)", "SC-7(15)", "SC-25"],
		"page": "101",
	},
	"realignment.restriction": {
		"technique": "realignment",
		"name": "Restriction",
		"text": "Remove or disable unneeded functionality or connectivity, or add mechanisms to reduce the chance of vulnerability or failure.",
		"objectives": ["transform", "re-architect"],
		"sp800_53": ["CM-2(7)", "CM-7(2)", "CP-12", "SA-8(2)", "SA-8(6)", "SA-8(13)", "SC-3(3)", "SC-25", "SI-16"],
		"page": "102",
	},
	"realignment.replacement": {
		"technique": "realignment",
		"name": "Replacement",
		"text": "Replace low-assurance or poorly understood implementations with trustworthy implementations.",
		"objectives": ["transform", "re-architect"],
		"sp800_53": ["SA-11(6)", "SA-15(5)"],
		"page": "102",
	},
	"realignment.specialization": {
		"technique": "realignment",
		"name": "Specialization",
		"text": "Uniquely augment, configure, or modify the design of critical cyber resources for missions or business functions to improve trustworthiness.",
		"objectives": ["transform", "re-architect"],
		"sp800_53": ["SA-8(3)", "SA-8(7)", "SA-20", "SA-23"],
		"page": "102",
	},
	"realignment.evolvability": {
		"technique": "realignment",
		"name": "Evolvability",
		"text": "Provide mechanisms and structure resources to enable the system to be maintained, modified, extended, or used in new ways without increasing security or mission risk.",
		"objectives": ["transform", "re-architect"],
		"sp800_53": ["SA-8(3)", "SA-8(8)", "SA-8(31)", "SA-17(6)", "SC-27"],
		"page": "102",
	},
	"redundancy.protected-backup-and-restore": {
		"technique": "redundancy",
		"name": "Protected Backup and Restore",
		"text": "Back up information and software (including configuration data and virtualized resources) in a way that protects its confidentiality, integrity, and authenticity. Enable safe and secure restoration in case of disruption or corruption.",
		"objectives": ["prepare", "continue", "reconstitute"],
		"sp800_53": ["CP-9", "CP-9(1)", "CP-9(8)", "SA-8(19)"],
		"page": "103",
	},
	"redundancy.surplus-capacity": {
		"technique": "redundancy",
		"name": "Surplus Capacity",
		"text": "Maintain extra capacity for information storage, processing, or communications.",
		"objectives": ["prepare", "continue"],
		"sp800_53": ["SC-5(2)"],
		"page": "103",
	},
	"redundancy.replication": {
		"technique": "redundancy",
		"name": "Replication",
		"text": "Duplicate hardware, information, backups, or functionality in multiple locations, and keep them synchronized.",
		"objectives": ["prevent-or-avoid", "prepare", "continue", "transform", "re-architect"],
		"sp800_53": ["AC-4(27)", "AC-4(30)", "CP-9(6)", "PE-9(1)", "PE-11(1)", "PE-11(2)", "PE-17", "SC-22", "SC-36", "SC-36(2)", "SR-5(1)"],
		"page": "103",
	},
	"segmentation.predefined-segmentation": {
		"technique": "segmentation",
		"name": "Predefined Segmentation",
		"text": "Define enclaves, segments, micro-segments, or other restricted types of resource sets based on criticality and trustworthiness so that they can be protected separately and, if necessary, isolated.",
		"objectives": ["prevent-or-avoid", "constrain", "reconstitute", "re-architect"],
		"sp800_53": ["AC-4(2)", "AC-4(21)", "AC-6(4)", "AU-6(8)", "AU-9(2)", "CM-4(1)", "CM-7(6)", "CM-7(7)", "IA-2(13)", "IR-4(12)", "MA-4(4)", "SA-3(2)", "SA-8(3)", "SA-8(6)", "SC-2", "SC-2(1)", "SC-3", "SC-3(1)", "SC-3(2)", "SC-3(5)", "SC-7", "SC-7(13)", "SC-7(15)", "SC-7(21)", "SC-7(22)", "SC-7(29)", "SC-8(5)", "SC-11", "SC-32", "SC-32(1)", "SC-39", "SC-39(1)", "SC-39(2)", "SC-44", "SC-46", "SC-49", "SC-50"],
		"page": "103",
	},
	"segmentation.dynamic-segmentation-and-isolation": {
		"technique": "segmentation",
		"name": "Dynamic Segmentation and Isolation",
		"text": "Change the configuration of enclaves or protected segments, or isolate resources while minimizing operational disruption.",
		"objectives": ["prevent-or-avoid", "constrain", "reconstitute"],
		"sp800_53": ["CM-7(6)", "SA-8(16)", "SC-7(20)", "SC-18(5)", "SC-32(1)", "SC-35", "SC-39", "SC-39(1)", "SC-39(2)"],
		"page": "104",
	},
	"substantiated-integrity.integrity-checks": {
		"technique": "substantiated-integrity",
		"name": "Integrity Checks",
		"text": "Apply and validate checks of the integrity or quality of information, components, or services to guard against surreptitious modification.",
		"objectives": ["continue", "constrain", "reconstitute", "understand"],
		"sp800_53": ["AC-4(8)", "AC-4(12)", "AU-9(1)", "AU-9(3)", "AU-9(6)", "CM-14", "CP-9(1)", "CP-9(8)", "IA-3(1)", "PE-3(5)", "SA-8(16)", "SA-8(19)", "SA-9(7)", "SC-8(1)", "SC-8(5)", "SC-16(1)", "SC-16(3)", "SC-28(1)", "SC-34", "SC-34(2)", "SC-51", "SI-6", "SI-7", "SI-7(1)", "SI-7(5)", "SI-7(6)", "SI-7(7)", "SI-7(9)", "SI-7(10)", "SI-7(12)", "SI-15", "SR-4(3)", "SR-5", "SR-9", "SR-9(1)", "SR-10", "SR-11", "SR-11(3)"],
		"page": "104",
	},
	"substantiated-integrity.provenance-tracking": {
		"technique": "substantiated-integrity",
		"name": "Provenance Tracking",
		"text": "Identify and track the provenance of data, software, or hardware elements.",
		"objectives": ["continue", "reconstitute", "understand"],
		"sp800_53": ["AC-4(17)", "AU-10(2)", "CM-14", "PM-30(1)", "SC-7(11)", "SC-11", "SI-7(15)", "SI-10(5)", "SI-14(1)", "SR-4", "SR-4(1)", "SR-4(2)", "SR-4(3)", "SR-4(4)", "SR-5", "SR-11"],
		"page": "105",
	},
	"substantiated-integrity.behavior-validation": {
		"technique": "substantiated-integrity",
		"name": "Behavior Validation",
		"text": "Validate the behavior of a system, service, device, or individual user against defined or emergent criteria (e.g., requirements, patterns of prior usage).",
		"objectives": ["continue", "constrain", "reconstitute", "understand"],
		"sp800_53": ["AC-2(12)", "AU-6", "IR-4(13)", "SC-36(1)", "SI-4(2)", "SI-4(4)", "SI-4(13)", "SI-10(3)"],
		"page": "105",
	},
	"unpredictability.temporal-unpredictability": {
		"technique": "unpredictability",
		"name": "Temporal Unpredictability",
		"text": "Change behavior or state at times that are determined randomly or by complex functions.",
		"objectives": ["prevent-or-avoid", "constrain"],
		"sp800_53": ["SC-23(3)", "SC-30(2)", "SC-30(3)", "SC-40(3)", "SI-16"],
		"page": "105",
	},
	"unpredictability.contextual-unpredictability": {
		"technique": "unpredictability",
		"name": "Contextual Unpredictability",
		"text": "Change behavior or state in ways that are determined randomly or by complex functions.",
		"objectives": ["prevent-or-avoid", "constrain"],
		"sp800_53": ["SC-8(4)", "SC-30(2)", "SC-40(3)"],
		"page": "105",
	},
}

default compliant := false

compliant if count(violations) == 0

_in := x if {
	x := input.nist_sp_800_160v2
	is_object(x)
} else := {}

_given := d if {
	d := _in.approaches
	is_object(d)
}

_supplied if _given

_true(id) if _given[id] == true

_scope := s if {
	s := _in.scope
	is_object(s)
} else := {}

_gate_declared if "techniques_selected" in object.keys(_scope)

_gate_valid if {
	sel := _scope.techniques_selected
	is_array(sel)
	count(sel) > 0
	every t in sel {
		is_string(t)
		techniques[t]
	}
}

# the techniques evaluated: the declared list when it is valid, otherwise all 14
selected_techniques := {t | some t in _scope.techniques_selected} if _gate_valid

else := {t | some t, _ in techniques}

_in_scope(id) if approaches[id].technique in selected_techniques

_by_technique[t] := ids if {
	some t, _ in techniques
	ids := {id | some id, a in approaches; a.technique == t}
}

_by_objective[o] := ids if {
	some o, _ in objectives
	ids := {id | some id, a in approaches; o in a.objectives}
}

violations contains "NIST SP 800-160v2: FAIL-CLOSED - approaches 'input.nist_sp_800_160v2.approaches' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, a in approaches
	_in_scope(id)
	not _true(id)
	msg := sprintf("NIST SP 800-160v2 %v (%v / %v): approach not attested implemented — %v", [id, techniques[a.technique], a.name, a.text])
}

violations contains msg if {
	some id, _ in _given
	not approaches[id]
	msg := sprintf("NIST SP 800-160v2 Input Contract: unknown approach id %v — ids are <technique>.<approach> slugs such as adaptive-response.dynamic-reconfiguration", [id])
}

violations contains "NIST SP 800-160v2 Input Contract: scope 'input.nist_sp_800_160v2.scope' must be an object" if {
	"scope" in object.keys(_in)
	not is_object(_in.scope)
}

violations contains msg if {
	some k, _ in _scope
	k != "techniques_selected"
	msg := sprintf("NIST SP 800-160v2 Input Contract: undeclared gate flag scope.%v — the only gate is scope.techniques_selected", [k])
}

violations contains "NIST SP 800-160v2 Input Contract: scope.techniques_selected must be a non-empty list of technique ids; the gate is ignored and all approaches are evaluated" if {
	_gate_declared
	not _gate_valid
}

violations contains msg if {
	_gate_declared
	sel := _scope.techniques_selected
	is_array(sel)
	some t in sel
	not _known_technique(t)
	msg := sprintf("NIST SP 800-160v2 Input Contract: unknown technique id %v in scope.techniques_selected", [t])
}

_known_technique(t) if {
	is_string(t)
	techniques[t]
}

_status(ids, in_scope) := "not_selected" if {
	not in_scope
} else := "satisfied" if {
	every id in ids { _true(id) }
} else := "not_satisfied"

technique_rollup[t] := s if {
	some t, name in techniques
	ids := _by_technique[t]
	s := {
		"name": name,
		"approaches_total": count(ids),
		"approaches_attested": count({id | some id in ids; _true(id)}),
		"not_attested": sort([id | some id in ids; not _true(id)]),
		"status": _status(ids, t in selected_techniques),
	}
}

objective_rollup[o] := s if {
	some o, name in objective_names
	ids := _by_objective[o]
	scoped := {id | some id in ids; _in_scope(id)}
	s := {
		"name": name,
		"goals": objective_goals[o],
		"approaches_total": count(ids),
		"approaches_in_scope": count(scoped),
		"approaches_attested": count({id | some id in scoped; _true(id)}),
		"not_attested": sort([id | some id in scoped; not _true(id)]),
		"status": _status(scoped, count(scoped) > 0),
	}
}

compliance_report := {
	"framework": "NIST SP 800-160 Vol. 2 Rev. 1",
	"standard": "NIST SP 800-160 Vol. 2 Rev. 1 — Developing Cyber-Resilient Systems: A Systems Security Engineering Approach (December 2021)",
	"source": source,
	"compliant": compliant,
	"total_controls": count(approaches),
	"standard_total": 50, # implementation approaches in Table D-4
	"approaches_in_scope": count({id | some id, _ in approaches; _in_scope(id)}),
	"approaches_attested": count({id | some id, _ in approaches; _in_scope(id); _true(id)}),
	"gate_applied": _gate_valid_bool,
	"techniques_selected": sort([t | some t in selected_techniques]),
	"goals_total": count(goals),
	"objectives_total": count(objectives),
	"techniques_total": count(techniques),
	"strategic_design_principles_total": count(strategic_design_principles),
	"structural_design_principles_total": count(structural_design_principles),
	"techniques": technique_rollup,
	"objectives": objective_rollup,
	"violation_count": count(violations),
	"violations": violations,
}

_gate_valid_bool if _gate_valid

else := false
