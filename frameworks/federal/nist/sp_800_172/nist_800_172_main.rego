# NIST SP 800-172 Revision 3 — Enhanced Security Requirements for Protecting
# Controlled Unclassified Information, with the SP 800-172A Revision 3
# determination statements as the assessment table.
#
# Source of truth: NIST CPRT JSON export of SP_800_172_3_0_0, retrieved 2026-10-13
#   https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_172_3_0_0/export/json?element=all
#   sha256 666f09a36045a9b132a4f8dbfa8b905ab5a019d192009798b30bd02acef33f3c
# Every id and text below is generated verbatim from that export (public domain).
# Rev 3 enhanced requirements supplement SP 800-171 Rev 3 (ids 03.xx.yyE; the
# withdraw_reason elements cite SP 800-171 Rev 3 ids). No CMMC level mapping is
# modelled here.
#
# Measured in the export (element_type: count):
#   family 17 · security_requirement 115 (103 active, 12 withdrawn: title
#   "Withdrawn" plus a withdraw_reason) · enhanced_security_requirement 174
#   · determination 199 · examine/interview/test 103/103/98 (one each per active
#   requirement; 5 have no test) · odp 165 · discussion, adversary_effect, effect, tactic,
#   protection_strategy, impact, example, expected_result, reference (context, not carried).
#
# Nesting, and how the control grain was chosen (statement = CPRT element type
# enhanced_security_requirement; its ids are prefixed "ES-", requirement ids are not):
#   security_requirement 03.01.08E (title "Account Monitoring for Atypical Usage")
#     ES-03.01.08E          top statement — empty text when the requirement has parts
#       ES-03.01.08E-a      leaf statement — text, owns determination DS-A.03.01.08E.a
#       ES-03.01.08E-b      leaf statement — text, owns determination DS-A.03.01.08E.b
#   Parts nest one level deeper where the publication does (ES-03.02.01E-a-1).
#   174 statements − 12 withdrawn = 162 active = 21 empty-text parent statements
#   + 4 lead-in statements (text ends in ":" and has no determination of its own:
#   ES-03.02.01E-a, ES-03.09.03E-c, ES-03.11.02E-a, ES-03.15.01E-a)
#   + 137 leaf statements. Only the leaves have both text and determinations, so
#   the 137 leaves are the controls; a lead-in's text is carried on its children
#   as `lead_in`. Every one of the 199 determinations belongs to exactly one leaf,
#   and every leaf has at least one. Withdrawn requirements carry no determinations.
#
# Identifier spelling: keys are the CPRT element identifiers verbatim — statements
# "ES-03.01.08E-a", determinations "DS-A.03.01.05E[01]". The printed SP 800-172A
# drops the "DS-" prefix (A.03.01.05E[01]); CPRT's type prefixes are kept so every
# key can be looked up in the export. Determination text keeps its ODP placeholders
# (<A.03.01.01E.ODP[01]: ...>); ODP values are not evaluated here.
#
# Rollup (no double count): a statement is SATISFIED only when it is attested
# true AND every one of its determinations is true. One violation per unsatisfied
# statement names both causes; a false determination is reported inside its
# statement's violation, never as a second violation. A requirement is satisfied
# when all its leaf statements are. Assessment methods (examine / interview /
# test) are carried as data per requirement (`assessment_methods`), not controls.
#
# Fail-closed:
#   - absent or non-object input.nist_sp_800_172 is an explicit FAIL-CLOSED violation
#   - every value must be the boolean true; absent, false, "true" are not
#   - unknown statement or determination ids are violations (withdrawn ids and
#     parent / lead-in statements are named as such)
#   - non-object requirements / determinations containers are violations
#
# Input contract — input.nist_sp_800_172.*
#   requirements   — object {"<ES- statement id>": true}, e.g. {"ES-03.01.08E-a": true}
#   determinations — object {"<DS- determination id>": true}, e.g. {"DS-A.03.01.08E.a": true}
#
# Query: POST /v1/data/nist/sp800_172/main/compliance_report

# METADATA
# title: "NIST SP 800-172 Rev 3 — enhanced security requirements for CUI, with SP 800-172A Rev 3 determinations"
# custom:
#   class: compliance
#   framework: nist_sp_800_172
#   source: nist
#   domains: [us-federal, cui]
#   coverage:
#     checks: 144
#     cited: 140
#     expected: 137
#     found: 144
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.sp800_172.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

source := {
	"document": "NIST SP 800-172 Revision 3 (determinations: SP 800-172A Revision 3)",
	"cprt_export": "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/SP_800_172_3_0_0/export/json?element=all",
	"sha256": "666f09a36045a9b132a4f8dbfa8b905ab5a019d192009798b30bd02acef33f3c",
	"retrieved": "2026-10-13",
}

export_counts := {
	"enhanced_security_requirement_statements": 174,
	"withdrawn_statements": 12,
	"active_statements": 162,
	"parent_statements_without_text": 21,
	"lead_in_statements": 4,
	"leaf_statements": 137,
	"security_requirements": 115,
	"security_requirements_withdrawn": 12,
	"determinations": 199,
}

# family id -> title (CPRT `family` elements)
families := {
	"3.1": "Access Control",
	"3.2": "Awareness and Training",
	"3.3": "Audit and Accountability",
	"3.4": "Configuration Management",
	"3.5": "Identification and Authentication",
	"3.6": "Incident Response",
	"3.7": "Maintenance",
	"3.8": "Media Protection",
	"3.9": "Personnel Security",
	"3.10": "Physical Protection",
	"3.11": "Risk Assessment",
	"3.12": "Security Assessment and Monitoring",
	"3.13": "System and Communications Protection",
	"3.14": "System and Information Integrity",
	"3.15": "Planning",
	"3.16": "System and Services Acquisition",
	"3.17": "Supply Chain Risk Management",
}

# active security requirement id -> title
titles := {
	"03.01.01E": "Dual Authorization",
	"03.01.02E": "Non-Organizationally Owned Systems - Restricted Use",
	"03.01.04E": "Concurrent Session Control",
	"03.01.05E": "Remote Access Monitoring and Control",
	"03.01.06E": "Protection of Remote Access Mechanism Information",
	"03.01.07E": "Automated Audit Actions for Account Management",
	"03.01.08E": "Account Monitoring for Atypical Usage",
	"03.01.09E": "Attribute-Based Access Control",
	"03.01.10E": "Object Security Attributes",
	"03.01.11E": "Role-Based Access Control",
	"03.01.12E": "Physical or Logical Separation of CUI Flows",
	"03.01.13E": "Metadata",
	"03.01.14E": "Security Policy Filters",
	"03.01.15E": "Data Type Identifiers",
	"03.01.16E": "Decomposition Into Policy-Relevant Subcomponents",
	"03.01.17E": "Detection of Unsanctioned CUI",
	"03.02.01E": "Advanced Literacy and Awareness Training",
	"03.02.02E": "Literacy and Awareness Training Practical Exercises",
	"03.02.03E": "Literacy and Awareness Training Feedback",
	"03.02.04E": "Anti-Counterfeit Training",
	"03.03.01E": "Protection of Audit Record Storage in Separate Physical Systems or Components",
	"03.03.02E": "Real-Time Alerts for Audit Processing Failures",
	"03.03.03E": "Dual Authorization for Audit Information and Actions",
	"03.03.04E": "Integrated Analysis of Audit Records",
	"03.04.02E": "Automated Unauthorized Component Detection",
	"03.04.03E": "Automated Maintenance of System Component Inventory",
	"03.04.04E": "Automation Support for Baseline Configuration",
	"03.04.05E": "Dual Authorization for System Changes",
	"03.04.06E": "Retention of Previous Configurations",
	"03.04.07E": "Testing, Validation, and Documentation of Changes",
	"03.04.08E": "Centralized Repository",
	"03.05.01E": "Cryptographic Bidirectional Authentication",
	"03.05.02E": "Password Managers",
	"03.05.03E": "Device Attestation",
	"03.05.04E": "No Embedded Unencrypted Static Authenticators",
	"03.05.05E": "Expiration of Cached Authenticators",
	"03.05.06E": "Identity Proofing",
	"03.05.07E": "Identity Providers and Authorization Servers",
	"03.06.01E": "Security Operations Center",
	"03.06.02E": "Integrated Incident Response Team",
	"03.06.03E": "Behavior Analysis",
	"03.06.04E": "Automated Tracking, Data Collection, and Analysis for Incident Monitoring",
	"03.07.01E": "Software Updates and Patches for Maintenance Tools",
	"03.08.01E": "Dual Authorization for Media Sanitization",
	"03.08.02E": "Dual Authorization for System Backup Deletion and Destruction",
	"03.08.03E": "Testing System Backups for Reliability and Integrity",
	"03.08.04E": "System Recovery and Reconstitution",
	"03.09.03E": "Access Agreements",
	"03.09.04E": "Citizenship Requirements",
	"03.10.01E": "Intrusion Alarms and Surveillance Equipment",
	"03.10.02E": "Delivery and Removal of System Components",
	"03.11.01E": "Threat Awareness Program",
	"03.11.02E": "Threat Hunting",
	"03.11.03E": "Predictive Cyber Analytics",
	"03.11.08E": "Dynamic Threat Awareness",
	"03.11.09E": "Indicators of Compromise",
	"03.11.10E": "Criticality Analysis",
	"03.11.11E": "Discoverable Information",
	"03.11.12E": "Automated Means for Sharing Threat Intelligence",
	"03.12.01E": "Penetration Testing",
	"03.12.02E": "Independent Assessors",
	"03.12.03E": "Risk Monitoring",
	"03.12.04E": "Internal System Connections",
	"03.13.01E": "Heterogeneity",
	"03.13.02E": "Randomness",
	"03.13.03E": "Concealment and Misdirection",
	"03.13.04E": "Isolation of System Components",
	"03.13.05E": "Change Processing and Storage Locations",
	"03.13.06E": "Platform-Independent Applications",
	"03.13.07E": "Virtualization Techniques",
	"03.13.08E": "Decoys",
	"03.13.09E": "Isolation of Security Tools, Mechanisms, and Support Components",
	"03.13.10E": "Separate Subnetworks",
	"03.13.11E": "Thin Nodes",
	"03.13.12E": "Denial-of-Service Protection",
	"03.13.13E": "Port and Input/Output Device Access",
	"03.13.14E": "Detonation Chambers",
	"03.13.15E": "Separate Subnets to Isolate System Components and Functions",
	"03.13.16E": "System Partitioning",
	"03.14.01E": "Software, Firmware, and Information Integrity",
	"03.14.04E": "Refresh From Trusted Sources",
	"03.14.05E": "Non-Persistent Information",
	"03.14.08E": "Integrity Checks",
	"03.14.09E": "Cryptographic Protection",
	"03.14.10E": "Protection of Boot Firmware",
	"03.14.11E": "Integration of Detection and Response",
	"03.14.12E": "Information Input Validation",
	"03.14.13E": "Error Handling",
	"03.14.14E": "Memory Protection",
	"03.14.15E": "Non-Persistent System Components and Services",
	"03.14.16E": "Tainting",
	"03.14.17E": "System-Generated Alerts",
	"03.14.18E": "Automated Organization-Generated Alerts",
	"03.14.19E": "Wireless Intrusion Detection",
	"03.15.01E": "Security Architecture",
	"03.15.02E": "Defense In Depth",
	"03.15.03E": "Supplier Diversity",
	"03.16.01E": "Specialization",
	"03.17.01E": "Notification Agreements",
	"03.17.02E": "Inspection of Systems or Components",
	"03.17.03E": "Component Authenticity",
	"03.17.04E": "Provenance",
	"03.17.05E": "Supply Chain Integrity – Pedigree",
}

# withdrawn security requirement id -> CPRT withdraw_reason (where it went)
withdrawn := {
	"03.01.03E": "03.01.09E, 03.01.10E, and 03.01.03 (SP 800-171).",
	"03.04.01E": "03.04.08E, 03.14.04E, 03.17.03E, 03.17.04E, 03.17.05E, 03.04.01 (SP 800-171), 03.04.03 (SP 800-171), and 03.04.10 (SP 800-171).",
	"03.09.01E": "03.09.01 (SP 800-171).",
	"03.09.02E": "03.01.01 (SP 800-171) and 03.09.01 (SP 800-171).",
	"03.11.04E": "03.15.01E, 03.11.01 (SP 800-171), 03.11.04 (SP 800-171), and 03.15.02 (SP 800-171).",
	"03.11.05E": "03.11.01E, 03.11.03E, 03.11.01 (SP 800-171), 03.11.04 (SP 800-171), 03.12.01 (SP 800-171), and 03.12.03 (SP 800-171).",
	"03.11.06E": "03.12.03E, 03.11.01 (SP 800-171), 03.11.04 (SP 800-171), 03.12.01 (SP 800-171), 03.12.03 (SP 800-171), and 03.17.03 (SP 800-171).",
	"03.11.07E": "03.17.01 (SP 800-171).",
	"03.14.02E": "03.14.06 (SP 800-171).",
	"03.14.03E": "03.15.01E, 03.13.16E, 03.12.01 (SP 800-171), 03.13.01 (SP 800-171), and 03.16.01 (SP 800-171).",
	"03.14.06E": "03.11.02E and 03.11.09E.",
	"03.14.07E": "03.14.08E, 03.14.10E, 03.14.14E, 03.17.03E, 03.16.01 (SP 800-171)",
}

# withdrawn security requirement id -> family
withdrawn_family := {
	"03.01.03E": "3.1",
	"03.04.01E": "3.4",
	"03.09.01E": "3.9",
	"03.09.02E": "3.9",
	"03.11.04E": "3.11",
	"03.11.05E": "3.11",
	"03.11.06E": "3.11",
	"03.11.07E": "3.11",
	"03.14.02E": "3.14",
	"03.14.03E": "3.14",
	"03.14.06E": "3.14",
	"03.14.07E": "3.14",
}

# leaf statement id -> family, requirement, parent statement, lead-in text, text, determination ids
statements := {
	# ── 3.1 Access Control
	"ES-03.01.01E": {"family": "3.1", "requirement": "03.01.01E", "parent": null, "lead_in": "", "text": "Enforce dual authorization for [Assignment: organization-defined privileged commands and/or other organization-defined actions].", "determinations": ["DS-A.03.01.01E"]},
	"ES-03.01.02E": {"family": "3.1", "requirement": "03.01.02E", "parent": null, "lead_in": "", "text": "Restrict the use of non-organizationally owned systems or system components to process, store, or transmit CUI using [Assignment: organization-defined restrictions].", "determinations": ["DS-A.03.01.02E"]},
	"ES-03.01.04E": {"family": "3.1", "requirement": "03.01.04E", "parent": null, "lead_in": "", "text": "Limit the number of concurrent sessions for each [Assignment: organization-defined account and/or account type] to [Assignment: organization-defined number].", "determinations": ["DS-A.03.01.04E"]},
	"ES-03.01.05E": {"family": "3.1", "requirement": "03.01.05E", "parent": null, "lead_in": "", "text": "Employ automated mechanisms to monitor and control remote access methods.", "determinations": ["DS-A.03.01.05E[01]", "DS-A.03.01.05E[02]"]},
	"ES-03.01.06E": {"family": "3.1", "requirement": "03.01.06E", "parent": null, "lead_in": "", "text": "Protect information about remote access mechanisms from unauthorized use and disclosure.", "determinations": ["DS-A.03.01.06E"]},
	"ES-03.01.07E": {"family": "3.1", "requirement": "03.01.07E", "parent": null, "lead_in": "", "text": "Use automated mechanisms to audit account creation, modification, enabling, disabling, and removal actions.", "determinations": ["DS-A.03.01.07E[01]", "DS-A.03.01.07E[02]", "DS-A.03.01.07E[03]", "DS-A.03.01.07E[04]", "DS-A.03.01.07E[05]"]},
	"ES-03.01.08E-a": {"family": "3.1", "requirement": "03.01.08E", "parent": "ES-03.01.08E", "lead_in": "", "text": "Monitor system accounts for [Assignment: organization-defined atypical usage].", "determinations": ["DS-A.03.01.08E.a"]},
	"ES-03.01.08E-b": {"family": "3.1", "requirement": "03.01.08E", "parent": "ES-03.01.08E", "lead_in": "", "text": "Report atypical usage of system accounts to [Assignment: organization-defined personnel or roles].", "determinations": ["DS-A.03.01.08E.b"]},
	"ES-03.01.09E-a": {"family": "3.1", "requirement": "03.01.09E", "parent": "ES-03.01.09E", "lead_in": "", "text": "Enforce attribute-based access control policy over defined subjects and objects.", "determinations": ["DS-A.03.01.09E.a[01]", "DS-A.03.01.09E.a[02]"]},
	"ES-03.01.09E-b": {"family": "3.1", "requirement": "03.01.09E", "parent": "ES-03.01.09E", "lead_in": "", "text": "Control access based upon [Assignment: organization-defined attributes to assume access permissions].", "determinations": ["DS-A.03.01.09E.b"]},
	"ES-03.01.10E": {"family": "3.1", "requirement": "03.01.10E", "parent": null, "lead_in": "", "text": "Use [Assignment: organization-defined security attributes] associated with [Assignment: organization-defined information, source, and destination objects] to enforce [Assignment: organization-defined information flow control policies] as a basis for flow control decisions.", "determinations": ["DS-A.03.01.10E"]},
	"ES-03.01.11E-a": {"family": "3.1", "requirement": "03.01.11E", "parent": "ES-03.01.11E", "lead_in": "", "text": "Enforce a role-based access control policy over defined subjects and objects.", "determinations": ["DS-A.03.01.11E.a"]},
	"ES-03.01.11E-b": {"family": "3.1", "requirement": "03.01.11E", "parent": "ES-03.01.11E", "lead_in": "", "text": "Control access based upon [Assignment: organization-defined roles and users authorized to assume such roles].", "determinations": ["DS-A.03.01.11E.b"]},
	"ES-03.01.12E": {"family": "3.1", "requirement": "03.01.12E", "parent": null, "lead_in": "", "text": "Separate CUI flows logically or physically using [Assignment: organization-defined mechanisms and/or techniques].", "determinations": ["DS-A.03.01.12E"]},
	"ES-03.01.13E": {"family": "3.1", "requirement": "03.01.13E", "parent": null, "lead_in": "", "text": "Enforce information flow control based on [Assignment: organization-defined metadata].", "determinations": ["DS-A.03.01.13E"]},
	"ES-03.01.14E-a": {"family": "3.1", "requirement": "03.01.14E", "parent": "ES-03.01.14E", "lead_in": "", "text": "Enforce information flow control using [Assignment: organization-defined security policy filters] as a basis for flow control decisions for [Assignment: organization-defined information flows].", "determinations": ["DS-A.03.01.14E.a"]},
	"ES-03.01.14E-b": {"family": "3.1", "requirement": "03.01.14E", "parent": "ES-03.01.14E", "lead_in": "", "text": "[Selection (one or more): Block; Strip; Modify; Quarantine] data after a filter processing failure in accordance with [Assignment: organization-defined security policy].", "determinations": ["DS-A.03.01.14E.b"]},
	"ES-03.01.15E": {"family": "3.1", "requirement": "03.01.15E", "parent": null, "lead_in": "", "text": "Use [Assignment: organization-defined data type identifiers] to validate data that is essential for information flow decisions when transferring CUI between security domains.", "determinations": ["DS-A.03.01.15E"]},
	"ES-03.01.16E": {"family": "3.1", "requirement": "03.01.16E", "parent": null, "lead_in": "", "text": "Decompose CUI into [Assignment: organization-defined policy-relevant subcomponents] for submission to policy enforcement mechanisms when transferring CUI between different security domains.", "determinations": ["DS-A.03.01.16E"]},
	"ES-03.01.17E-a": {"family": "3.1", "requirement": "03.01.17E", "parent": "ES-03.01.17E", "lead_in": "", "text": "Examine CUI for the presence of [Assignment: organization-defined unsanctioned information] when transferring information between different security domains.", "determinations": ["DS-A.03.01.17E.a"]},
	"ES-03.01.17E-b": {"family": "3.1", "requirement": "03.01.17E", "parent": "ES-03.01.17E", "lead_in": "", "text": "Prohibit the transfer of the CUI defined in 03.01.17E.a in accordance with the [Assignment: organization-defined security policy].", "determinations": ["DS-A.03.01.17E.b"]},
	# ── 3.2 Awareness and Training
	"ES-03.02.01E-a-1": {"family": "3.2", "requirement": "03.02.01E", "parent": "ES-03.02.01E-a", "lead_in": "Provide security literacy training to system users:", "text": "On the advanced persistent threat,", "determinations": ["DS-A.03.02.01E.a.01"]},
	"ES-03.02.01E-a-2": {"family": "3.2", "requirement": "03.02.01E", "parent": "ES-03.02.01E-a", "lead_in": "Provide security literacy training to system users:", "text": "On recognizing suspicious communications and anomalous behavior in systems using [Assignment: organization-defined indicators of malicious code], and", "determinations": ["DS-A.03.02.01E.a.02"]},
	"ES-03.02.01E-a-3": {"family": "3.2", "requirement": "03.02.01E", "parent": "ES-03.02.01E-a", "lead_in": "Provide security literacy training to system users:", "text": "On the cyber threat environment.", "determinations": ["DS-A.03.02.01E.a.03"]},
	"ES-03.02.01E-b": {"family": "3.2", "requirement": "03.02.01E", "parent": "ES-03.02.01E", "lead_in": "", "text": "Update security literacy training content [Assignment: organization-defined frequency] and following [Assignment: organization-defined events].", "determinations": ["DS-A.03.02.01E.b[01]", "DS-A.03.02.01E.b[02]"]},
	"ES-03.02.02E": {"family": "3.2", "requirement": "03.02.02E", "parent": null, "lead_in": "", "text": "Provide practical exercises in literacy training that simulate events and incidents.", "determinations": ["DS-A.03.02.02E"]},
	"ES-03.02.03E": {"family": "3.2", "requirement": "03.02.03E", "parent": null, "lead_in": "", "text": "Provide feedback on organizational training results to the following personnel [Assignment: organization-defined personnel].", "determinations": ["DS-A.03.02.03E"]},
	"ES-03.02.04E": {"family": "3.2", "requirement": "03.02.04E", "parent": null, "lead_in": "", "text": "Train [Assignment: organization-defined personnel or roles] to detect counterfeit system components.", "determinations": ["DS-A.03.02.04E"]},
	# ── 3.3 Audit and Accountability
	"ES-03.03.01E": {"family": "3.3", "requirement": "03.03.01E", "parent": null, "lead_in": "", "text": "Store audit records in a repository that is part of a physically different system or system component than the system or component being audited.", "determinations": ["DS-A.03.03.01E"]},
	"ES-03.03.02E": {"family": "3.3", "requirement": "03.03.02E", "parent": null, "lead_in": "", "text": "Provide an alert within [Assignment: organization-defined real-time period] to [Assignment: organization-defined personnel, roles, and/or locations] when the following audit failure events occur: [Assignment: organization-defined audit logging failure events requiring real-time alerts].", "determinations": ["DS-A.03.03.02E"]},
	"ES-03.03.03E": {"family": "3.3", "requirement": "03.03.03E", "parent": null, "lead_in": "", "text": "Enforce dual authorization for [Selection (one or more): movement; deletion] of [Assignment: organization-defined audit information].", "determinations": ["DS-A.03.03.03E"]},
	"ES-03.03.04E": {"family": "3.3", "requirement": "03.03.04E", "parent": null, "lead_in": "", "text": "Integrate analysis of audit records with analysis of [Selection (one or more): vulnerability scanning information; performance data; system monitoring information; [Assignment: organization-defined data/information collected from other sources]] to further enhance the ability to identify inappropriate or unusual activity.", "determinations": ["DS-A.03.03.04E"]},
	# ── 3.4 Configuration Management
	"ES-03.04.02E-a": {"family": "3.4", "requirement": "03.04.02E", "parent": "ES-03.04.02E", "lead_in": "", "text": "Detect the presence of unauthorized or misconfigured system components using [Assignment: organization-defined automated mechanisms].", "determinations": ["DS-A.03.04.02E.a"]},
	"ES-03.04.02E-b": {"family": "3.4", "requirement": "03.04.02E", "parent": "ES-03.04.02E", "lead_in": "", "text": "Take the following actions when unauthorized or misconfigured components are detected: [Selection (one or more): disable network access by such components; isolate the components; notify [Assignment: organization-defined personnel or roles]].", "determinations": ["DS-A.03.04.02E.b"]},
	"ES-03.04.03E": {"family": "3.4", "requirement": "03.04.03E", "parent": null, "lead_in": "", "text": "Maintain the currency, completeness, accuracy, and availability of the inventory of system components using [Assignment: organization-defined automated mechanisms].", "determinations": ["DS-A.03.04.03E[01]", "DS-A.03.04.03E[02]", "DS-A.03.04.03E[03]", "DS-A.03.04.03E[04]"]},
	"ES-03.04.04E": {"family": "3.4", "requirement": "03.04.04E", "parent": null, "lead_in": "", "text": "Maintain the currency, completeness, accuracy, and availability of the baseline configuration of the system using [Assignment: organization-defined automated mechanisms].", "determinations": ["DS-A.03.04.04E[01]", "DS-A.03.04.04E[02]", "DS-A.03.04.04E[03]", "DS-A.03.04.04E[04]"]},
	"ES-03.04.05E": {"family": "3.4", "requirement": "03.04.05E", "parent": null, "lead_in": "", "text": "Enforce dual authorization for implementing changes to [Assignment: organization-defined system components and system-level information].", "determinations": ["DS-A.03.04.05E[01]", "DS-A.03.04.05E[02]"]},
	"ES-03.04.06E": {"family": "3.4", "requirement": "03.04.06E", "parent": null, "lead_in": "", "text": "Retain [Assignment: organization-defined number] previous versions of baseline configurations of the system to support rollback.", "determinations": ["DS-A.03.04.06E"]},
	"ES-03.04.07E": {"family": "3.4", "requirement": "03.04.07E", "parent": null, "lead_in": "", "text": "Test, validate, and document changes to the system before finalizing the implementation of the changes.", "determinations": ["DS-A.03.04.07E[01]", "DS-A.03.04.07E[02]", "DS-A.03.04.07E[03]"]},
	"ES-03.04.08E": {"family": "3.4", "requirement": "03.04.08E", "parent": null, "lead_in": "", "text": "Provide a centralized repository for the inventory of system components.", "determinations": ["DS-A.03.04.08E"]},
	# ── 3.5 Identification and Authentication
	"ES-03.05.01E": {"family": "3.5", "requirement": "03.05.01E", "parent": null, "lead_in": "", "text": "Authenticate [Assignment: organization-defined devices and/or types of devices] before establishing a system connection using bidirectional authentication that is cryptographically based.", "determinations": ["DS-A.03.05.01E"]},
	"ES-03.05.02E-a": {"family": "3.5", "requirement": "03.05.02E", "parent": "ES-03.05.02E", "lead_in": "", "text": "Employ [Assignment: organization-defined password managers] to generate and manage passwords.", "determinations": ["DS-A.03.05.02E.a"]},
	"ES-03.05.02E-b": {"family": "3.5", "requirement": "03.05.02E", "parent": "ES-03.05.02E", "lead_in": "", "text": "Protect the passwords using [Assignment: organization-defined safeguards].", "determinations": ["DS-A.03.05.02E.b"]},
	"ES-03.05.03E": {"family": "3.5", "requirement": "03.05.03E", "parent": null, "lead_in": "", "text": "Handle device identification and authentication based on attestation by [Assignment: organization-defined configuration management process].", "determinations": ["DS-A.03.05.03E"]},
	"ES-03.05.04E": {"family": "3.5", "requirement": "03.05.04E", "parent": null, "lead_in": "", "text": "Ensure that unencrypted static authenticators are not embedded in applications or other forms of static storage.", "determinations": ["DS-A.03.05.04E"]},
	"ES-03.05.05E": {"family": "3.5", "requirement": "03.05.05E", "parent": null, "lead_in": "", "text": "Prohibit the use of cached authenticators after [Assignment: organization-defined time period].", "determinations": ["DS-A.03.05.05E"]},
	"ES-03.05.06E-a": {"family": "3.5", "requirement": "03.05.06E", "parent": "ES-03.05.06E", "lead_in": "", "text": "Identity proof users that require accounts for logical access to systems based on appropriate identity assurance level requirements as specified in applicable standards and guidelines.", "determinations": ["DS-A.03.05.06E.a"]},
	"ES-03.05.06E-b": {"family": "3.5", "requirement": "03.05.06E", "parent": "ES-03.05.06E", "lead_in": "", "text": "Resolve user identities to a unique individual.", "determinations": ["DS-A.03.05.06E.b"]},
	"ES-03.05.06E-c": {"family": "3.5", "requirement": "03.05.06E", "parent": "ES-03.05.06E", "lead_in": "", "text": "Collect, validate, and verify identity evidence.", "determinations": ["DS-A.03.05.06E.c[01]", "DS-A.03.05.06E.c[02]", "DS-A.03.05.06E.c[03]"]},
	"ES-03.05.07E": {"family": "3.5", "requirement": "03.05.07E", "parent": null, "lead_in": "", "text": "Employ identity providers and authorization servers to manage user, device, and non-person entity identities, attributes, and access rights that support authentication and authorization decisions in accordance with [Assignment: organization-defined identification and authentication policy] using [Assignment: organization-defined mechanisms].", "determinations": ["DS-A.03.05.07E[01]", "DS-A.03.05.07E[02]", "DS-A.03.05.07E[03]"]},
	# ── 3.6 Incident Response
	"ES-03.06.01E": {"family": "3.6", "requirement": "03.06.01E", "parent": null, "lead_in": "", "text": "Establish and maintain a security operations center.", "determinations": ["DS-A.03.06.01E[01]", "DS-A.03.06.01E[02]"]},
	"ES-03.06.02E": {"family": "3.6", "requirement": "03.06.02E", "parent": null, "lead_in": "", "text": "Establish and maintain an integrated incident response team that can be deployed to any location identified by the organization in [Assignment: organization-defined time period].", "determinations": ["DS-A.03.06.02E[01]", "DS-A.03.06.02E[02]", "DS-A.03.06.02E[03]"]},
	"ES-03.06.03E": {"family": "3.6", "requirement": "03.06.03E", "parent": null, "lead_in": "", "text": "Analyze anomalous or suspected adversarial behavior in or related to [Assignment: organization-defined environments or resources].", "determinations": ["DS-A.03.06.03E"]},
	"ES-03.06.04E": {"family": "3.6", "requirement": "03.06.04E", "parent": null, "lead_in": "", "text": "Track incidents and collect and analyze incident information using [Assignment: organization-defined automated mechanisms].", "determinations": ["DS-A.03.06.04E[01]", "DS-A.03.06.04E[02]", "DS-A.03.06.04E[03]"]},
	# ── 3.7 Maintenance
	"ES-03.07.01E": {"family": "3.7", "requirement": "03.07.01E", "parent": null, "lead_in": "", "text": "Inspect maintenance tools to ensure the latest software updates and patches are installed.", "determinations": ["DS-A.03.07.01E"]},
	# ── 3.8 Media Protection
	"ES-03.08.01E": {"family": "3.8", "requirement": "03.08.01E", "parent": null, "lead_in": "", "text": "Enforce dual authorization for the sanitization of [Assignment: organization-defined system media containing CUI].", "determinations": ["DS-A.03.08.01E"]},
	"ES-03.08.02E": {"family": "3.8", "requirement": "03.08.02E", "parent": null, "lead_in": "", "text": "Enforce dual authorization for the deletion or destruction of [Assignment: organization-defined system backup information].", "determinations": ["DS-A.03.08.02E"]},
	"ES-03.08.03E": {"family": "3.8", "requirement": "03.08.03E", "parent": null, "lead_in": "", "text": "Test backup information [Assignment: organization-defined frequency] to verify media reliability and information integrity.", "determinations": ["DS-A.03.08.03E[01]", "DS-A.03.08.03E[02]"]},
	"ES-03.08.04E": {"family": "3.8", "requirement": "03.08.04E", "parent": null, "lead_in": "", "text": "Provide for the recovery and reconstitution of the system to a known state within [Assignment: organization-defined time period consistent with recovery time and recovery point objectives] after a disruption, compromise, or failure.", "determinations": ["DS-A.03.08.04E[01]", "DS-A.03.08.04E[02]"]},
	# ── 3.9 Personnel Security
	"ES-03.09.03E-a": {"family": "3.9", "requirement": "03.09.03E", "parent": "ES-03.09.03E", "lead_in": "", "text": "Develop and document access agreements for systems processing, storing, or transmitting CUI.", "determinations": ["DS-A.03.09.03E.a"]},
	"ES-03.09.03E-b": {"family": "3.9", "requirement": "03.09.03E", "parent": "ES-03.09.03E", "lead_in": "", "text": "Review and update the access agreements [Assignment: organization-defined frequency].", "determinations": ["DS-A.03.09.03E.b[01]", "DS-A.03.09.03E.b[02]"]},
	"ES-03.09.03E-c-1": {"family": "3.9", "requirement": "03.09.03E", "parent": "ES-03.09.03E-c", "lead_in": "Verify that individuals requiring access to CUI and systems processing, storing, or transmitting CUI:", "text": "Sign appropriate access agreements prior to being granted access; and", "determinations": ["DS-A.03.09.03E.c.01"]},
	"ES-03.09.03E-c-2": {"family": "3.9", "requirement": "03.09.03E", "parent": "ES-03.09.03E-c", "lead_in": "Verify that individuals requiring access to CUI and systems processing, storing, or transmitting CUI:", "text": "Re-sign access agreements to maintain access to systems when access agreements have been updated or [Assignment: organization-defined frequency].", "determinations": ["DS-A.03.09.03E.c.02"]},
	"ES-03.09.04E": {"family": "3.9", "requirement": "03.09.04E", "parent": null, "lead_in": "", "text": "Verify that individuals accessing a system that processes, stores, or transmits CUI meet [Assignment: organization-defined citizenship requirements].", "determinations": ["DS-A.03.09.04E"]},
	# ── 3.10 Physical Protection
	"ES-03.10.01E": {"family": "3.10", "requirement": "03.10.01E", "parent": null, "lead_in": "", "text": "Monitor physical access to the facility where the system resides using physical intrusion alarms and surveillance equipment.", "determinations": ["DS-A.03.10.01E[01]", "DS-A.03.10.01E[02]"]},
	"ES-03.10.02E-a": {"family": "3.10", "requirement": "03.10.02E", "parent": "ES-03.10.02E", "lead_in": "", "text": "Authorize and control [Assignment: organization-defined types of system components] entering and exiting the facility.", "determinations": ["DS-A.03.10.02E.a[01]", "DS-A.03.10.02E.a[02]", "DS-A.03.10.02E.a[03]", "DS-A.03.10.02E.a[04]"]},
	"ES-03.10.02E-b": {"family": "3.10", "requirement": "03.10.02E", "parent": "ES-03.10.02E", "lead_in": "", "text": "Maintain records of the system components.", "determinations": ["DS-A.03.10.02E.b"]},
	# ── 3.11 Risk Assessment
	"ES-03.11.01E": {"family": "3.11", "requirement": "03.11.01E", "parent": null, "lead_in": "", "text": "Implement a threat awareness program that includes a cross-organization information-sharing capability for threat intelligence.", "determinations": ["DS-A.03.11.01E"]},
	"ES-03.11.02E-a-1": {"family": "3.11", "requirement": "03.11.02E", "parent": "ES-03.11.02E-a", "lead_in": "Establish and maintain a cyber threat-hunting capability to:", "text": "Search for indicators of compromise in organizational systems and", "determinations": ["DS-A.03.11.02E.a.01[01]", "DS-A.03.11.02E.a.01[02]"]},
	"ES-03.11.02E-a-2": {"family": "3.11", "requirement": "03.11.02E", "parent": "ES-03.11.02E-a", "lead_in": "Establish and maintain a cyber threat-hunting capability to:", "text": "Detect, track, and disrupt threats that evade existing safeguards.", "determinations": ["DS-A.03.11.02E.a.02[01]", "DS-A.03.11.02E.a.02[02]"]},
	"ES-03.11.02E-b": {"family": "3.11", "requirement": "03.11.02E", "parent": "ES-03.11.02E", "lead_in": "", "text": "Employ the threat-hunting capability [Assignment: organization-defined frequency].", "determinations": ["DS-A.03.11.02E.b"]},
	"ES-03.11.03E": {"family": "3.11", "requirement": "03.11.03E", "parent": null, "lead_in": "", "text": "Employ the following advanced automation and analytics capabilities to predict and identify risks to [Assignment: organization-defined systems or system components]: [Assignment: organization-defined advanced automation and analytics capabilities].", "determinations": ["DS-A.03.11.03E[01]", "DS-A.03.11.03E[02]"]},
	"ES-03.11.08E": {"family": "3.11", "requirement": "03.11.08E", "parent": null, "lead_in": "", "text": "Determine the current cyber threat environment on an ongoing basis using [Assignment: organization-defined means].", "determinations": ["DS-A.03.11.08E"]},
	"ES-03.11.09E": {"family": "3.11", "requirement": "03.11.09E", "parent": null, "lead_in": "", "text": "Discover, collect, and distribute to [Assignment: organization-defined personnel or roles], indicators of compromise provided by [Assignment: organization-defined sources].", "determinations": ["DS-A.03.11.09E[01]", "DS-A.03.11.09E[02]", "DS-A.03.11.09E[03]"]},
	"ES-03.11.10E": {"family": "3.11", "requirement": "03.11.10E", "parent": null, "lead_in": "", "text": "Identify critical system components and functions by performing a criticality analysis for [Assignment: organization-defined systems, system components, or system services] at [Assignment: organization-defined decision points in the system development life cycle].", "determinations": ["DS-A.03.11.10E"]},
	"ES-03.11.11E": {"family": "3.11", "requirement": "03.11.11E", "parent": null, "lead_in": "", "text": "Determine information about the system that is discoverable and take [Assignment: organization-defined corrective actions].", "determinations": ["DS-A.03.11.11E[01]", "DS-A.03.11.11E[02]"]},
	"ES-03.11.12E": {"family": "3.11", "requirement": "03.11.12E", "parent": null, "lead_in": "", "text": "Employ automated mechanisms to maximize the effectiveness of sharing threat intelligence information.", "determinations": ["DS-A.03.11.12E"]},
	# ── 3.12 Security Assessment and Monitoring
	"ES-03.12.01E": {"family": "3.12", "requirement": "03.12.01E", "parent": null, "lead_in": "", "text": "Conduct penetration testing [Assignment: organization-defined frequency] on [Assignment: organization-defined systems or system components].", "determinations": ["DS-A.03.12.01E"]},
	"ES-03.12.02E": {"family": "3.12", "requirement": "03.12.02E", "parent": null, "lead_in": "", "text": "Use independent assessors or assessment teams to conduct security requirement assessments.", "determinations": ["DS-A.03.12.02E"]},
	"ES-03.12.03E": {"family": "3.12", "requirement": "03.12.03E", "parent": null, "lead_in": "", "text": "Ensure risk monitoring is an integral part of the continuous monitoring strategy that includes effectiveness monitoring, compliance monitoring, change monitoring.", "determinations": ["DS-A.03.12.03E[01]", "DS-A.03.12.03E[02]", "DS-A.03.12.03E[03]", "DS-A.03.12.03E[04]"]},
	"ES-03.12.04E-a": {"family": "3.12", "requirement": "03.12.04E", "parent": "ES-03.12.04E", "lead_in": "", "text": "Authorize internal connections of [Assignment: organization-defined system components or classes of components] to the system.", "determinations": ["DS-A.03.12.04E.a"]},
	"ES-03.12.04E-b": {"family": "3.12", "requirement": "03.12.04E", "parent": "ES-03.12.04E", "lead_in": "", "text": "Document, for each internal connection, the interface characteristics, security requirements, and the nature of the information communicated.", "determinations": ["DS-A.03.12.04E.b[01]", "DS-A.03.12.04E.b[02]", "DS-A.03.12.04E.b[03]"]},
	"ES-03.12.04E-c": {"family": "3.12", "requirement": "03.12.04E", "parent": "ES-03.12.04E", "lead_in": "", "text": "Terminate internal system connections after [Assignment: organization-defined conditions].", "determinations": ["DS-A.03.12.04E.c"]},
	"ES-03.12.04E-d": {"family": "3.12", "requirement": "03.12.04E", "parent": "ES-03.12.04E", "lead_in": "", "text": "Review [Assignment: organization-defined frequency] the continued need for each internal connection.", "determinations": ["DS-A.03.12.04E.d"]},
	# ── 3.13 System and Communications Protection
	"ES-03.13.01E": {"family": "3.13", "requirement": "03.13.01E", "parent": null, "lead_in": "", "text": "Employ a diverse set of information technologies for the following system components in the implementation of the system: [Assignment: organization-defined system components].", "determinations": ["DS-A.03.13.01E"]},
	"ES-03.13.02E": {"family": "3.13", "requirement": "03.13.02E", "parent": null, "lead_in": "", "text": "Employ [Assignment: organization-defined techniques] to introduce randomness into organizational operations and assets.", "determinations": ["DS-A.03.13.02E"]},
	"ES-03.13.03E": {"family": "3.13", "requirement": "03.13.03E", "parent": null, "lead_in": "", "text": "Employ the following concealment and misdirection techniques to mislead adversaries: [Assignment: organization-defined concealment and misdirection techniques].", "determinations": ["DS-A.03.13.03E"]},
	"ES-03.13.04E": {"family": "3.13", "requirement": "03.13.04E", "parent": null, "lead_in": "", "text": "Employ boundary protection mechanisms to isolate [Assignment: organization-defined system components].", "determinations": ["DS-A.03.13.04E"]},
	"ES-03.13.05E": {"family": "3.13", "requirement": "03.13.05E", "parent": null, "lead_in": "", "text": "Change the location of [Assignment: organization-defined processing and/or storage] [Selection (one): [Assignment: organization-defined time frequency]; at random time intervals].", "determinations": ["DS-A.03.13.05E"]},
	"ES-03.13.06E": {"family": "3.13", "requirement": "03.13.06E", "parent": null, "lead_in": "", "text": "Include within organizational systems the following platform independent applications: [Assignment: organization-defined platform-independent applications].", "determinations": ["DS-A.03.13.06E"]},
	"ES-03.13.07E": {"family": "3.13", "requirement": "03.13.07E", "parent": null, "lead_in": "", "text": "Employ virtualization techniques to support the deployment of a diversity of operating systems and applications that are changed [Assignment: organization-defined frequency].", "determinations": ["DS-A.03.13.07E"]},
	"ES-03.13.08E": {"family": "3.13", "requirement": "03.13.08E", "parent": null, "lead_in": "", "text": "Include components within organizational systems specifically designed to be the target of malicious attacks for detecting, deflecting, and analyzing such attacks.", "determinations": ["DS-A.03.13.08E[01]", "DS-A.03.13.08E[02]", "DS-A.03.13.08E[03]"]},
	"ES-03.13.09E": {"family": "3.13", "requirement": "03.13.09E", "parent": null, "lead_in": "", "text": "Isolate [Assignment: organization-defined information security tools, mechanisms, and support components] from other internal system components by implementing physically separate subnetworks with managed interfaces to other components of the system.", "determinations": ["DS-A.03.13.09E"]},
	"ES-03.13.10E": {"family": "3.13", "requirement": "03.13.10E", "parent": null, "lead_in": "", "text": "Implement separate network addresses to connect to systems in different security domains.", "determinations": ["DS-A.03.13.10E"]},
	"ES-03.13.11E": {"family": "3.13", "requirement": "03.13.11E", "parent": null, "lead_in": "", "text": "Employ minimal functionality and information storage on the following system components: [Assignment: organization-defined system components].", "determinations": ["DS-A.03.13.11E[01]", "DS-A.03.13.11E[02]"]},
	"ES-03.13.12E-a": {"family": "3.13", "requirement": "03.13.12E", "parent": "ES-03.13.12E", "lead_in": "", "text": "[Selection (one): Protect against; Limit] the effects of the following types of denial-of-service events: [Assignment: organization-defined types of denial-of-service events].", "determinations": ["DS-A.03.13.12E.a"]},
	"ES-03.13.12E-b": {"family": "3.13", "requirement": "03.13.12E", "parent": "ES-03.13.12E", "lead_in": "", "text": "Employ the following safeguards to prevent the denial-of-service events[Assignment: organization-defined safeguards by type of denial-of-service event].", "determinations": ["DS-A.03.13.12E.b"]},
	"ES-03.13.13E": {"family": "3.13", "requirement": "03.13.13E", "parent": null, "lead_in": "", "text": "[Selection (one): Physically; Logically] disable or remove [Assignment: organization-defined connection ports or input/output devices] on the following systems or system components: [Assignment: organization-defined systems or system components].", "determinations": ["DS-A.03.13.13E"]},
	"ES-03.13.14E": {"family": "3.13", "requirement": "03.13.14E", "parent": null, "lead_in": "", "text": "Employ a detonation chamber capability within [Assignment: organization-defined system, system component, or location].", "determinations": ["DS-A.03.13.14E"]},
	"ES-03.13.15E": {"family": "3.13", "requirement": "03.13.15E", "parent": null, "lead_in": "", "text": "Implement [Selection (one): physically; logically] separate subnetworks to isolate the following critical system components and functions: [Assignment: organization-defined critical system components and functions].", "determinations": ["DS-A.03.13.15E"]},
	"ES-03.13.16E": {"family": "3.13", "requirement": "03.13.16E", "parent": null, "lead_in": "", "text": "Partition the system into [Assignment: organization-defined system components] residing in separate [Selection (one): physical; logical] domains or environments based on [Assignment: organization-defined circumstances for physical or logical separation of components].", "determinations": ["DS-A.03.13.16E"]},
	# ── 3.14 System and Information Integrity
	"ES-03.14.01E-a": {"family": "3.14", "requirement": "03.14.01E", "parent": "ES-03.14.01E", "lead_in": "", "text": "Employ integrity verification tools to detect unauthorized changes to the following software, firmware, and information: [Assignment: organization-defined software, firmware, and information].", "determinations": ["DS-A.03.14.01E.a[01]", "DS-A.03.14.01E.a[02]", "DS-A.03.14.01E.a[03]"]},
	"ES-03.14.01E-b": {"family": "3.14", "requirement": "03.14.01E", "parent": "ES-03.14.01E", "lead_in": "", "text": "Take the following actions when unauthorized changes to the software, firmware, and information are detected: [Assignment: organization-defined actions].", "determinations": ["DS-A.03.14.01E.b[01]", "DS-A.03.14.01E.b[02]", "DS-A.03.14.01E.b[03]"]},
	"ES-03.14.04E": {"family": "3.14", "requirement": "03.14.04E", "parent": null, "lead_in": "", "text": "Obtain software and data employed during system component and service refreshes from the following trusted sources: [Assignment: organization-defined trusted sources].", "determinations": ["DS-A.03.14.04E"]},
	"ES-03.14.05E-a": {"family": "3.14", "requirement": "03.14.05E", "parent": "ES-03.14.05E", "lead_in": "", "text": "[Selection (one): Refresh [Assignment: organization-defined information] [Assignment: organization-defined frequency]; Generate [Assignment: organization-defined information] on demand].", "determinations": ["DS-A.03.14.05E.a"]},
	"ES-03.14.05E-b": {"family": "3.14", "requirement": "03.14.05E", "parent": "ES-03.14.05E", "lead_in": "", "text": "Delete information when no longer needed.", "determinations": ["DS-A.03.14.05E.b"]},
	"ES-03.14.08E": {"family": "3.14", "requirement": "03.14.08E", "parent": null, "lead_in": "", "text": "Perform an integrity check of [Assignment: organization-defined software, firmware, and information] [Selection (one or more): at startup; at [Assignment: organization-defined transitional states or security-relevant events]; [Assignment: organization-defined frequency]].", "determinations": ["DS-A.03.14.08E[01]", "DS-A.03.14.08E[02]", "DS-A.03.14.08E[03]"]},
	"ES-03.14.09E": {"family": "3.14", "requirement": "03.14.09E", "parent": null, "lead_in": "", "text": "Implement cryptographic mechanisms to detect unauthorized changes to software, firmware, and information.", "determinations": ["DS-A.03.14.09E[01]", "DS-A.03.14.09E[02]", "DS-A.03.14.09E[03]"]},
	"ES-03.14.10E": {"family": "3.14", "requirement": "03.14.10E", "parent": null, "lead_in": "", "text": "Implement the following mechanisms to protect the integrity of boot firmware in [Assignment: organization-defined system components]: [Assignment: organization-defined mechanisms].", "determinations": ["DS-A.03.14.10E"]},
	"ES-03.14.11E": {"family": "3.14", "requirement": "03.14.11E", "parent": null, "lead_in": "", "text": "Incorporate the detection of the following unauthorized changes into the organizational incident response capability: [Assignment: organization-defined security-relevant changes to the system].", "determinations": ["DS-A.03.14.11E"]},
	"ES-03.14.12E": {"family": "3.14", "requirement": "03.14.12E", "parent": null, "lead_in": "", "text": "Check the validity of the following information inputs: [Assignment: organization-defined information inputs to the system].", "determinations": ["DS-A.03.14.12E"]},
	"ES-03.14.13E-a": {"family": "3.14", "requirement": "03.14.13E", "parent": "ES-03.14.13E", "lead_in": "", "text": "Generate error messages that provide information necessary for corrective actions without revealing information that could be exploited.", "determinations": ["DS-A.03.14.13E.a"]},
	"ES-03.14.13E-b": {"family": "3.14", "requirement": "03.14.13E", "parent": "ES-03.14.13E", "lead_in": "", "text": "Reveal error messages only to [Assignment: organization-defined personnel or roles].", "determinations": ["DS-A.03.14.13E.b"]},
	"ES-03.14.14E": {"family": "3.14", "requirement": "03.14.14E", "parent": null, "lead_in": "", "text": "Implement the following safeguards to protect the system memory from unauthorized code execution: [Assignment: organization-defined safeguards].", "determinations": ["DS-A.03.14.14E"]},
	"ES-03.14.15E-a": {"family": "3.14", "requirement": "03.14.15E", "parent": "ES-03.14.15E", "lead_in": "", "text": "Implement non-persistent [Assignment: organization-defined system components and services].", "determinations": ["DS-A.03.14.15E.a"]},
	"ES-03.14.15E-b": {"family": "3.14", "requirement": "03.14.15E", "parent": "ES-03.14.15E", "lead_in": "", "text": "Initiate non-persistent [Assignment: organization-defined system components and services] from a known state.", "determinations": ["DS-A.03.14.15E.b"]},
	"ES-03.14.15E-c": {"family": "3.14", "requirement": "03.14.15E", "parent": "ES-03.14.15E", "lead_in": "", "text": "Terminate non-persistent [Assignment: organization-defined system components and services] [Selection (one or more): upon end of session of use; [Assignment: organization-defined frequency]].", "determinations": ["DS-A.03.14.15E.c"]},
	"ES-03.14.16E": {"family": "3.14", "requirement": "03.14.16E", "parent": null, "lead_in": "", "text": "Embed data or capabilities in the following systems or system components to determine if CUI has been exfiltrated or improperly removed from the organization: [Assignment: organization-defined systems or system components].", "determinations": ["DS-A.03.14.16E"]},
	"ES-03.14.17E": {"family": "3.14", "requirement": "03.14.17E", "parent": null, "lead_in": "", "text": "Alert [Assignment: organization-defined personnel or roles] when the following system-generated indications of compromise or potential compromise occur: [Assignment: organization-defined compromise indicators].", "determinations": ["DS-A.03.14.17E"]},
	"ES-03.14.18E": {"family": "3.14", "requirement": "03.14.18E", "parent": null, "lead_in": "", "text": "Alert [Assignment: organization-defined personnel or roles] using [Assignment: organization-defined automated mechanisms] when the following indications of inappropriate or unusual activities with security implications occur: [Assignment: organization-defined activities that trigger alerts].", "determinations": ["DS-A.03.14.18E"]},
	"ES-03.14.19E": {"family": "3.14", "requirement": "03.14.19E", "parent": null, "lead_in": "", "text": "Employ a wireless intrusion detection system to identify rogue wireless devices and to detect attack attempts and potential compromises or breaches to the system", "determinations": ["DS-A.03.14.19E[01]", "DS-A.03.14.19E[02]", "DS-A.03.14.19E[03]"]},
	# ── 3.15 Planning
	"ES-03.15.01E-a-1": {"family": "3.15", "requirement": "03.15.01E", "parent": "ES-03.15.01E-a", "lead_in": "Develop a security architecture for the system that:", "text": "Describes the security requirements and approach to be taken for protecting the confidentiality, integrity, and availability of CUI,", "determinations": ["DS-A.03.15.01E.a.01"]},
	"ES-03.15.01E-a-2": {"family": "3.15", "requirement": "03.15.01E", "parent": "ES-03.15.01E-a", "lead_in": "Develop a security architecture for the system that:", "text": "Describes how the architecture is integrated into and supports the enterprise architecture, and", "determinations": ["DS-A.03.15.01E.a.02"]},
	"ES-03.15.01E-a-3": {"family": "3.15", "requirement": "03.15.01E", "parent": "ES-03.15.01E-a", "lead_in": "Develop a security architecture for the system that:", "text": "Describes any assumptions about, and dependencies on, external systems and services.", "determinations": ["DS-A.03.15.01E.a.03"]},
	"ES-03.15.01E-b": {"family": "3.15", "requirement": "03.15.01E", "parent": "ES-03.15.01E", "lead_in": "", "text": "Review and update the security architecture [Assignment: organization-defined frequency] to reflect changes in the enterprise architecture.", "determinations": ["DS-A.03.15.01E.b"]},
	"ES-03.15.01E-c": {"family": "3.15", "requirement": "03.15.01E", "parent": "ES-03.15.01E", "lead_in": "", "text": "Reflect planned security architecture changes in system security plans, concept of operations, criticality analysis, organizational procedures, and procurements and acquisitions.", "determinations": ["DS-A.03.15.01E.c"]},
	"ES-03.15.02E-a": {"family": "3.15", "requirement": "03.15.02E", "parent": "ES-03.15.02E", "lead_in": "", "text": "Design the security architecture for the system using a defense-in-depth approach.", "determinations": ["DS-A.03.15.02E.a"]},
	"ES-03.15.02E-b": {"family": "3.15", "requirement": "03.15.02E", "parent": "ES-03.15.02E", "lead_in": "", "text": "Allocate [Assignment: organization-defined security requirements] to [Assignment: organization-defined architectural layers and locations].", "determinations": ["DS-A.03.15.02E.b"]},
	"ES-03.15.02E-c": {"family": "3.15", "requirement": "03.15.02E", "parent": "ES-03.15.02E", "lead_in": "", "text": "Ensure that the allocated requirements operate in a coordinated and mutually reinforcing manner.", "determinations": ["DS-A.03.15.02E.c"]},
	"ES-03.15.03E": {"family": "3.15", "requirement": "03.15.03E", "parent": null, "lead_in": "", "text": "Require that [Assignment: organization-defined safeguards] allocated to [Assignment: organization-defined locations and architectural layers] are obtained from different suppliers.", "determinations": ["DS-A.03.15.03E"]},
	# ── 3.16 System and Services Acquisition
	"ES-03.16.01E": {"family": "3.16", "requirement": "03.16.01E", "parent": null, "lead_in": "", "text": "Employ [Selection (one or more): design; modification; augmentation; reconfiguration] on [Assignment: organization-defined systems or system components] supporting mission-essential services or functions to increase the trustworthiness in those systems or components.", "determinations": ["DS-A.03.16.01E"]},
	# ── 3.17 Supply Chain Risk Management
	"ES-03.17.01E": {"family": "3.17", "requirement": "03.17.01E", "parent": null, "lead_in": "", "text": "Establish agreements and procedures with entities involved in the supply chain for the system, system component, or system service for the [Selection (one or more): notification of supply chain compromises; results of assessments or audits; [Assignment: organization-defined information]].", "determinations": ["DS-A.03.17.01E"]},
	"ES-03.17.02E": {"family": "3.17", "requirement": "03.17.02E", "parent": null, "lead_in": "", "text": "Inspect the following systems or system components [Selection (one or more): at random; [Assignment: organization-defined frequency]; upon [Assignment: organization-defined indications of need for inspection]] to detect tampering: [Assignment: organization-defined systems or system components].", "determinations": ["DS-A.03.17.02E"]},
	"ES-03.17.03E-a": {"family": "3.17", "requirement": "03.17.03E", "parent": "ES-03.17.03E", "lead_in": "", "text": "Develop and implement anti-counterfeit policy and procedures that include the means to detect and prevent counterfeit components from entering the system.", "determinations": ["DS-A.03.17.03E.a[01]", "DS-A.03.17.03E.a[02]", "DS-A.03.17.03E.a[03]", "DS-A.03.17.03E.a[04]"]},
	"ES-03.17.03E-b": {"family": "3.17", "requirement": "03.17.03E", "parent": "ES-03.17.03E", "lead_in": "", "text": "Report counterfeit system components to [Selection (one or more): source of counterfeit component; [Assignment: organization-defined external reporting organizations]; [Assignment: organization-defined personnel or roles]].", "determinations": ["DS-A.03.17.03E.b"]},
	"ES-03.17.04E": {"family": "3.17", "requirement": "03.17.04E", "parent": null, "lead_in": "", "text": "Document, monitor, and maintain valid provenance of the following systems, system components, and associated CUI: [Assignment: organization-defined systems, system components, and associated CUI].", "determinations": ["DS-A.03.17.04E[01]", "DS-A.03.17.04E[02]", "DS-A.03.17.04E[03]"]},
	"ES-03.17.05E": {"family": "3.17", "requirement": "03.17.05E", "parent": null, "lead_in": "", "text": "Employ [Assignment: organization-defined safeguards] and conduct [Assignment: organization-defined analysis] to ensure the integrity of the system and system components by validating the internal composition and provenance of critical or mission-essential technologies, products, and services.", "determinations": ["DS-A.03.17.05E[01]", "DS-A.03.17.05E[02]"]},
}

# SP 800-172A Rev 3 determination id -> determination statement
determination_text := {
	"DS-A.03.01.01E": "dual authorization is enforced for <A.03.01.01E.ODP[01]: privileged commands and/or other actions>.",
	"DS-A.03.01.02E": "the use of non-organizationally owned systems or system components to process, store, or transmit CUI is restricted using <A.03.01.02E.ODP[01]: restrictions>.",
	"DS-A.03.01.04E": "the number of concurrent sessions for each <A.03.01.04E.ODP[01]: account and/or account types> is limited to <A.03.01.04E.ODP[02]: number>.",
	"DS-A.03.01.05E[01]": "automated mechanisms are employed to monitor remote access methods.",
	"DS-A.03.01.05E[02]": "automated mechanisms are employed to control remote access methods.",
	"DS-A.03.01.06E": "information about remote access mechanisms is protected from unauthorized use and disclosure.",
	"DS-A.03.01.07E[01]": "automated mechanisms are used to audit account creation actions.",
	"DS-A.03.01.07E[02]": "automated mechanisms are used to audit account modification actions.",
	"DS-A.03.01.07E[03]": "automated mechanisms are used to audit account enabling actions.",
	"DS-A.03.01.07E[04]": "automated mechanisms are used to audit account disabling actions.",
	"DS-A.03.01.07E[05]": "automated mechanisms are used to audit account removal actions.",
	"DS-A.03.01.08E.a": "system accounts are monitored for <A.03.01.08E.ODP[01]: atypical usage>.",
	"DS-A.03.01.08E.b": "atypical usage of system accounts is reported to <A.03.01.08E.ODP[02]: personnel or roles>.",
	"DS-A.03.01.09E.a[01]": "the attribute-based access control policy is enforced over defined subjects.",
	"DS-A.03.01.09E.a[02]": "the attribute-based access control policy is enforced over defined objects.",
	"DS-A.03.01.09E.b": "access is controlled based upon <A.03.01.09E.ODP[01]: attributes>.",
	"DS-A.03.01.10E": "<A.03.01.10E.ODP[01]: security attributes> associated with <A.03.01.10E.ODP[02]: information objects>, <A.03.01.10E.ODP[03]: source objects>, and <A.03.01.10E.ODP[04]: destination objects> are used to enforce <A.03.01.10E.ODP[05]: information flow control policies> as a basis for flow control decisions.",
	"DS-A.03.01.11E.a": "a role-based access control policy over defined subjects and objects is enforced.",
	"DS-A.03.01.11E.b": "access is controlled based upon <A.03.01.11E.ODP[01] roles and authorized users>.",
	"DS-A.03.01.12E": "CUI flows are logically or physically separated using <A.03.01.12E.ODP[01] mechanisms and/or techniques>.",
	"DS-A.03.01.13E": "information flow control based on <A.03.01.13E.ODP[01]: metadata> is enforced.",
	"DS-A.03.01.14E.a": "information flow control is enforced using <A.03.01.14E.ODP[01] security policy filters> as a basis for flow control decisions for <A.03.01.14E.ODP[02] information flows>.",
	"DS-A.03.01.14E.b": "<A.03.01.14E.ODP[03]: SELECTED PARAMETER VALUE(S)> data after a filter processing failure in accordance with <A.03.01.14E.ODP[04] security policy>.",
	"DS-A.03.01.15E": "when transferring information between security domains, <A.03.01.15E.ODP[01]: data type identifiers> are used to validate data that is essential for information flow decisions.",
	"DS-A.03.01.16E": "when transferring information between different security domains, CUI is decomposed into <A.03.01.16E.ODP[01]: policy-relevant subcomponents> for submission to policy enforcement mechanisms",
	"DS-A.03.01.17E.a": "when transferring information between different security domains, information is examined for the presence of <A.03.01.17E.ODP[01] unsanctioned information>.",
	"DS-A.03.01.17E.b": "the transfer of CUI defined in 03.01.17E.a is prohibited in accordance with <A.03.01.17E.ODP[02] security policy>.",
	"DS-A.03.02.01E.a.01": "security literacy training on the advanced persistent threat is provided to system users.",
	"DS-A.03.02.01E.a.02": "security literacy training on recognizing suspicious communications and anomalous behavior in systems using <A.03.02.01E.ODP[01]: indicators of malicious code> is provided to system users.",
	"DS-A.03.02.01E.a.03": "security literacy training on the cyber threat environment is provided to system users.",
	"DS-A.03.02.01E.b[01]": "security literacy training content is updated <A.03.02.01E.ODP[02]: frequency>.",
	"DS-A.03.02.01E.b[02]": "security literacy training content is updated following <A.03.02.01E.ODP[03]: events>",
	"DS-A.03.02.02E": "practical exercises in literacy training that simulate events and incidents are provided.",
	"DS-A.03.02.03E": "feedback on organizational training results is provided to <A.03.02.03E.ODP[01]: personnel>.",
	"DS-A.03.02.04E": "<A.03.02.04E.ODP[01]: personnel or roles> are trained to detect counterfeit system components.",
	"DS-A.03.03.01E": "audit records are stored in a repository that is part of a physically different system or system component than the system or component being audited.",
	"DS-A.03.03.02E": "an alert is provided within <A.03.03.02E.ODP[01]: real-time period> to <A.03.03.02E.ODP[02]: personnel, roles, and/or locations> when <A.03.03.02E.ODP[03]: audit logging failure events> occur.",
	"DS-A.03.03.03E": "dual authorization is enforced for the <A.03.03.03E.ODP[01]: SELECTED PARAMETER VALUE(S)> of <A.03.03.03E.ODP[02]: audit information>.",
	"DS-A.03.03.04E": "analysis of audit records is integrated with analysis of <A.03.03.04E.ODP[01]: SELECTED PARAMETER VALUE(S)> to further enhance the ability to identify inappropriate or unusual activity.",
	"DS-A.03.04.02E.a": "the presence of unauthorized or misconfigured system components is detected using <A.03.04.02E.ODP[01]: automated mechanisms>.",
	"DS-A.03.04.02E.b": "one or more of the following actions is/are taken when unauthorized or misconfigured system components are detected: <A.03.04.02E.ODP[02]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.04.03E[01]": "<A.03.04.03E.ODP[01]: automated mechanisms> are used to maintain the currency of the system component inventory.",
	"DS-A.03.04.03E[02]": "<A.03.04.03E.ODP[02]: automated mechanisms> are used to maintain the completeness of the system component inventory.",
	"DS-A.03.04.03E[03]": "<A.03.04.03E.ODP[03]: automated mechanisms> are used to maintain the accuracy of the system component inventory.",
	"DS-A.03.04.03E[04]": "<A.03.04.03E.ODP[04]: automated mechanisms> are used to maintain the availability of the system component inventory.",
	"DS-A.03.04.04E[01]": "the currency of the baseline configuration of the system is maintained using <A.03.04.04E.ODP[01]: automated mechanisms>.",
	"DS-A.03.04.04E[02]": "the completeness of the baseline configuration of the system is maintained using <A.03.04.04E.ODP[01]: automated mechanisms>.",
	"DS-A.03.04.04E[03]": "the accuracy of the baseline configuration of the system is maintained using <A.03.04.04E.ODP[01]: automated mechanisms>.",
	"DS-A.03.04.04E[04]": "the availability of the baseline configuration of the system is maintained using <A.03.04.04E.ODP[01]: automated mechanisms>.",
	"DS-A.03.04.05E[01]": "dual authorization for implementing changes to <A.03.04.05E.ODP[01]: system components> is enforced.",
	"DS-A.03.04.05E[02]": "dual authorization for implementing changes to <A.03.04.05E.ODP[02]: system-level information> is enforced.",
	"DS-A.03.04.06E": "<A.03.04.06E.ODP[01]: number> previous versions of baseline configurations of the system are retained to support rollback.",
	"DS-A.03.04.07E[01]": "changes to the system are tested before finalizing the implementation of the changes.",
	"DS-A.03.04.07E[02]": "changes to the system are validated before finalizing the implementation of the changes.",
	"DS-A.03.04.07E[03]": "changes to the system are documented before finalizing the implementation of the changes.",
	"DS-A.03.04.08E": "a centralized repository for the inventory of system components is provided.",
	"DS-A.03.05.01E": "<A.03.05.01E.ODP[01]: devices and/or types of devices> are authenticated before establishing a system connection using bidirectional authentication that is cryptographically based.",
	"DS-A.03.05.02E.a": "<A.03.05.02E.ODP[01]: password managers> are employed to generate and manage passwords.",
	"DS-A.03.05.02E.b": "passwords are protected using <A.03.05.02E.ODP[02]: safeguards>.",
	"DS-A.03.05.03E": "device identification and authentication are handled based on attestation by <A.03.05.03E.ODP[01]: configuration management process>.",
	"DS-A.03.05.04E": "unencrypted static authenticators are not embedded in applications or other forms of static storage.",
	"DS-A.03.05.05E": "the use of cached authenticators is prohibited after <A.03.05.05E.ODP[01]: time period>.",
	"DS-A.03.05.06E.a": "users who require accounts for logical access to systems based on appropriate identity assurance level requirements as specified in applicable standards and guidelines are identity-proofed.",
	"DS-A.03.05.06E.b": "user identities are resolved to a unique individual.",
	"DS-A.03.05.06E.c[01]": "identity evidence is collected.",
	"DS-A.03.05.06E.c[02]": "identity evidence is validated.",
	"DS-A.03.05.06E.c[03]": "identity evidence is verified.",
	"DS-A.03.05.07E[01]": "identity providers are employed to manage user, device, and non-person entity identities, attributes, and access rights supporting authentication decisions in accordance with <A.03.05.07E.ODP[01]: policy> using <A.03.05.07E.ODP[02]: mechanisms>.",
	"DS-A.03.05.07E[02]": "identity providers are employed to manage user, device, and non-person entity identities, attributes, and access rights supporting authorization decisions in accordance with <A.03.05.07E.ODP[01]: policy> using <A.03.05.07E.ODP[02]: mechanisms>.",
	"DS-A.03.05.07E[03]": "authorization servers are employed to manage user, device, and non-person entity identities, attributes, and access rights supporting authentication decisions in accordance with <A.03.05.07E.ODP[01]: policy> using <A.03.05.07E.ODP[02]: mechanisms>.",
	"DS-A.03.06.01E[01]": "a security operations center is established.",
	"DS-A.03.06.01E[02]": "a security operations center is maintained.",
	"DS-A.03.06.02E[01]": "an integrated incident response team is established.",
	"DS-A.03.06.02E[02]": "an integrated incident response team is maintained.",
	"DS-A.03.06.02E[03]": "the integrated incident response team can be deployed to any location identified by the organization in <A.03.06.02E.ODP[01]: time period>.",
	"DS-A.03.06.03E": "anomalous or suspected adversarial behavior in or related to <A.03.06.03E.ODP[01]: environments or resources> is analyzed.",
	"DS-A.03.06.04E[01]": "incidents are tracked using <A.03.06.04E.ODP[01]: automated mechanisms>.",
	"DS-A.03.06.04E[02]": "incident information is collected using <A.03.06.04E.ODP[02]: automated mechanisms>.",
	"DS-A.03.06.04E[03]": "incident information is analyzed using <A.03.06.04E.ODP[03]: automated mechanisms>.",
	"DS-A.03.07.01E": "maintenance tools are inspected to ensure that the latest software updates and patches are installed.",
	"DS-A.03.08.01E": "dual authorization for the sanitization of <A.03.08.01E.ODP[01]: system media> is enforced.",
	"DS-A.03.08.02E": "dual authorization for the deletion or destruction of <A.03.08.02E.ODP[01]: system backup information> is enforced.",
	"DS-A.03.08.03E[01]": "backup information is tested <A.03.08.03E.ODP[01]: frequency> to verify media reliability.",
	"DS-A.03.08.03E[02]": "backup information is tested <A.03.08.03E.ODP[02]: frequency> to verify information integrity.",
	"DS-A.03.08.04E[01]": "the recovery of the system to a known state is provided within <A.03.08.04E.ODP[01]: time period> after a disruption, compromise, or failure.",
	"DS-A.03.08.04E[02]": "the reconstitution of the system to a known state is provided within <A.03.08.04E.ODP[02]: time period> after a disruption, compromise, or failure.",
	"DS-A.03.09.03E.a": "access agreements are developed and documented for systems processing, storing, or transmitting CUI.",
	"DS-A.03.09.03E.b[01]": "access agreements are reviewed <A.03.09.03E.ODP[01]: frequency>.",
	"DS-A.03.09.03E.b[02]": "access agreements are updated <A.03.09.03E.ODP[01]: frequency>.",
	"DS-A.03.09.03E.c.01": "individuals requiring access to CUI and systems processing, storing, or transmitting CUI sign appropriate access agreements prior to being granted access.",
	"DS-A.03.09.03E.c.02": "individuals requiring access to CUI and systems processing, storing, or transmitting CUI re-sign access agreements to maintain access when access agreements have been updated or <A.03.09.03E.ODP[02]: frequency>.",
	"DS-A.03.09.04E": "individuals accessing a system processing, storing, or transmitting CUI meet <A.03.09.04E.ODP[01] citizenship requirements>.",
	"DS-A.03.10.01E[01]": "physical access to the facility where the system resides is monitored using physical intrusion alarms.",
	"DS-A.03.10.01E[02]": "physical access to the facility where the system resides is monitored using physical surveillance equipment.",
	"DS-A.03.10.02E.a[01]": "<A.03.10.02E.ODP[01]: types of system components> are authorized when entering the facility.",
	"DS-A.03.10.02E.a[02]": "<A.03.10.02E.ODP[01]: types of system components> are controlled when entering the facility.",
	"DS-A.03.10.02E.a[03]": "<A.03.10.02E.ODP[02]: types of system components> are authorized when exiting the facility.",
	"DS-A.03.10.02E.a[04]": "<A.03.10.02E.ODP[02]: types of system components> are controlled when exiting the facility.",
	"DS-A.03.10.02E.b": "records of the system components entering and exiting the facility are maintained.",
	"DS-A.03.11.01E": "a threat awareness program that includes a cross-organization information-sharing capability for threat intelligence is implemented.",
	"DS-A.03.11.02E.a.01[01]": "a cyber threat-hunting capability is established to search for indicators of compromise in organizational systems.",
	"DS-A.03.11.02E.a.01[02]": "a cyber threat-hunting capability is maintained to search for indicators of compromise in organizational systems.",
	"DS-A.03.11.02E.a.02[01]": "a cyber threat-hunting capability is established to detect, track, and disrupt threats that evade existing safeguards.",
	"DS-A.03.11.02E.a.02[02]": "a cyber threat-hunting capability is maintained to detect, track, and disrupt threats that evade existing safeguards.",
	"DS-A.03.11.02E.b": "the threat-hunting capability is employed<A.03.11.02E.ODP[01]: frequency>.",
	"DS-A.03.11.03E[01]": "<A.03.11.03E.ODP[01]: advanced automation capabilities> are employed to predict and identify risks to <A.03.11.03E.ODP[02]: systems or system components>.",
	"DS-A.03.11.03E[02]": "<A.03.11.03E.ODP[03]: advanced analytics capabilities> are employed to predict and identify risks to <A.03.11.03E.ODP[02]: systems or system components>.",
	"DS-A.03.11.08E": "the current cyber threat environment is determined on an ongoing basis using <A.03.11.08E.ODP[01]: means>.",
	"DS-A.03.11.09E[01]": "indicators of compromise provided by <A.03.11.09E.ODP[01]: sources> are discovered.",
	"DS-A.03.11.09E[02]": "indicators of compromise provided by <A.03.11.09E.ODP[01]: sources> are collected.",
	"DS-A.03.11.09E[03]": "indicators of compromise provided by <A.03.11.09E.ODP[01]: sources> are distributed to <A.03.11.09E.ODP[02]: personnel or roles>.",
	"DS-A.03.11.10E": "critical system components and functions are identified by performing a criticality analysis for <A.03.11.10E.ODP[01]: systems, system components, or system services> at <A.03.11.10E.ODP[02]: decision points>.",
	"DS-A.03.11.11E[01]": "discoverable information about the system is identified.",
	"DS-A.03.11.11E[02]": "<A.03.11.11E.ODP[01]: corrective actions> are taken when information about the system is confirmed as discoverable.",
	"DS-A.03.11.12E": "automated mechanisms are employed to maximize the effectiveness of sharing threat intelligence information.",
	"DS-A.03.12.01E": "penetration testing is conducted <A.03.12.01E.ODP[01]: frequency> on <A.03.12.01E.ODP[02]: systems or system components>.",
	"DS-A.03.12.02E": "independent assessors or assessment teams are used to conduct security requirement assessments.",
	"DS-A.03.12.03E[01]": "risk monitoring is an integral part of the continuous monitoring strategy.",
	"DS-A.03.12.03E[02]": "effectiveness monitoring is included in risk monitoring.",
	"DS-A.03.12.03E[03]": "compliance monitoring is included in risk monitoring.",
	"DS-A.03.12.03E[04]": "change monitoring is included in risk monitoring.",
	"DS-A.03.12.04E.a": "internal connections of <A.03.12.04E.ODP[01]: system components or classes of components> to the system are authorized.",
	"DS-A.03.12.04E.b[01]": "for each internal connection, the interface characteristics are documented.",
	"DS-A.03.12.04E.b[02]": "for each internal connection, the security requirements are documented.",
	"DS-A.03.12.04E.b[03]": "for each internal connection, the nature of the information communicated is documented.",
	"DS-A.03.12.04E.c": "internal system connections are terminated after <A.03.12.04E.ODP[02]: conditions>.",
	"DS-A.03.12.04E.d": "the continued need for each internal connection is reviewed <A.03.12.04E.ODP[03]: frequency>.",
	"DS-A.03.13.01E": "a diverse set of information technologies is employed for <A.03.13.01E.ODP[01]: system components> in the implementation of the system.",
	"DS-A.03.13.02E": "<A.03.13.02E.ODP[01]: techniques> are employed to introduce randomness into organizational operations and assets.",
	"DS-A.03.13.03E": "<A.03.13.03E.ODP[01]: concealment and misdirection techniques> are used to mislead adversaries.",
	"DS-A.03.13.04E": "boundary protection mechanisms are employed to isolate <A.03.13.04E.ODP[01]: system components>.",
	"DS-A.03.13.05E": "the location of <A.03.13.05E.ODP[01]: processing and/or storage> is changed <A.03.13.05E.ODP[02]: SELECTED PARAMETER VALUE>.",
	"DS-A.03.13.06E": "<A.03.13.06E.ODP[01]: platform-independent applications> are implemented within organizational systems.",
	"DS-A.03.13.07E": "virtualization techniques are employed to support the deployment of a diverse range of operating systems and applications that are changed <A.03.13.07E.ODP[01]: frequency>.",
	"DS-A.03.13.08E[01]": "components within organizational systems specifically designed to be the target of malicious attacks are included to detect such attacks.",
	"DS-A.03.13.08E[02]": "components within organizational systems specifically designed to be the target of malicious attacks are included to deflect such attacks.",
	"DS-A.03.13.08E[03]": "components within organizational systems specifically designed to be the target of malicious attacks are included to analyze such attacks.",
	"DS-A.03.13.09E": "<A.03.13.09E.ODP[01]: information security tools, mechanisms, and support components> are isolated from other internal system components by implementing physically separate subnetworks with managed interfaces to other components of the system.",
	"DS-A.03.13.10E": "separate network addresses are implemented to connect to systems in different security domains.",
	"DS-A.03.13.11E[01]": "minimal functionality for <A.03.13.11E.ODP[01]: system components> is employed.",
	"DS-A.03.13.11E[02]": "minimal information storage on <A.03.13.11E.ODP[01]: system components> is employed.",
	"DS-A.03.13.12E.a": "the effects of <A.03.13.12E.ODP[01]: types of denial-of-service events> are <A.03.13.12E.ODP[02]: SELECTED PARAMETER VALUE>.",
	"DS-A.03.13.12E.b": "<A.03.13.12E.ODP[03]: safeguards> are employed to protect against or limit the effects of denial-of-service events.",
	"DS-A.03.13.13E": "<A.03.13.13E.ODP[01]: connection ports or input/output devices> are <A.03.13.13E.ODP[02]: SELECTED PARAMETER VALUE> disabled or removed on <A.03.13.13E.ODP[03]: systems or system components>.",
	"DS-A.03.13.14E": "a detonation chamber capability is employed within the <A.03.13.14E.ODP[01]: system, system component, or location>.",
	"DS-A.03.13.15E": "subnetworks are separated <A.03.13.15E.ODP[01]: SELECTED PARAMETER VALUE> to isolate <A.03.13.15E.ODP[02]: critical system components and functions>.",
	"DS-A.03.13.16E": "the system is partitioned into <A.03.13.16E.ODP[01]: system components> residing in separate <A.03.13.16E.ODP[02]: SELECTED PARAMETER VALUE> security domains or environments based on <A.03.13.16E.ODP[03]: circumstances>.",
	"DS-A.03.14.01E.a[01]": "integrity verification tools are employed to detect unauthorized changes to <A.03.14.01E.ODP[01]: software>.",
	"DS-A.03.14.01E.a[02]": "integrity verification tools are employed to detect unauthorized changes to <A.03.14.01E.ODP[02]: firmware>.",
	"DS-A.03.14.01E.a[03]": "integrity verification tools are employed to detect unauthorized changes to <A.03.14.01E.ODP[03]: information>.",
	"DS-A.03.14.01E.b[01]": "<A.03.14.01E.ODP[04]: actions> are taken when unauthorized changes to software are detected.",
	"DS-A.03.14.01E.b[02]": "<A.03.14.01E.ODP[05]: actions> are taken when unauthorized changes to firmware are detected.",
	"DS-A.03.14.01E.b[03]": "<A.03.14.01E.ODP[06]: actions> are taken when unauthorized changes to information are detected.",
	"DS-A.03.14.04E": "the software and data used during system component and service refreshes are obtained from <A.03.14.04E.ODP[01]: trusted sources>.",
	"DS-A.03.14.05E.a": "<A.03.14.05E.ODP[01]: SELECTED PARAMETER VALUE> is performed.",
	"DS-A.03.14.05E.b": "information is deleted when no longer needed.",
	"DS-A.03.14.08E[01]": "an integrity check of <A.03.14.08E.ODP[01]: software> is performed <A.03.14.08E.ODP[02]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.14.08E[02]": "an integrity check of <A.03.14.08E.ODP[05]: firmware> is performed <A.03.14.08E.ODP[06]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.14.08E[03]": "an integrity check of <A.03.14.08E.ODP[09]: information> is performed <A.03.14.08E.ODP[10]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.14.09E[01]": "cryptographic mechanisms are implemented to detect unauthorized changes to software.",
	"DS-A.03.14.09E[02]": "cryptographic mechanisms are implemented to detect unauthorized changes to firmware.",
	"DS-A.03.14.09E[03]": "cryptographic mechanisms are implemented to detect unauthorized changes to information.",
	"DS-A.03.14.10E": "<A.03.14.10E.ODP[01]: mechanisms> are implemented to protect the integrity of boot firmware in <A.03.14.10E.ODP[02]: system components>.",
	"DS-A.03.14.11E": "the detection of <A.03.14.11E.ODP[01]: changes> are incorporated into the organizational incident response capability.",
	"DS-A.03.14.12E": "the validity of the <A.03.14.12E.ODP[01]: information inputs> is checked.",
	"DS-A.03.14.13E.a": "error messages that provide the information necessary for corrective actions are generated without revealing information that could be exploited.",
	"DS-A.03.14.13E.b": "error messages are revealed only to <A.03.14.13E.ODP[01]: personnel or roles>.",
	"DS-A.03.14.14E": "<A.03.14.14E.ODP[01]: safeguards> are implemented to protect the system memory from unauthorized code execution.",
	"DS-A.03.14.15E.a": "<A.03.14.15E.ODP[01]: non-persistent system components and services> are implemented.",
	"DS-A.03.14.15E.b": "<A.03.14.15E.ODP[01]: non-persistent system components and services> are initiated from a known state.",
	"DS-A.03.14.15E.c": "<A.03.14.15E.ODP[01]: non-persistent system components and services> are terminated <A.03.14.15E.ODP[02]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.14.16E": "data or capabilities are embedded in <A.03.14.16E.ODP[01]: systems or system components> to determine if CUI has been exfiltrated or improperly removed from the organization.",
	"DS-A.03.14.17E": "<A.03.14.17E.ODP[01]: personnel or roles> are alerted when system-generated <A.03.14.17E.ODP[02]: indicators of compromise> occur.",
	"DS-A.03.14.18E": "<A.03.14.18E.ODP[01]: personnel or roles> are alerted using <A.03.14.18E.ODP[02]: automated mechanisms> when <A.03.14.18E.ODP[03]: activities> indicate inappropriate or unusual activities with security implications.",
	"DS-A.03.14.19E[01]": "a wireless intrusion detection system is employed to identify rogue wireless devices.",
	"DS-A.03.14.19E[02]": "a wireless intrusion detection system is employed to detect attack attempts on the system.",
	"DS-A.03.14.19E[03]": "a wireless intrusion detection system is employed to detect a potential compromise or breach to the system.",
	"DS-A.03.15.01E.a.01": "a security architecture for the system that describes the requirements and approach to be taken for protecting the confidentiality, integrity, and availability of CUI is developed.",
	"DS-A.03.15.01E.a.02": "a security architecture for the system that describes how the security architecture is integrated into and supports the enterprise architecture is developed.",
	"DS-A.03.15.01E.a.03": "a security architecture for the system that describes any assumptions about and dependencies on external systems and services is developed.",
	"DS-A.03.15.01E.b": "the security architecture is reviewed and updated <A.03.15.01E.ODP[01]: frequency> to reflect changes in the enterprise architecture.",
	"DS-A.03.15.01E.c": "planned security architecture changes are reflected in system security plans, concept of operations, criticality analyses, organizational procedures, procurements, and acquisitions.",
	"DS-A.03.15.02E.a": "the security architecture for the system is designed using a defense-in-depth approach.",
	"DS-A.03.15.02E.b": "<A.03.15.02E.ODP[01]: security requirements> are allocated to <A.03.15.02E.ODP[02]: architectural layers and locations>.",
	"DS-A.03.15.02E.c": "the security requirements allocated to the architectural layers and locations are coordinated and mutually reinforcing.",
	"DS-A.03.15.03E": "<A.03.15.03E.ODP[01]: safeguards> that are allocated to <A.03.15.03E.ODP[02]: architectural layers and locations> are obtained from different suppliers.",
	"DS-A.03.16.01E": "<A.03.16.01E.ODP[01]: SELECTED PARAMETER VALUE(S)> is/are employed to <A.03.16.01E.ODP[02]: systems or system components> supporting mission-essential services or functions to increase the trustworthiness in those systems or components.",
	"DS-A.03.17.01E": "agreements and procedures are established with entities involved in the supply chain for the system, system components, or system service for <A.03.17.01E.ODP[01]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.17.02E": "<A.03.17.02E.ODP[01]: systems or system components> are inspected <A.03.17.02E.ODP[02]: SELECTED PARAMETER VALUE(S)> to detect tampering.",
	"DS-A.03.17.03E.a[01]": "an anti-counterfeit policy is developed and implemented.",
	"DS-A.03.17.03E.a[02]": "anti-counterfeit procedures are developed and implemented.",
	"DS-A.03.17.03E.a[03]": "the anti-counterfeit policy and procedures include the means to detect counterfeit components entering the system.",
	"DS-A.03.17.03E.a[04]": "the anti-counterfeit policy and procedures include the means to prevent counterfeit components from entering the system.",
	"DS-A.03.17.03E.b": "counterfeit system components are reported to <A.03.17.03E.ODP[01]: SELECTED PARAMETER VALUE(S)>.",
	"DS-A.03.17.04E[01]": "valid provenance is documented for <A.03.17.04E.ODP[01]: systems, system components, and associated CUI>.",
	"DS-A.03.17.04E[02]": "valid provenance is monitored for <A.03.17.04E.ODP[01]: systems, system components, and associated CUI>.",
	"DS-A.03.17.04E[03]": "valid provenance is maintained for <A.03.17.04E.ODP[01]: systems, system components, and associated CUI>.",
	"DS-A.03.17.05E[01]": "<A.03.17.05E.ODP[01]: safeguards> are employed to ensure the integrity of the system and system components.",
	"DS-A.03.17.05E[02]": "<A.03.17.05E.ODP[02]: analysis method> is conducted to ensure the integrity of the system and system components.",
}

# Assessment methods per active requirement (SP 800-172A [SELECT FROM: ...] lists): data, not controls
method_examine := {
	"03.01.01E": "[SELECT FROM: Access control policy; procedures addressing access enforcement and dual authorization; system design documentation; system configuration settings and associated documentation; list of actions requiring dual authorization; list of privileged commands requiring dual authorization; list of approved authorizations (user privileges); system security plan; other relevant documents or records].",
	"03.01.02E": "[SELECT FROM: Access control policy; procedures addressing the use of external systems; system design documentation; system configuration settings and associated documentation; system connection or processing agreements; account management documents; system audit records; other relevant documents or records].",
	"03.01.04E": "[SELECT FROM: Access control policy; procedures addressing concurrent session control; system design documentation; system configuration settings and associated documentation; security plan; system security plan; other relevant documents or records].",
	"03.01.05E": "[SELECT FROM: Access control policy; procedures addressing remote access to the system; system design documentation; system configuration settings and associated documentation; system audit records; system monitoring records; system security plan; other relevant documents or records].",
	"03.01.06E": "[SELECT FROM: Access control policy; procedures addressing remote access to the system; system security plan; other relevant documents or records].",
	"03.01.07E": "[SELECT FROM: Access control policy; procedures addressing account management; system design documentation; system configuration settings and associated documentation; notifications or alerts of account creation, modification, enabling, disabling, and removal actions; system audit records; system security plan; other relevant documents or records].",
	"03.01.08E": "[SELECT FROM: Access control policy; procedures addressing account management; system design documentation; system configuration settings and associated documentation; system monitoring records; system audit records; audit tracking and monitoring reports; system security plan; other relevant documents or records].",
	"03.01.09E": "[SELECT FROM: Access control policy; procedures addressing access enforcement; system design documentation; system configuration settings and associated documentation; list of subjects and objects (i.e., users and resources) requiring enforcement of attribute-based access control policies; system audit records; system security plan; other relevant documents or records].",
	"03.01.10E": "[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; list of security attributes and associated source and destination objects; system audit records; system security plan; other relevant documents or records].",
	"03.01.11E": "[SELECT FROM: Access control policy; role-based access control policies; procedures addressing access enforcement; system design documentation; system configuration settings and associated documentation; list of roles, users, and associated privileges required to control system access; system audit records; system security plan; other relevant documents or records].",
	"03.01.12E": "[SELECT FROM: Information flow enforcement policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; list of required separation of information flows by information types; list of mechanisms and/or techniques used to logically or physically separate information flows; system audit records; system security plan; other relevant documents or records].",
	"03.01.13E": "[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.01.14E": "[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; list of security policy filters regulating flow control decisions; system audit records; system security plan; other relevant documents or records].",
	"03.01.15E": "[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; list of data type identifiers; system audit records; system security plan; other relevant documents or records].",
	"03.01.16E": "[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.01.17E": "[SELECT FROM: Access control policy; information flow control policies; procedures addressing information flow enforcement; system design documentation; system configuration settings and associated documentation; list of unsanctioned information types and associated information; system audit records; system security plan; other relevant documents or records].",
	"03.02.01E": "[SELECT FROM: System security plan; security literacy and awareness training policy; procedures addressing security literacy and awareness training implementation; security literacy and awareness training curriculum; security literacy and awareness training materials; other relevant documents or records].",
	"03.02.02E": "[SELECT FROM: System security plan; security literacy and awareness training policy; procedures addressing security literacy and awareness training implementation; security awareness training curriculum; security awareness training materials; other relevant documents or records].",
	"03.02.03E": "[SELECT FROM: Security awareness training policy; procedures addressing security literacy and awareness training records; security literacy and awareness training records; security plan; other relevant documents or records].",
	"03.02.04E": "[SELECT FROM: Supply chain risk management policy and procedures; supply chain risk management plan; system and services acquisition policy; anti-counterfeit plan; anti-counterfeit policy and procedures; media disposal policy; media protection policy; incident response policy; training materials addressing counterfeit system components; training records on the detection and prevention of counterfeit components entering the system; system security plan; other relevant documents or records].",
	"03.03.01E": "[SELECT FROM: Audit and accountability policy; system security plan; procedures addressing protection of audit information; system design documentation; system configuration settings and associated documentation; system or media storing backups of system audit records; system audit records; other relevant documents or records].",
	"03.03.02E": "[SELECT FROM: Audit and accountability policy; procedures addressing response to audit processing failures; system design documentation; system security plan; system configuration settings and associated documentation; system audit records; other relevant documents or records].",
	"03.03.03E": "[SELECT FROM: Audit and accountability policy; system security plan; access control policy and procedures; procedures addressing protection of audit information; system design documentation; system configuration settings and associated documentation; access authorizations; system audit records; other relevant documents or records].",
	"03.03.04E": "[SELECT FROM: Audit and accountability policy; system security plan; procedures addressing audit review, analysis, and reporting; system design documentation; system configuration settings and associated documentation; integrated analysis of audit records, vulnerability scanning information, performance data, network monitoring information and associated documentation; other relevant documents or records].",
	"03.04.02E": "[SELECT FROM: Configuration management policy; procedures addressing system component inventory and configuration settings; configuration management plan; system configuration settings and associated documentation; system component inventory; system design documentation; change control records; common secure configuration checklists; alerts or notifications of unauthorized components within the system; system monitoring records; system maintenance records; system audit records; system security plan; other relevant documents or records].",
	"03.04.03E": "[SELECT FROM: Configuration management policy; procedures addressing system component inventory; configuration management plan; system security plan; system design documentation; system component inventory; change control records; system maintenance records; system audit records; other relevant documents or records].",
	"03.04.04E": "[SELECT FROM: Configuration management policy; procedures addressing the baseline configuration of the system; configuration management plan; system design documentation; system architecture and configuration documentation; system configuration settings and associated documentation; system component inventory; configuration change control records; system security plan; other relevant documents or records].",
	"03.04.05E": "[SELECT FROM: Configuration management policy; procedures addressing access restrictions for changes to the system; configuration management plan; system design documentation; system architecture and configuration documentation; system configuration settings and associated documentation; change control records; system audit records; system component inventory; system information types; system security plan; other relevant documents or records].",
	"03.04.06E": "[SELECT FROM: Configuration management policy; procedures addressing the baseline configuration of the system; configuration management plan; system architecture and configuration documentation; system configuration settings and associated documentation; copies of previous baseline configuration versions; system security plan; other relevant documents or records].",
	"03.04.07E": "[SELECT FROM: Configuration management policy; configuration management plan; procedures addressing system configuration change control; system architecture and configuration documentation; system design documentation; test records; system configuration settings and associated documentation; validation records; change control records; system audit records; system security plan; other relevant documents or records].",
	"03.04.08E": "[SELECT FROM: Configuration management policy; procedures addressing system component inventory; configuration management plan; system design documentation; system security plan; system component inventory; system configuration settings and associated documentation; change control records; system security plan; other relevant documents or records].",
	"03.05.01E": "[SELECT FROM: Identification and authentication policy; system security plan; procedures addressing device identification and authentication; system design documentation; configuration settings and associated documentation; list of devices requiring unique identification and authentication; device connection reports; other relevant documents or records].",
	"03.05.02E": "[SELECT FROM: Identification and authentication policy; procedures addressing identifier management; system security plan; system design documentation; mechanisms providing dynamic binding of identifiers and authenticators; system configuration settings and associated documentation; system audit records; other relevant documents or records].",
	"03.05.03E": "[SELECT FROM: Identification and authentication policy; system security plan; procedures addressing device identification and authentication; procedures addressing device configuration management; system design documentation; system configuration settings and associated documentation; configuration management records; change control records; system audit records; other relevant documents or records].",
	"03.05.04E": "[SELECT FROM: Identification and authentication policy; system security plan; procedures addressing authenticator management; system design documentation; system configuration settings and associated documentation; logical access scripts; application code reviews for detecting unencrypted static authenticators; other relevant documents or records].",
	"03.05.05E": "[SELECT FROM: Identification and authentication policy; procedures addressing authenticator management; system security plan; system design documentation; system configuration settings and associated documentation; system audit records; other relevant documents or records].",
	"03.05.06E": "[SELECT FROM: Identification and authentication policy; procedures addressing identity proofing; system security plan; other relevant documents or records].",
	"03.05.07E": "[SELECT FROM: Identification and authentication policy; procedures addressing user and device identification and authentication; system security plan; system design documentation; system configuration settings and associated documentation; other relevant documents or records].",
	"03.06.01E": "[SELECT FROM: Incident response policy; contingency planning policy; procedures addressing incident handling; procedures addressing the security operations center operations; mechanisms supporting dynamic response capabilities; system security plan; contingency plan; incident response plan; other relevant documents or records].",
	"03.06.02E": "[SELECT FROM: Incident response policy; procedures addressing incident handling; procedures addressing incident response planning; incident response plan; system security plan; other relevant documents or records].",
	"03.06.03E": "[SELECT FROM: Incident response policy; procedures addressing system monitoring tools and techniques; incident response plan; system monitoring logs or records; system monitoring tools and techniques documentation; system configuration settings and associated documentation; system security plan; system component inventory; network diagram; system protocols documentation; list of acceptable thresholds for false positives and false negatives; other relevant documents or records].",
	"03.06.04E": "[SELECT FROM: Incident response policy; procedures addressing incident monitoring; incident response records and documentation; system security plan; incident response plan; other relevant documents or records].",
	"03.07.01E": "[SELECT FROM: Maintenance policy; procedures addressing system maintenance tools; system maintenance tools and associated documentation; list of personnel authorized to use maintenance tools; maintenance tool usage records; maintenance records; system security plan; other relevant documents or records].",
	"03.08.01E": "[SELECT FROM: System media protection policy; procedures addressing media sanitization and disposal; dual authorization policy and procedures; list of system media requiring dual authorization for sanitization; authorization records; media sanitization records; audit records; system security plan; other relevant documents or records].",
	"03.08.02E": "[SELECT FROM: Contingency planning policy; procedures addressing system backup; contingency plan; system design documentation; system configuration settings and associated documentation; system-generated list of dual authorization credentials or rules; logs or records of the deletion or destruction of backup information; system security plan; other relevant documents or records]",
	"03.08.03E": "[SELECT FROM: Contingency planning policy; procedures addressing system backup; contingency plan; system backup test results; contingency plan test documentation; contingency plan test results; system security plan; other relevant documents or records].",
	"03.08.04E": "[SELECT FROM: Contingency planning policy; procedures addressing system backup; contingency plan; system backup test results; contingency plan test results; contingency plan test documentation; redundant secondary system for system backups; locations of redundant secondary backup systems; system security plan; other relevant documents or records].",
	"03.09.03E": "[SELECT FROM: Personnel security policy; personnel security procedures; procedures addressing access agreements for systems processing, storing, or transmitting CUI; access control policy; access control procedures; access agreements (including non-disclosure agreements, acceptable use agreements, rules of behavior, and conflict-of-interest agreements); documentation of access agreement reviews, updates, and re-signing; system security plan; other relevant documents or records].",
	"03.09.04E": "[SELECT FROM: Personnel security policy; access control policy, procedures addressing personnel screening; records of screened personnel; screening criteria; records of access authorizations; system security plan; other relevant documents or records].",
	"03.10.01E": "[SELECT FROM: Physical and environmental protection policy; procedures addressing physical access monitoring; physical access monitoring records; physical access log reviews; physical access logs or records; system security plan; other relevant documents or records].",
	"03.10.02E": "[SELECT FROM: Physical and environmental protection policy; procedures addressing the delivery and removal of system components from the facility; facility housing the system; records of items entering and exiting the facility; system security plan; other relevant documents or records].",
	"03.11.01E": "[SELECT FROM: Information security program plan; threat awareness program policy; threat awareness program procedures; risk assessment results relevant to threat awareness; documentation about the cross-organization information-sharing capability; other relevant documents or records].",
	"03.11.02E": "[SELECT FROM: Risk assessment policy; assessment reports; audit records and/or event logs; threat-hunting capability; system security plan; other relevant documents or records].",
	"03.11.03E": "[SELECT FROM: Risk assessment policy; security planning policy and procedures; procedures addressing organizational assessments of risk; risk assessment; risk assessment results; risk assessment reviews; risk assessment updates; risk reports; system security plan; other relevant documents or records].",
	"03.11.08E": "[SELECT FROM: Risk assessment policy; security planning policy and procedures; procedures addressing organizational assessments of risk; risk assessment; risk assessment results; risk assessment reviews; risk assessment updates; risk reports; system security plan; other relevant documents or records].",
	"03.11.09E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing system monitoring; system design documentation; system monitoring tools and techniques documentation; system configuration settings and associated documentation; system monitoring logs or records; system audit records; system security plan; other relevant documents or records].",
	"03.11.10E": "[SELECT FROM: Risk assessment policy; assessment reports; criticality analysis and/or finalized criticality for each component and/or subcomponent; audit records and/or event logs; analysis reports; system security plan; other relevant documents or records].",
	"03.11.11E": "[SELECT FROM: Procedures addressing vulnerability scanning; assessment report; penetration test results; vulnerability scanning results; risk assessment report; records of corrective actions taken on discoverable information; incident response records; audit records; system security plan; other relevant documents or records].",
	"03.11.12E": "[SELECT FROM: Information security program plan; threat awareness program policy; threat awareness program procedures; risk assessment results related to threat awareness; documentation about the cross-organization information-sharing capability; other relevant documents or records].",
	"03.12.01E": "[SELECT FROM: Assessment and monitoring policy; procedures addressing penetration testing; assessment plan; system security plan; penetration test rules of engagement; penetration test report; assessment report; assessment evidence; other relevant documents or records].",
	"03.12.02E": "[SELECT FROM: Assessment and monitoring policy; procedures addressing assessments; previous assessment plan; previous assessment report; plan of action and milestones; system security plan; other relevant documents or records].",
	"03.12.03E": "[SELECT FROM: Assessment and monitoring policy; organizational continuous monitoring strategy; system-level continuous monitoring strategy; procedures addressing continuous monitoring of system; assessment report; plan of action and milestones; system monitoring records; impact analyses; status reports; system security plan; other relevant documents or records].",
	"03.12.04E": "[SELECT FROM: Assessment and monitoring policy; access control policy; procedures addressing system connections; system and communications protection policy; system design documentation; system audit records; list of components or classes of components authorized as internal system connections; system security plan; system configuration settings and associated documentation; assessment report; other relevant documents or records].",
	"03.13.01E": "[SELECT FROM: System and communications protection policy; system design documentation; system configuration settings and associated documentation; list of technologies deployed in the system; acquisition documentation; acquisition contracts for system components or services; system security plan; other relevant documents or records].",
	"03.13.02E": "[SELECT FROM: System and communications protection policy; procedures addressing concealment and misdirection techniques for the system; system design documentation; system configuration settings and associated documentation; system architecture; list of techniques to be used to introduce randomness into organizational operations and assets; system audit records; system security plan; other relevant documents or records].",
	"03.13.03E": "[SELECT FROM: System and communications protection policy; procedures addressing concealment and misdirection techniques for the system; system design documentation; system configuration settings and associated documentation; system architecture; list of concealment and misdirection techniques to be used for organizational systems; system audit records; system security plan; other relevant documents or records].",
	"03.13.04E": "[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system design documentation; system hardware and software; enterprise architecture documentation; system architecture; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.13.05E": "[SELECT FROM: System and communications protection policy; configuration management policy and procedures; procedures addressing concealment and misdirection techniques for the system; list of processing and/or storage locations to be changed at organizational time intervals; change control records; configuration management records; system audit records; system security plan; other relevant documents or records].",
	"03.13.06E": "[SELECT FROM: System and communications protection policy; procedures addressing platform-independent applications; system design documentation; system configuration settings and associated documentation; list of platform-independent applications; system audit records; system security plan; other relevant documents or records].",
	"03.13.07E": "[SELECT FROM: System and communications protection policy; configuration management policy and procedures; system design documentation; system configuration settings and associated documentation; system architecture; list of operating systems and applications deployed using virtualization techniques; change control records; configuration management records; system audit records; system security plan; other relevant documents or records].",
	"03.13.08E": "[SELECT FROM: System and communications protection policy; procedures addressing the use of decoys; system design documentation; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.13.09E": "[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system design documentation; system hardware and software; system architecture; system configuration settings and associated documentation; list of security tools and support components to be isolated from other internal system components; system audit records; system security plan; other relevant documents or records].",
	"03.13.10E": "[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system design documentation; system hardware and software; system architecture; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.13.11E": "[SELECT FROM: System and communications protection policy; procedures addressing use of thin nodes; system design documentation; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.13.12E": "[SELECT FROM: System and communications protection policy; procedures addressing denial-of-service protection; list of denial-of-service attacks requiring employment of security safeguards to protect against or limit effects of such attacks; system design documentation; list of security safeguards protecting against or limiting the effects of denial-of-service attacks; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.13.13E": "[SELECT FROM: System and communications protection policy; access control policy and procedures; procedures addressing port and input/output device access; system design documentation; system architecture; system configuration settings and associated documentation; systems or system components; list of connection ports or input/output devices to be physically disabled or removed on systems or system components; system security plan; other relevant documents or records].",
	"03.13.14E": "[SELECT FROM: System and communications protection policy; procedures addressing detonation chambers; system configuration settings and associated documentation; system audit records; system design documentation; system security plan; other relevant documents or records].",
	"03.13.15E": "[SELECT FROM: System and communications protection policy; procedures addressing boundary protection; system design documentation; system hardware and software; system architecture; system configuration settings and associated documentation; criticality analysis; system audit records; system security plan; other relevant documents or records].",
	"03.13.16E": "[SELECT FROM: System and communications protection policy; procedures addressing system partitioning; system design documentation; system configuration settings and associated documentation; system architecture; list of system physical domains (or environments); system facility diagrams; system network diagrams; system security plan; other relevant documents or records].",
	"03.14.01E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing software, firmware, and information integrity; system configuration settings and associated documentation; integrity verification tools and associated documentation; records generated or triggered by system design documentation; integrity verification tools regarding unauthorized software, firmware, and information changes; system audit records; system security plan; other relevant documents or records].",
	"03.14.04E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; system design documentation; procedures addressing non-persistence for system components; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.14.05E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; system security plan; procedures addressing non-persistence for system components; system design documentation; system configuration settings and associated documentation; system audit records; other relevant documents or records].",
	"03.14.08E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing software, firmware, and information integrity testing; system design documentation; system configuration settings and associated documentation; system security plan; integrity verification tools and associated documentation; records of integrity scans; other relevant documents or records].",
	"03.14.09E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing software, firmware, and information integrity; system design documentation; system configuration settings and associated documentation; system audit records; system security plan; cryptographic mechanisms and associated documentation; records of detected unauthorized changes to software, firmware, and information; other relevant documents or records].",
	"03.14.10E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing software, firmware, and information integrity; system design documentation; system configuration settings and associated documentation; system security plan; integrity verification tools and associated documentation; records of integrity verification scans; system audit records; other relevant documents or records].",
	"03.14.11E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing software, firmware, and information integrity; procedures addressing incident response; system design documentation; system configuration settings and associated documentation; incident response records; audit records; system security plan; other relevant documents or records].",
	"03.14.12E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; access control policy and procedures; separation of duties policy and procedures; procedures addressing information input validation; documentation for automated tools and applications to verify the validity of information; list of information inputs requiring validity checks; system design documentation; system configuration settings and associated documentation; system audit records; system security plan; other relevant documents or records].",
	"03.14.13E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing system error handling; system design documentation; system configuration settings and associated documentation; documentation providing the structure and content of error messages; system audit records; system security plan; other relevant documents or records].",
	"03.14.14E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing memory protection for the system; system design documentation; system configuration settings and associated documentation; list of security safeguards protecting system memory from unauthorized code execution; system audit records; system security plan; other relevant documents or records].",
	"03.14.15E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; system design documentation; procedures addressing non-persistence for system components; system security plan; system configuration settings and associated documentation; system audit records; other relevant documents or records].",
	"03.14.16E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing software and information integrity; system design documentation; system configuration settings and associated documentation; policy and procedures addressing the systems security engineering technique of deception; system security plan; other relevant documents or records].",
	"03.14.17E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; system security plan; system audit records; procedures addressing system monitoring tools and techniques; system monitoring tools and techniques documentation; list of personnel selected to receive alerts; system configuration settings and associated documentation; documentation of alerts generated based on compromise indicators; other relevant documents or records].",
	"03.14.18E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; system security plan; list of inappropriate or unusual activities with security implications that trigger alerts; suspicious activity reports; system monitoring tools and techniques documentation; system design documentation; procedures addressing system monitoring tools and techniques; alerts provided to security personnel; system configuration settings and associated documentation; system monitoring logs or records; system audit records; other relevant documents or records].",
	"03.14.19E": "[SELECT FROM: System and information integrity policy; system and information integrity procedures; procedures addressing system monitoring tools and techniques; system design documentation; system monitoring tools and techniques documentation; system configuration settings and associated documentation; system protocols; system audit records; system security plan; other relevant documents or records].",
	"03.15.01E": "[SELECT FROM: Security planning policy; procedures addressing information security architecture development; procedures addressing information security architecture reviews and updates; enterprise architecture documentation; information security architecture documentation; system security plan; security CONOPS for the system; records of information security architecture reviews and updates; other relevant documents or records].",
	"03.15.02E": "[SELECT FROM: Security planning policy; procedures addressing information security architecture development; enterprise architecture documentation; information security architecture documentation; system security plan; security CONOPS for the system; other relevant documents or records].",
	"03.15.03E": "[SELECT FROM: Security planning policy; procedures addressing information security architecture development; enterprise architecture documentation; information security architecture documentation; system security plan; security CONOPS for the system; IT acquisitions policy; other relevant documents or records].",
	"03.16.01E": "[SELECT FROM: System and services acquisition policy; procedures addressing design modification, augmentation, or reconfiguration of systems or system components; documented evidence of design modification, augmentation, or reconfiguration; system security plan; supply chain risk management plan; other relevant documents or records].",
	"03.17.01E": "[SELECT FROM: Supply chain risk management policy and procedures; supply chain risk management plan; system and services acquisition policy; acquisition contracts for the system, system component, or system service; procedures addressing supply chain protection; acquisition documentation; service-level agreements; system security plan; inter-organizational agreements and procedures; other relevant documents or records].",
	"03.17.02E": "[SELECT FROM: Supply chain risk management policy and procedures; supply chain risk management plan; system and services acquisition policy; records of random inspections; inspection reports or results; assessment reports or results; acquisition documentation; acquisition contracts for the system, system component, or system service; inter-organizational agreements and procedures; system security plan; service-level agreements; other relevant documents or records].",
	"03.17.03E": "[SELECT FROM: Supply chain risk management policy and procedures; supply chain risk management plan; system and services acquisition policy; anti-counterfeit plan; anti-counterfeit policy and procedures; media disposal policy; media protection policy; incident response policy; reports notifying developers, manufacturers, vendors, contractors, and/or external reporting organizations of counterfeit system components; acquisition documentation; service-level agreements; acquisition contracts for the system, system component, or system service; inter-organizational agreements and procedures; records of reported counterfeit system components; system security plan; other relevant documents or records].",
	"03.17.04E": "[SELECT FROM: Supply chain risk management policy; supply chain risk management procedures; supply chain risk management plan; documentation of critical systems, critical system components, and associated data; documentation showing the history of ownership, custody, and location of and changes to critical systems or critical system components; system architecture; inter-organizational agreements and procedures; contracts; system security plan; other relevant documents or records].",
	"03.17.05E": "[SELECT FROM: Supply chain risk management policy and procedures; supply chain risk management plan; system and services acquisition policy; procedures addressing supply chain protection; bill of materials for critical systems or system components; acquisition documentation; software identification tags; manufacturer declarations of platform attributes (e.g., serial numbers, hardware component inventory) and measurements (e.g., firmware hashes) that are tightly bound to the hardware itself; system security plan; other relevant documents or records].",
}

method_interview := {
	"03.01.01E": "[SELECT FROM: Personnel with access enforcement responsibilities; system/network administrators; system developers; personnel with information security responsibilities].",
	"03.01.02E": "[SELECT FROM: Personnel with responsibilities for restricting or prohibiting the use of non-organizationally owned systems, system components, or devices; system/network administrators; personnel with information security responsibilities].",
	"03.01.04E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers].",
	"03.01.05E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers].",
	"03.01.06E": "[SELECT FROM: Personnel with responsibilities for implementing or monitoring remote access to the system; system users with knowledge of information about remote access mechanisms; personnel with information security responsibilities].",
	"03.01.07E": "[SELECT FROM: Personnel with account management responsibilities; system/network administrators; personnel with information security responsibilities].",
	"03.01.08E": "[SELECT FROM: Personnel with account management responsibilities; system/network administrators; personnel with information security responsibilities].",
	"03.01.09E": "[SELECT FROM: Personnel with access enforcement responsibilities; system/network administrators; personnel with information security responsibilities].",
	"03.01.10E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers].",
	"03.01.11E": "[SELECT FROM: Organizational personnel with access enforcement responsibilities; system/network administrators; organizational personnel with information security responsibilities; system developers].",
	"03.01.12E": "[SELECT FROM: Organizational personnel with information flow enforcement responsibilities; system/network administrators; organizational personnel with information security responsibilities; system developers].",
	"03.01.13E": "[SELECT FROM: System/network administrators; organizational personnel with information security responsibilities; system developers].",
	"03.01.14E": "[SELECT FROM: System/network administrators; organizational personnel with information security responsibilities; system developers].",
	"03.01.15E": "[SELECT FROM: System/network administrators; organizational personnel with information security responsibilities; system developers].",
	"03.01.16E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers].",
	"03.01.17E": "[SELECT FROM: Organizational personnel with information security responsibilities; system developers].",
	"03.02.01E": "[SELECT FROM: Personnel who receive security literacy and awareness training; personnel with responsibilities for security literacy and awareness training; personnel with information security responsibilities].",
	"03.02.02E": "[SELECT FROM: Personnel who receive security literacy and awareness training; personnel with responsibilities for security awareness training; personnel with information security responsibilities].",
	"03.02.03E": "[SELECT FROM: Personnel with security and awareness training record retention responsibilities].",
	"03.02.04E": "[SELECT FROM: Personnel with information security responsibilities; personnel with supply chain risk management responsibilities; personnel with contract management responsibilities; personnel with personnel with responsibilities for anti-counterfeit policies, procedures, and training].",
	"03.03.01E": "[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.03.02E": "[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.03.03E": "[SELECT FROM: Personnel with audit and accountability responsibilities; personnel with information security responsibilities; system/network administrators].",
	"03.03.04E": "[SELECT FROM: Personnel with audit review, analysis, and reporting responsibilities; personnel with information security responsibilities].",
	"03.04.02E": "[SELECT FROM: Personnel with component inventory and security configuration management responsibilities; personnel with responsibilities for managing automated mechanisms implementing unauthorized system component detection; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.04.03E": "[SELECT FROM: Personnel with component inventory management responsibilities; personnel with information security responsibilities; system developers; system/network administrators].",
	"03.04.04E": "[SELECT FROM: Personnel with configuration management responsibilities; personnel with information security responsibilities; system/network administrators].",
	"03.04.05E": "[SELECT FROM: Personnel with dual authorization enforcement responsibilities for implementing system changes; personnel with information security responsibilities; system/network administrators].",
	"03.04.06E": "[SELECT FROM: Personnel with configuration management responsibilities; personnel with information security responsibilities; system/network administrators].",
	"03.04.07E": "[SELECT FROM: Personnel with configuration change control responsibilities; personnel with information security responsibilities; members of change control board or similar; system/network administrators; system developers].",
	"03.04.08E": "[SELECT FROM: Organizational personnel with component inventory management responsibilities; organizational personnel with security responsibilities].",
	"03.05.01E": "[SELECT FROM: Personnel with operational responsibilities for device identification and authentication; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.05.02E": "[SELECT FROM: Personnel with identification and authentication management responsibilities; personnel with information security responsibilities; system/network administrators].",
	"03.05.03E": "[SELECT FROM: Personnel with operational responsibilities for device identification and authentication; personnel with information security responsibilities; system/network administrators].",
	"03.05.04E": "[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.05.05E": "[SELECT FROM: Personnel with authenticator management responsibilities; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.05.06E": "[SELECT FROM: Personnel with system operations responsibilities; personnel with information security responsibilities; system/network administrators; system developers; personnel with identification and authentication responsibilities].",
	"03.05.07E": "[SELECT FROM: Organizational personnel with system operations responsibilities; organizational personnel with information security responsibilities; system/network administrators; organizational personnel with account management responsibilities; system developers].",
	"03.06.01E": "[SELECT FROM: Personnel with incident handling responsibilities; personnel with information security responsibilities; security operations center personnel; personnel with contingency planning responsibilities].",
	"03.06.02E": "[SELECT FROM: Personnel with incident handling responsibilities; personnel with information security responsibilities; members of the integrated incident response team].",
	"03.06.03E": "[SELECT FROM: Personnel with information security responsibilities; system/network administrators].",
	"03.06.04E": "[SELECT FROM: Personnel with incident monitoring responsibilities; personnel with information security responsibilities].",
	"03.07.01E": "[SELECT FROM: Personnel with system maintenance responsibilities; personnel with information security responsibilities].",
	"03.08.01E": "[SELECT FROM: Personnel with system media sanitization responsibilities; personnel with information security responsibilities; system/network administrators].",
	"03.08.02E": "[SELECT FROM: Personnel with system backup responsibilities; personnel with information security responsibilities].",
	"03.08.03E": "[SELECT FROM: Personnel with system backup responsibilities; personnel with information security responsibilities].",
	"03.08.04E": "[SELECT FROM: Organizational personnel with contingency planning, recovery, and/or reconstitution responsibilities; organizational personnel with information security responsibilities].",
	"03.09.03E": "[SELECT FROM: Personnel with personnel security responsibilities; personnel who have signed and/or resigned access agreements; personnel with information security responsibilities].",
	"03.09.04E": "[SELECT FROM: Personnel with personnel security responsibilities; personnel with information security responsibilities].",
	"03.10.01E": "[SELECT FROM: Personnel with physical access monitoring responsibilities; personnel with incident response responsibilities; personnel with information security responsibilities].",
	"03.10.02E": "[SELECT FROM: Personnel with responsibilities for controlling system components entering and exiting the facility; personnel with information security responsibilities].",
	"03.11.01E": "[SELECT FROM: Personnel with information security program planning and plan implementation responsibilities; personnel responsible for the threat awareness program; personnel responsible for the cross-organization information-sharing capability; personnel with information security responsibilities; external personnel with whom threat awareness information is shared by the organization].",
	"03.11.02E": "[SELECT FROM: Personnel with threat-hunting responsibilities; system/network administrators; personnel with information security responsibilities].",
	"03.11.03E": "[SELECT FROM: Personnel with risk assessment responsibilities; personnel with information security responsibilities].",
	"03.11.08E": "[SELECT FROM: Personnel with risk assessment responsibilities; personnel with information security responsibilities].",
	"03.11.09E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers; personnel installing, configuring, and/or maintaining the system; personnel responsible for monitoring system hosts].",
	"03.11.10E": "[SELECT FROM: Personnel with assessment and auditing responsibilities; personnel with criticality analysis responsibilities; system/network administrators; personnel with information security responsibilities].",
	"03.11.11E": "[SELECT FROM: Personnel with vulnerability scanning and/or penetration testing responsibilities; personnel with vulnerability scan analysis responsibilities; personnel responsible for risk response; personnel responsible for incident management and response; personnel with information security responsibilities].",
	"03.11.12E": "[SELECT FROM: Personnel with information security program planning and plan implementation responsibilities; personnel responsible for the threat awareness program; personnel responsible for the cross-organization information-sharing capability; personnel with information security responsibilities; external personnel with whom threat awareness information is shared by the organization].",
	"03.12.01E": "[SELECT FROM: Personnel with assessment responsibilities; personnel with information security responsibilities; system/network administrators].",
	"03.12.02E": "[SELECT FROM: Personnel with assessment responsibilities; personnel with information security responsibilities].",
	"03.12.03E": "[SELECT FROM: Personnel with continuous monitoring responsibilities; personnel with information security responsibilities].",
	"03.12.04E": "[SELECT FROM: Personnel with responsibilities for developing, implementing, or authorizing internal system connections; personnel with information security and responsibilities].",
	"03.13.01E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with system acquisition, development, and implementation responsibilities].",
	"03.13.02E": "[SELECT FROM: System/network administrators; personnel with the responsibility to implement concealment and misdirection techniques for systems; personnel with information security responsibilities].",
	"03.13.03E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with the responsibility to implement concealment and misdirection techniques for systems].",
	"03.13.04E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with boundary protection responsibilities].",
	"03.13.05E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with the responsibility to change processing and/or storage locations].",
	"03.13.06E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers].",
	"03.13.07E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with responsibilities for implementing approved virtualization techniques to the system].",
	"03.13.08E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers].",
	"03.13.09E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with boundary protection responsibilities].",
	"03.13.10E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; system developers; personnel with boundary protection responsibilities].",
	"03.13.11E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities].",
	"03.13.12E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel with incident response responsibilities; system developers].",
	"03.13.13E": "[SELECT FROM: System/network administrators; personnel with information security responsibilities; personnel installing, configuring, and/or maintaining the system].",
	"03.13.14E": "[SELECT FROM: system/network administrators; personnel with information security responsibilities; personnel installing, configuring, and/or maintaining the system].",
	"03.13.15E": "[SELECT FROM: System/network administrators; organizational personnel with information security responsibilities; system developer; organizational personnel with boundary protection responsibilities].",
	"03.13.16E": "[SELECT FROM: System/network administrators; organizational personnel with information security responsibilities; organizational personnel installing, configuring, and/or maintaining the system; system developers/integrators].",
	"03.14.01E": "[SELECT FROM: Personnel responsible for software, firmware, and/or information integrity; personnel with information security responsibilities; system/network administrators].",
	"03.14.04E": "[SELECT FROM: Personnel responsible for obtaining component and service refreshes from trusted sources; personnel with information security responsibilities].",
	"03.14.05E": "[SELECT FROM: Personnel responsible for ensuring that information is and remains non-persistent; personnel with information security responsibilities].",
	"03.14.08E": "[SELECT FROM: Personnel responsible for software, firmware, and/or information integrity; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.14.09E": "[SELECT FROM: Personnel responsible for software, firmware, and/or information integrity; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.14.10E": "[SELECT FROM: Personnel responsible for software, firmware, and/or information integrity; personnel with information security responsibilities; system/network administrators; system developer].",
	"03.14.11E": "[SELECT FROM: Personnel responsible for software, firmware, and/or information integrity; personnel with information security responsibilities; personnel with incident response responsibilities].",
	"03.14.12E": "[SELECT FROM: Personnel responsible for information input validation; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.14.13E": "[SELECT FROM: Personnel responsible for information input validation; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.14.14E": "[SELECT FROM: Personnel responsible for memory protection; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.14.15E": "[SELECT FROM: Personnel responsible for non-persistence; personnel with information security responsibilities; system/network administrators; system developers].",
	"03.14.16E": "[SELECT FROM: Personnel responsible for detecting tainted data; personnel with systems security engineering responsibilities; personnel with information security responsibilities].",
	"03.14.17E": "[SELECT FROM: Personnel with information security responsibilities; system developers; personnel installing, configuring, and/or maintaining the system; personnel responsible for monitoring the system; personnel on the system alert notification list; personnel responsible for the intrusion detection system; system/network administrators].",
	"03.14.18E": "[SELECT FROM: Personnel with information security responsibilities; system developers; personnel installing, configuring, and/or maintaining the system; personnel responsible for monitoring the system; personnel responsible for the intrusion detection system; system/network administrators].",
	"03.14.19E": "[SELECT FROM: System/network administrators; organizational personnel with information security responsibilities; organizational personnel installing, configuring, and/or maintaining the system; organizational personnel responsible for monitoring the system; organizational personnel responsible for the intrusion detection system].",
	"03.15.01E": "[SELECT FROM: Personnel with security planning and plan implementation responsibilities; personnel with information security responsibilities; personnel with information security architecture development responsibilities].",
	"03.15.02E": "[SELECT FROM: Personnel with information security responsibilities; personnel with information security architecture development responsibilities; personnel with security planning and plan implementation responsibilities].",
	"03.15.03E": "[SELECT FROM: Personnel with acquisition responsibilities personnel with information security responsibilities; personnel with security planning and plan implementation responsibilities; personnel with information security architecture development responsibilities].",
	"03.16.01E": "[SELECT FROM: Personnel with system and service acquisition responsibilities; personnel with information security responsibilities; personnel with security architecture responsibilities; personnel with configuration management responsibilities].",
	"03.17.01E": "[SELECT FROM: Personnel with system and service acquisition responsibilities; personnel with information security responsibilities; personnel with supply chain risk management responsibilities].",
	"03.17.02E": "[SELECT FROM: Personnel with system and services acquisition responsibilities; personnel with information security responsibilities; personnel with supply chain risk management responsibilities].",
	"03.17.03E": "[SELECT FROM: Personnel with system and service acquisition responsibilities; personnel with information security responsibilities; personnel with supply chain risk management responsibilities; personnel with responsibilities for anti-counterfeit policies, procedures, and reporting].",
	"03.17.04E": "[SELECT FROM: Organizational personnel with acquisition responsibilities; organizational personnel with information security responsibilities; organizational personnel with supply chain risk management responsibilities].",
	"03.17.05E": "[[SELECT FROM: Organizational personnel with system and services acquisition responsibilities; organizational personnel with information security responsibilities; organizational personnel with supply chain risk management responsibilities].",
}

method_test := {
	"03.01.01E": "[SELECT FROM: Dual authorization mechanisms implementing access control policy].",
	"03.01.02E": "[SELECT FROM: Mechanisms implementing restrictions on the use of non-organizationally owned systems, components, or devices].",
	"03.01.04E": "[SELECT FROM: Mechanisms implementing access control policy for concurrent session control].",
	"03.01.05E": "[SELECT FROM: Automated mechanisms monitoring and controlling remote access methods].",
	"03.01.07E": "[SELECT FROM: Automated mechanisms implementing account management functions].",
	"03.01.08E": "[SELECT FROM: Mechanisms implementing account management functions].",
	"03.01.09E": "[SELECT FROM: Mechanisms implementing access enforcement functions].",
	"03.01.10E": "[SELECT FROM: Mechanisms implementing information flow enforcement policy].",
	"03.01.11E": "[SELECT FROM: Mechanisms implementing role-based access control policy].",
	"03.01.12E": "[SELECT FROM: Mechanisms implementing information flow enforcement functions].",
	"03.01.13E": "[SELECT FROM: Mechanisms implementing information flow enforcement policy].",
	"03.01.14E": "[SELECT FROM: Mechanisms implementing information flow enforcement policy; security policy filters].",
	"03.01.15E": "[SELECT FROM: Mechanisms implementing information flow enforcement policy].",
	"03.01.16E": "[SELECT FROM: Mechanisms implementing information flow enforcement policy].",
	"03.01.17E": "[SELECT FROM: Mechanisms implementing information flow enforcement policy].",
	"03.02.02E": "[SELECT FROM: Mechanisms implementing cyber-attack simulations in practical exercises].",
	"03.02.03E": "[SELECT FROM: Mechanisms supporting the management of security literacy and awareness training records].",
	"03.02.04E": "[SELECT FROM: Processes for anti-counterfeit training].",
	"03.03.01E": "[SELECT FROM: Mechanisms implementing the backing up of audit records].",
	"03.03.03E": "[SELECT FROM: Mechanisms implementing the enforcement of dual authorization].",
	"03.03.04E": "[SELECT FROM: Mechanisms implementing the capability to integrate analysis of audit records with analysis of data or information sources].",
	"03.04.02E": "[SELECT FROM: Processes for the detection of unauthorized or misconfigured system components; automated processes for taking action when unauthorized or misconfigured system components are detected; automated mechanisms supporting and/or implementing the detection of unauthorized or misconfigured system components; automated mechanisms supporting and/or implementing actions taken when unauthorized or misconfigured system components are detected].",
	"03.04.03E": "[SELECT FROM: Processes for maintaining the system component inventory; automated mechanisms supporting and/or implementing the system component inventory].",
	"03.04.04E": "[SELECT FROM: Processes for managing baseline configurations; automated mechanisms implementing baseline configuration maintenance].",
	"03.04.05E": "[SELECT FROM: Processes for managing access restrictions to change; mechanisms implementing dual authorization enforcement].",
	"03.04.06E": "[SELECT FROM: Processes for managing baseline configurations].",
	"03.04.07E": "[SELECT FROM: Processes for configuration change control; mechanisms supporting and/or implementing, testing, validating, and documenting system changes].",
	"03.04.08E": "[SELECT FROM: Organizational processes for managing the system component inventory; mechanisms supporting and/or implementing system component inventory].",
	"03.05.01E": "[SELECT FROM: Mechanisms supporting and/or implementing device authentication capabilities; cryptographically based bidirectional authentication mechanisms].",
	"03.05.02E": "[SELECT FROM: Mechanisms supporting and/or implementing account management capabilities; mechanisms supporting and/or implementing identification and authentication management capabilities for the system].",
	"03.05.03E": "[SELECT FROM: Mechanisms supporting and/or implementing device identification and authentication capabilities; mechanisms supporting and/or implementing configuration management; cryptographic mechanisms supporting device attestation].",
	"03.05.04E": "[SELECT FROM: Mechanisms supporting and/or implementing authenticator management capabilities; mechanisms implementing authentication in applications].",
	"03.05.05E": "[SELECT FROM: Mechanisms supporting and/or implementing authenticator management capabilities].",
	"03.05.06E": "[SELECT FROM: Mechanisms supporting and/or implementing identification and authentication capabilities].",
	"03.05.07E": "[SELECT FROM: Mechanisms supporting and/or implementing identification and authentication capabilities and access rights].",
	"03.06.01E": "[SELECT FROM: Mechanisms that support and/or implement the security operations center capability; mechanisms that support and/or implement the incident handling process].",
	"03.06.03E": "[SELECT FROM: Processes for detecting anomalous behavior].",
	"03.06.04E": "[SELECT FROM: Incident monitoring capability for the organization; automated mechanisms supporting and/or implementing the tracking and documenting of system security incidents].",
	"03.07.01E": "[SELECT FROM: Processes for inspecting maintenance tools; processes for maintenance tool updates; mechanisms supporting and/or implementing the inspection of maintenance tools; mechanisms supporting and/or implementing maintenance tool updates].",
	"03.08.01E": "[SELECT FROM: Processes requiring dual authorization for media sanitization; mechanisms supporting and/or implementing media sanitization; mechanisms supporting and/or implementing dual authorization].",
	"03.08.02E": "[SELECT FROM: Mechanisms supporting and/or implementing dual authorization; mechanisms supporting and/or implementing the deletion and/or destruction of backup information].",
	"03.08.03E": "[SELECT FROM: Processes for conducting system backups; mechanisms supporting and/or implementing system backups].",
	"03.08.04E": "[SELECT FROM: Organizational processes implementing system recovery and reconstitution operations; mechanisms supporting and/or implementing system recovery and reconstitution operations].",
	"03.09.03E": "[SELECT FROM: Processes for reviewing, updating, and re-signing access agreements; mechanisms supporting reviewing, updating, and re-signing of access agreements].",
	"03.09.04E": "[SELECT FROM: Processes for ensuring valid access authorizations for accessing CUI and systems requiring citizenship; processes for additional personnel screening].",
	"03.10.01E": "[SELECT FROM: Processes for monitoring physical intrusion alarms and surveillance equipment; mechanisms supporting and/or implementing physical intrusion alarms and surveillance equipment; mechanisms supporting and/or implementing physical access monitoring].",
	"03.10.02E": "[SELECT FROM: Process for authorizing, monitoring, and controlling system-related items entering and exiting the facility; mechanisms supporting and/or implementing, authorizing, monitoring, and controlling system components entering and exiting the facility].",
	"03.11.01E": "[SELECT FROM: Processes for implementing the threat awareness program; processes for implementing the cross-organization information-sharing capability; mechanisms supporting and/or implementing the threat awareness program; mechanisms supporting and/or implementing the cross-organization information-sharing capability].",
	"03.11.02E": "[SELECT FROM: Processes for assessments and audits; mechanisms or tools supporting and/or implementing threat-hunting capabilities].",
	"03.11.03E": "[SELECT FROM: Processes for risk assessment; mechanisms supporting and/or conducting, documenting, reviewing, disseminating, and updating the risk assessment].",
	"03.11.08E": "[SELECT FROM: Processes for risk assessment; mechanisms supporting and/or conducting, documenting, reviewing, disseminating, and updating the risk assessment].",
	"03.11.09E": "[SELECT FROM: Processes for system monitoring; processes for the discovery, collection, distribution, and use of indicators of compromise; mechanisms supporting and/or implementing a system monitoring capability; mechanisms supporting and/or implementing the discovery, collection, distribution, and use of indicators of compromise].",
	"03.11.10E": "[SELECT FROM: Processes for assessments and audits; mechanisms and/or tools supporting and/or implementing assessments and auditing].",
	"03.11.11E": "[SELECT FROM: Processes for vulnerability scanning; processes for risk response; processes for incident management and response; mechanisms and/or tools supporting and/or implementing vulnerability scanning; mechanisms supporting and/or implementing risk response; mechanisms supporting and/or implementing incident management and response].",
	"03.11.12E": "[SELECT FROM: Processes for implementing the threat awareness program; processes for implementing the cross-organization information-sharing capability; automated mechanisms supporting and/or implementing the threat awareness program; automated mechanisms supporting and/or implementing the cross-organization information-sharing capability].",
	"03.12.01E": "[SELECT FROM: Mechanisms supporting penetration testing].",
	"03.12.03E": "[SELECT FROM: Mechanisms supporting risk monitoring].",
	"03.12.04E": "[SELECT FROM: Mechanisms supporting internal system connections].",
	"03.13.01E": "[SELECT FROM: Mechanisms supporting and/or implementing the use of a diverse set of information technologies].",
	"03.13.02E": "[SELECT FROM: Mechanisms supporting and/or implementing randomness as a concealment and misdirection technique].",
	"03.13.03E": "[SELECT FROM: Mechanisms supporting and/or implementing concealment and misdirection techniques].",
	"03.13.04E": "[SELECT FROM: Mechanisms supporting and/or implementing the capability to separate system components].",
	"03.13.05E": "[SELECT FROM: Mechanisms supporting and/or implementing changing processing and/or storage locations].",
	"03.13.06E": "[SELECT FROM: Mechanisms supporting and/or implementing platform-independent applications].",
	"03.13.07E": "[SELECT FROM: Mechanisms supporting and/or implementing the use of a diverse set of information technologies; mechanisms supporting and/or implementing virtualization techniques].",
	"03.13.08E": "[SELECT FROM: Mechanisms supporting and/or implementing decoys].",
	"03.13.09E": "[SELECT FROM: Mechanisms supporting and/or implementing the isolation of information security tools, mechanisms, and support components].",
	"03.13.10E": "[SELECT FROM: Mechanisms supporting and/or implementing separate network addresses or different subnets].",
	"03.13.11E": "[SELECT FROM: Mechanisms supporting and/or implementing thin nodes].",
	"03.13.12E": "[SELECT FROM: Mechanisms protecting against or limiting the effects of denial-of-service attacks].",
	"03.13.13E": "[SELECT FROM: Mechanisms supporting and/or implementing the disabling of connection ports or input/output devices].",
	"03.13.14E": "[SELECT FROM: Mechanisms supporting and/or implementing the detonation chamber capability].",
	"03.13.15E": "[SELECT FROM: Mechanisms separating critical system components and functions].",
	"03.13.16E": "[SELECT FROM: Mechanisms supporting and/or implementing the physical separation of system components].",
	"03.14.01E": "[SELECT FROM: Software, firmware, and information integrity verification tools].",
	"03.14.04E": "[SELECT FROM: Processes for defining and obtaining component and service refreshes from trusted sources; automated mechanisms supporting and/or implementing component and service refreshes].",
	"03.14.05E": "[SELECT FROM: Processes for ensuring that information is and remains non-persistent; automated mechanisms supporting and/or implementing component and service refreshes].",
	"03.14.08E": "[SELECT FROM: Software, firmware, and information integrity verification tools].",
	"03.14.09E": "[SELECT FROM: Software, firmware, and information integrity verification tools; cryptographic mechanisms implementing software, firmware, and information integrity].",
	"03.14.10E": "[SELECT FROM: Software, firmware, and information integrity verification tools; mechanisms supporting and/or implementing protection of the integrity of boot firmware; safeguards implementing protection of the integrity of boot firmware].",
	"03.14.11E": "[SELECT FROM: Processes for incorporating the detection of unauthorized security-relevant changes into the incident response capability; mechanisms supporting and/or implementing the incorporation of detection of unauthorized security-relevant changes into the incident response capability; software, firmware, and information integrity verification tools].",
	"03.14.12E": "[SELECT FROM: Mechanisms supporting and/or implementing validity checks on information inputs].",
	"03.14.13E": "[SELECT FROM: Processes for error handling; automated mechanisms supporting and/or implementing error handling; automated mechanisms supporting and/or implementing the management of error messages].",
	"03.14.14E": "[SELECT FROM: Automated mechanisms supporting and/or implementing safeguards to protect the system memory from unauthorized code execution].",
	"03.14.15E": "[SELECT FROM: Automated mechanisms supporting and/or implementing the initiation and termination of non-persistent components].",
	"03.14.16E": "[SELECT FROM: Automated mechanisms for post-breach detection; decoys, traps, lures, and methods for deceiving adversaries; detection and notification mechanisms].",
	"03.14.17E": "[SELECT FROM: Processes for intrusion detection and system monitoring; mechanisms supporting and/or implementing intrusion detection and system monitoring capabilities; mechanisms supporting and/or implementing alerts for compromise indicators].",
	"03.14.18E": "[SELECT FROM: Processes for intrusion detection and system monitoring; automated mechanisms supporting and/or implementing intrusion detection and system monitoring capabilities; automated mechanisms supporting and/or implementing automated alerts to security personnel].",
	"03.14.19E": "[SELECT FROM: Organizational processes for intrusion detection; mechanisms supporting and/or implementing a wireless intrusion detection capability].",
	"03.15.01E": "[SELECT FROM: Mechanisms supporting and/or implementing the development, review, and update of the information security architecture; processes for developing, reviewing, and updating the information security architecture].",
	"03.15.02E": "[SELECT FROM: Processes for designing the information security architecture; mechanisms supporting and/or implementing the design of the information security architecture].",
	"03.15.03E": "[SELECT FROM: Processes for obtaining information security safeguards from different suppliers].",
	"03.16.01E": "[SELECT FROM: Processes for the modification, design, augmentation, or reconfiguration of systems or system components; mechanisms supporting and/or implementing design modification, augmentation, or reconfiguration of systems or system components].",
	"03.17.01E": "[SELECT FROM: Processes for establishing inter-organizational agreements and procedures with supply chain entities].",
	"03.17.02E": "[SELECT FROM: Processes for establishing inter-organizational agreements and procedures with supply chain entities; processes to inspect for tampering].",
	"03.17.03E": "[SELECT FROM: Processes for counterfeit prevention, detection, and reporting; mechanisms supporting and/or implementing anti-counterfeit detection, prevention, and reporting].",
	"03.17.04E": "[SELECT FROM: Organizational processes for identifying the provenance of critical systems and critical system components; mechanisms used to document, monitor, or maintain provenance].",
	"03.17.05E": "[SELECT FROM: Organizational processes for identifying pedigree information; organizational processes to determine and validate the integrity of the internal composition of critical systems and critical system components; mechanisms to determine and validate the integrity of the internal composition of critical systems and critical system components].",
}

assessment_methods[s] := {m: t |
	some m, tbl in {"examine": method_examine, "interview": method_interview, "test": method_test}
	t := tbl[s]
} if {
	some s, _ in titles
}

_supplied if is_object(input.nist_sp_800_172)

_in := object.get(input, "nist_sp_800_172", {})

_attested(id) if _in.requirements[id] == true

_det_true(id) if _in.determinations[id] == true

_det_gaps(id) := [d | some d in statements[id].determinations; not _det_true(d)]

satisfied contains id if {
	some id, _ in statements
	_attested(id)
	count(_det_gaps(id)) == 0
}

_family_name(f) := sprintf("%v %v", [f, families[f]])

_why(id) := concat("; ", array.concat(
	[x | not _attested(id); x := "statement not attested"],
	[x | count(_det_gaps(id)) > 0; x := sprintf("SP 800-172A determinations not satisfied: %v", [concat(", ", _det_gaps(id))])],
))

_full_text(s) := s.text if s.lead_in == ""

_full_text(s) := sprintf("%v %v", [s.lead_in, s.text]) if s.lead_in != ""

violations contains msg if {
	not _supplied
	msg := "NIST SP 800-172 Rev 3: FAIL-CLOSED - facts 'input.nist_sp_800_172' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant"
}

violations contains msg if {
	some id, s in statements
	not id in satisfied
	msg := sprintf("NIST SP 800-172 Rev 3 %v (%v %v, %v): %v — %v", [id, s.requirement, titles[s.requirement], _family_name(s.family), _full_text(s), _why(id)])
}

_withdrawn_statement(id) if {
	startswith(id, "ES-")
	withdrawn[substring(id, 3, -1)]
}

violations contains msg if {
	_supplied
	is_object(_in.requirements)
	some id, _ in _in.requirements
	not statements[id]
	_withdrawn_statement(id)
	msg := sprintf("NIST SP 800-172 Rev 3 Input Contract: attestation for withdrawn requirement %v — withdrawn; see %v", [id, withdrawn[substring(id, 3, -1)]])
}

_parent_statement(id) if {
	some _, s in statements
	s.parent == id
}

_parent_statement(id) if {
	some r, _ in titles
	id == concat("", ["ES-", r])
}

violations contains msg if {
	_supplied
	is_object(_in.requirements)
	some id, _ in _in.requirements
	not statements[id]
	not _withdrawn_statement(id)
	_parent_statement(id)
	msg := sprintf("NIST SP 800-172 Rev 3 Input Contract: %v is a parent or lead-in statement — attest its leaf statements (%v)", [id, concat(", ", sort([l | some l; _ = statements[l]; startswith(l, concat("", [id, "-"]))]))])
}

violations contains msg if {
	_supplied
	is_object(_in.requirements)
	some id, _ in _in.requirements
	not statements[id]
	not _withdrawn_statement(id)
	not _parent_statement(id)
	msg := sprintf("NIST SP 800-172 Rev 3 Input Contract: attestation for unknown statement id %v — not an enhanced security requirement statement in the CPRT export (keys look like \"ES-03.01.08E-a\")", [id])
}

violations contains msg if {
	_supplied
	is_object(_in.determinations)
	some id, _ in _in.determinations
	not determination_text[id]
	msg := sprintf("NIST SP 800-172A Rev 3 Input Contract: unknown determination id %v — not a determination statement in the CPRT export (keys look like \"DS-A.03.01.05E[01]\")", [id])
}

violations contains msg if {
	_supplied
	some key in ["requirements", "determinations"]
	x := _in[key]
	not is_object(x)
	msg := sprintf("NIST SP 800-172 Rev 3 Input Contract: input.nist_sp_800_172.%v must be an object of {\"<id>\": true}", [key])
}

_req_statements(r) := {id | some id; s := statements[id]; s.requirement == r}

requirements_satisfied := {r |
	some r
	_ = titles[r]
	every id in _req_statements(r) {
		id in satisfied
	}
}

family_reports[f] := rep if {
	some f, name in families
	ids := {id | some id; s := statements[id]; s.family == f}
	reqs := {s.requirement | some id in ids; s := statements[id]}
	dets := {d | some id in ids; some d in statements[id].determinations}
	rep := {
		"family": name,
		"requirements": count(reqs),
		"requirements_withdrawn": count({w | some w; wf := withdrawn_family[w]; wf == f}),
		"requirements_satisfied": count({r | some r in reqs; r in requirements_satisfied}),
		"statements": count(ids),
		"statements_attested": count({id | some id in ids; _attested(id)}),
		"statements_satisfied": count({id | some id in ids; id in satisfied}),
		"determinations": count(dets),
		"determinations_satisfied": count({d | some d in dets; _det_true(d)}),
		"gaps": sort([id | some id in ids; not id in satisfied]),
	}
}

compliance_report := {
	"framework": "NIST SP 800-172 Revision 3 with SP 800-172A Revision 3 determinations",
	"standard": "Enhanced Security Requirements for Protecting Controlled Unclassified Information",
	"source": source,
	"export_counts": export_counts,
	"total_controls": 137,
	"requirements_total": count(titles),
	"requirements_attested": count({r | some r; _ = titles[r]; every id in _req_statements(r) { _attested(id) }}),
	"requirements_satisfied": count(requirements_satisfied),
	"requirements_withdrawn": sort([w | some w; _ = withdrawn[w]]),
	"statements_total": count(statements),
	"statements_attested": count({id | some id; _ = statements[id]; _attested(id)}),
	"statements_satisfied": count(satisfied),
	"determinations_total": count(determination_text),
	"determinations_satisfied": count({d | some d; _ = determination_text[d]; _det_true(d)}),
	"families": family_reports,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
