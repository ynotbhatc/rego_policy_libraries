# DOE Cybersecurity Capability Maturity Model (C2M2) Version 2.1, June 2022 — the 356 practices of the
# model's 10 domains (§6 Model Domains, "Objectives and Practices" tables), one attested row per practice.
# Version 2.1 is the current model on the DOE CESER C2M2 page as retrieved 2026-10-14 ("C2M2 Model
# Document: Access the latest version here: C2M2 Version 2.1").
#
# Source: https://www.energy.gov/sites/default/files/2022-06/C2M2%20Version%202.1%20June%202022.pdf
#   sha256 3593e35448b917ec21f855b78fc6b3182e0d35658684c172200c8d3445f19515, 96 pages, retrieved 2026-10-14.
#   Linked from https://www.energy.gov/ceser/cybersecurity-capability-maturity-model-c2m2
# Cross-check: DOE "C2M2 V2.1 Practice and Help Text" workbook,
#   https://c2m2.doe.gov/C2M2%20V2.1%20Practice%20and%20Help%20Text.xlsx
#   sha256 b56ef5cf49b424054619c7dfa1fd5060ddc2aa205bc7c237460b7c29cd9be786, retrieved 2026-10-14.
#   Same 356 ids; identical practice text (whitespace-normalised); MIL identical except as noted below.
# Notice (model p. 95): "© 2022 Carnegie Mellon University. ... The U.S. Government has, at minimum,
# unlimited rights to use, modify, reproduce, release, perform, display, or disclose this version the C2M2
# ... as well as the right to authorize others, and hereby authorizes others, to do the same." Practice text
# is therefore copied verbatim (generated from the PDF text; five words hyphenated across a line break are
# rejoined, e.g. "organization-defined", as the workbook prints them).
#
# Ids are as printed in the model's notation (§4.8 Practice Reference Notation, "ASSET-1a"): <DOMAIN>-<objective number><practice letter>.
# The model states the total: "The C2M2 includes 356 cybersecurity practices, which are grouped into 10
# domains" (§4.1, p. 21).
#
# MIL: the maturity indicator level (1–3) printed beside each practice band. In three tables the PDF prints
# the third band without its "MIL3" label (a ruled, unlabeled band below MIL2): RESPONSE-4m..4p (p. 55),
# ARCHITECTURE-2h..2l (p. 65), ARCHITECTURE-6c..6f (p. 67). These 13 are MIL3 here — the band layout, the
# DOE workbook and the pattern of every other Management Activities objective (c–f at MIL3) agree.
#
# Domains                                                                   practices  MIL1/MIL2/MIL3
#   6.1  ASSET          Asset, Change, and Configuration Management               36    5 / 18 / 13
#   6.2  THREAT         Threat and Vulnerability Management                       30    8 / 11 / 11
#   6.3  RISK           Risk Management                                           39    4 / 19 / 16
#   6.4  ACCESS         Identity and Access Management                            35    8 / 17 / 10
#   6.5  SITUATION      Situational Awareness                                     28    3 / 13 / 12
#   6.6  RESPONSE       Event and Incident Response, Continuity of Operations     49    9 / 23 / 17
#   6.7  THIRD-PARTIES  Third-Party Risk Management                               25    4 / 10 / 11
#   6.8  WORKFORCE      Workforce Management                                      32    7 / 12 / 13
#   6.9  ARCHITECTURE   Cybersecurity Architecture                                58    6 / 30 / 22
#   6.10 PROGRAM        Cybersecurity Program Management                          24    2 / 13 /  9
#   total                                                                         356   56 / 166 / 134
#
# Gate: input.c2m2.target_mil in {1, 2, 3} (absent = 3). Practices at a MIL above the target are not
# evaluated (the model is cumulative: achieving MIL2 requires all MIL1 and MIL2 practices, §4.2 Maturity Indicator Levels). A present
# target_mil that is not exactly 1, 2 or 3 is a violation and the strictest target (3) is used.
#
# Input: input.c2m2.practices["ASSET-1a"] == true means the practice is performed as the model scores it
# ("the practice is considered performed if a response of Fully Implemented or Largely Implemented is
# selected", §4.2). Fail-closed: a missing or non-object practices container is a FAIL-CLOSED
# violation; a missing, false or non-true value for an evaluated practice is a violation; an unknown id is
# a violation. Rollups: per domain (with the MIL achieved — the highest level whose practices at or below it
# are all performed, 0 when none) and per MIL.
#
# Query: POST /v1/data/c2m2/main/compliance_report

# METADATA
# title: "DOE C2M2 Version 2.1 (June 2022) — 356 practices across 10 domains, attested, MIL-gated"
# custom:
#   class: compliance
#   framework: c2m2
#   source: us-federal
#   domains: [critical-infrastructure, energy]
#   coverage:
#     checks: 360
#     cited: 358
#     expected: 356
#     found: 358
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package c2m2.main

import rego.v1

source := {
	"publication": "Cybersecurity Capability Maturity Model (C2M2) Version 2.1",
	"publisher": "U.S. Department of Energy, Office of Cybersecurity, Energy Security, and Emergency Response (CESER)",
	"published": "June 2022",
	"url": "https://www.energy.gov/sites/default/files/2022-06/C2M2%20Version%202.1%20June%202022.pdf",
	"sha256": "3593e35448b917ec21f855b78fc6b3182e0d35658684c172200c8d3445f19515",
	"retrieved": "2026-10-14",
}

model_domains := {
	"ASSET": "Asset, Change, and Configuration Management",
	"THREAT": "Threat and Vulnerability Management",
	"RISK": "Risk Management",
	"ACCESS": "Identity and Access Management",
	"SITUATION": "Situational Awareness",
	"RESPONSE": "Event and Incident Response, Continuity of Operations",
	"THIRD-PARTIES": "Third-Party Risk Management",
	"WORKFORCE": "Workforce Management",
	"ARCHITECTURE": "Cybersecurity Architecture",
	"PROGRAM": "Cybersecurity Program Management",
}

objectives := {
	"ASSET-1": "Manage IT and OT Asset Inventory",
	"ASSET-2": "Manage Information Asset Inventory",
	"ASSET-3": "Manage IT and OT Asset Configuration",
	"ASSET-4": "Manage Changes to IT and OT Assets",
	"ASSET-5": "Management Activities for the ASSET domain",
	"THREAT-1": "Reduce Cybersecurity Vulnerabilities",
	"THREAT-2": "Respond to Threats and Share Threat Information",
	"THREAT-3": "Management Activities for the THREAT domain",
	"RISK-1": "Establish and Maintain Cyber Risk Management Strategy and Program",
	"RISK-2": "Identify Cyber Risk",
	"RISK-3": "Analyze Cyber Risk",
	"RISK-4": "Respond to Cyber Risk",
	"RISK-5": "Management Activities for the RISK domain",
	"ACCESS-1": "Establish Identities and Manage Authentication",
	"ACCESS-2": "Control Logical Access",
	"ACCESS-3": "Control Physical Access",
	"ACCESS-4": "Management Activities for the ACCESS domain",
	"SITUATION-1": "Perform Logging",
	"SITUATION-2": "Perform Monitoring",
	"SITUATION-3": "Establish and Maintain Situational Awareness",
	"SITUATION-4": "Management Activities for the SITUATION domain",
	"RESPONSE-1": "Detect Cybersecurity Events",
	"RESPONSE-2": "Analyze Cybersecurity Events and Declare Incidents",
	"RESPONSE-3": "Respond to Cybersecurity Incidents",
	"RESPONSE-4": "Address Cybersecurity in Continuity of Operations",
	"RESPONSE-5": "Management Activities for the RESPONSE domain",
	"THIRD-PARTIES-1": "Identify and Prioritize Third Parties",
	"THIRD-PARTIES-2": "Manage Third-Party Risk",
	"THIRD-PARTIES-3": "Management Activities for the THIRD-PARTIES domain",
	"WORKFORCE-1": "Implement Workforce Controls",
	"WORKFORCE-2": "Increase Cybersecurity Awareness",
	"WORKFORCE-3": "Assign Cybersecurity Responsibilities",
	"WORKFORCE-4": "Develop Cybersecurity Workforce",
	"WORKFORCE-5": "Management Activities for the WORKFORCE domain",
	"ARCHITECTURE-1": "Establish and Maintain Cybersecurity Architecture Strategy and Program",
	"ARCHITECTURE-2": "Implement Network Protections as an Element of the Cybersecurity Architecture",
	"ARCHITECTURE-3": "Implement IT and OT Asset Security as an Element of the Cybersecurity Architecture",
	"ARCHITECTURE-4": "Implement Software Security as an Element of the Cybersecurity Architecture",
	"ARCHITECTURE-5": "Implement Data Security as an Element of the Cybersecurity Architecture",
	"ARCHITECTURE-6": "Management Activities for the ARCHITECTURE domain",
	"PROGRAM-1": "Establish Cybersecurity Program Strategy",
	"PROGRAM-2": "Establish and Maintain Cybersecurity Program",
	"PROGRAM-3": "Management Activities for the PROGRAM domain",
}

practices := {
	# ── ASSET — Asset, Change, and Configuration Management ──
	"ASSET-1a": {"domain": "ASSET", "objective": "ASSET-1", "mil": 1, "text": "IT and OT assets that are important to the delivery of the function are inventoried, at least in an ad hoc manner"},
	"ASSET-1b": {"domain": "ASSET", "objective": "ASSET-1", "mil": 2, "text": "The IT and OT asset inventory includes assets within the function that may be leveraged to achieve a threat objective"},
	"ASSET-1c": {"domain": "ASSET", "objective": "ASSET-1", "mil": 2, "text": "Inventoried IT and OT assets are prioritized based on defined criteria that include importance to the delivery of the function"},
	"ASSET-1d": {"domain": "ASSET", "objective": "ASSET-1", "mil": 2, "text": "Prioritization criteria include consideration of the degree to which an asset within the function may be leveraged to achieve a threat objective"},
	"ASSET-1e": {"domain": "ASSET", "objective": "ASSET-1", "mil": 2, "text": "The IT and OT inventory includes attributes that support cybersecurity activities (for example, location, asset priority, asset owner, operating system, and firmware versions)"},
	"ASSET-1f": {"domain": "ASSET", "objective": "ASSET-1", "mil": 3, "text": "The IT and OT asset inventory is complete (the inventory includes all assets within the function)"},
	"ASSET-1g": {"domain": "ASSET", "objective": "ASSET-1", "mil": 3, "text": "The IT and OT asset inventory is current, that is, it is updated periodically and according to defined triggers, such as system changes"},
	"ASSET-1h": {"domain": "ASSET", "objective": "ASSET-1", "mil": 3, "text": "Data is destroyed or securely removed from IT and OT assets prior to redeployment and at end of life"},
	"ASSET-2a": {"domain": "ASSET", "objective": "ASSET-2", "mil": 1, "text": "Information assets that are important to the delivery of the function (for example, SCADA set points and customer information) are inventoried, at least in an ad hoc manner"},
	"ASSET-2b": {"domain": "ASSET", "objective": "ASSET-2", "mil": 2, "text": "The information asset inventory includes information assets within the function that may be leveraged to achieve a threat objective"},
	"ASSET-2c": {"domain": "ASSET", "objective": "ASSET-2", "mil": 2, "text": "Inventoried information assets are categorized based on defined criteria that includes importance to the delivery of the function"},
	"ASSET-2d": {"domain": "ASSET", "objective": "ASSET-2", "mil": 2, "text": "Categorization criteria include consideration of the degree to which an asset within the function may be leveraged to achieve a threat objective"},
	"ASSET-2e": {"domain": "ASSET", "objective": "ASSET-2", "mil": 2, "text": "The information asset inventory includes attributes that support cybersecurity activities (for example, asset category, backup locations and frequencies, storage locations, asset owner, cybersecurity requirements)"},
	"ASSET-2f": {"domain": "ASSET", "objective": "ASSET-2", "mil": 3, "text": "The information asset inventory is complete (the inventory includes all assets within the function)"},
	"ASSET-2g": {"domain": "ASSET", "objective": "ASSET-2", "mil": 3, "text": "The information asset inventory is current, that is, it is updated periodically and according to defined triggers, such as system changes"},
	"ASSET-2h": {"domain": "ASSET", "objective": "ASSET-2", "mil": 3, "text": "Information assets are sanitized or destroyed at end of life using techniques appropriate to their cybersecurity requirements"},
	"ASSET-3a": {"domain": "ASSET", "objective": "ASSET-3", "mil": 1, "text": "Configuration baselines are established, at least in an ad hoc manner"},
	"ASSET-3b": {"domain": "ASSET", "objective": "ASSET-3", "mil": 2, "text": "Configuration baselines are used to configure assets at deployment and restoration"},
	"ASSET-3c": {"domain": "ASSET", "objective": "ASSET-3", "mil": 2, "text": "Configuration baselines incorporate applicable requirements from the cybersecurity architecture (ARCHITECTURE-1f)"},
	"ASSET-3d": {"domain": "ASSET", "objective": "ASSET-3", "mil": 2, "text": "Configuration baselines are reviewed and updated periodically and according to defined triggers, such as system changes and changes to the cybersecurity architecture"},
	"ASSET-3e": {"domain": "ASSET", "objective": "ASSET-3", "mil": 3, "text": "Asset configurations are monitored for consistency with baselines throughout the assets’ lifecycles"},
	"ASSET-4a": {"domain": "ASSET", "objective": "ASSET-4", "mil": 1, "text": "Changes to assets are evaluated and approved before being implemented, at least in an ad hoc manner"},
	"ASSET-4b": {"domain": "ASSET", "objective": "ASSET-4", "mil": 1, "text": "Changes to assets are documented, at least in an ad hoc manner"},
	"ASSET-4c": {"domain": "ASSET", "objective": "ASSET-4", "mil": 2, "text": "Documentation requirements for asset changes are established and maintained"},
	"ASSET-4d": {"domain": "ASSET", "objective": "ASSET-4", "mil": 2, "text": "Changes to higher priority assets are tested prior to being deployed"},
	"ASSET-4e": {"domain": "ASSET", "objective": "ASSET-4", "mil": 2, "text": "Changes and updates are implemented in a secure manner"},
	"ASSET-4f": {"domain": "ASSET", "objective": "ASSET-4", "mil": 2, "text": "The capability to reverse changes is established and maintained for assets that are important to the delivery of the function"},
	"ASSET-4g": {"domain": "ASSET", "objective": "ASSET-4", "mil": 2, "text": "Change management practices address the full lifecycle of assets (for example, acquisition, deployment, operation, retirement)"},
	"ASSET-4h": {"domain": "ASSET", "objective": "ASSET-4", "mil": 3, "text": "Changes to higher priority assets are tested for cybersecurity impact prior to being deployed"},
	"ASSET-4i": {"domain": "ASSET", "objective": "ASSET-4", "mil": 3, "text": "Change logs include information about modifications that impact the cybersecurity requirements of assets"},
	"ASSET-5a": {"domain": "ASSET", "objective": "ASSET-5", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the ASSET domain"},
	"ASSET-5b": {"domain": "ASSET", "objective": "ASSET-5", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the ASSET domain"},
	"ASSET-5c": {"domain": "ASSET", "objective": "ASSET-5", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the ASSET domain"},
	"ASSET-5d": {"domain": "ASSET", "objective": "ASSET-5", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the ASSET domain are assigned to personnel"},
	"ASSET-5e": {"domain": "ASSET", "objective": "ASSET-5", "mil": 3, "text": "Personnel performing activities in the ASSET domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"ASSET-5f": {"domain": "ASSET", "objective": "ASSET-5", "mil": 3, "text": "The effectiveness of activities in the ASSET domain is evaluated and tracked"},
	# ── THREAT — Threat and Vulnerability Management ──
	"THREAT-1a": {"domain": "THREAT", "objective": "THREAT-1", "mil": 1, "text": "Information sources to support cybersecurity vulnerability discovery are identified, at least in an ad hoc manner"},
	"THREAT-1b": {"domain": "THREAT", "objective": "THREAT-1", "mil": 1, "text": "Cybersecurity vulnerability information is gathered and interpreted for the function, at least in an ad hoc manner"},
	"THREAT-1c": {"domain": "THREAT", "objective": "THREAT-1", "mil": 1, "text": "Cybersecurity vulnerability assessments are performed, at least in an ad hoc manner"},
	"THREAT-1d": {"domain": "THREAT", "objective": "THREAT-1", "mil": 1, "text": "Cybersecurity vulnerabilities that are relevant to the delivery of the function are mitigated, at least in an ad hoc manner"},
	"THREAT-1e": {"domain": "THREAT", "objective": "THREAT-1", "mil": 2, "text": "Cybersecurity vulnerability information sources that collectively address higher priority assets are monitored"},
	"THREAT-1f": {"domain": "THREAT", "objective": "THREAT-1", "mil": 2, "text": "Cybersecurity vulnerability assessments are performed periodically and according to defined triggers, such as system changes and external events"},
	"THREAT-1g": {"domain": "THREAT", "objective": "THREAT-1", "mil": 2, "text": "Identified cybersecurity vulnerabilities are analyzed and prioritized, and are addressed accordingly"},
	"THREAT-1h": {"domain": "THREAT", "objective": "THREAT-1", "mil": 2, "text": "Operational impact to the function is evaluated prior to deploying patches or other mitigations"},
	"THREAT-1i": {"domain": "THREAT", "objective": "THREAT-1", "mil": 2, "text": "Information on discovered cybersecurity vulnerabilities is shared with organization-defined stakeholders"},
	"THREAT-1j": {"domain": "THREAT", "objective": "THREAT-1", "mil": 3, "text": "Cybersecurity vulnerability information sources that collectively address all IT and OT assets within the function are monitored"},
	"THREAT-1k": {"domain": "THREAT", "objective": "THREAT-1", "mil": 3, "text": "Cybersecurity vulnerability assessments are performed by parties that are independent of the operations of the function"},
	"THREAT-1l": {"domain": "THREAT", "objective": "THREAT-1", "mil": 3, "text": "Vulnerability monitoring activities include review to confirm that actions taken in response to cybersecurity vulnerabilities were effective"},
	"THREAT-1m": {"domain": "THREAT", "objective": "THREAT-1", "mil": 3, "text": "Mechanisms are established and maintained to receive and respond to reports from the public or external parties of potential vulnerabilities related to the organization’s IT and OT assets, such as public-facing websites or mobile applications"},
	"THREAT-2a": {"domain": "THREAT", "objective": "THREAT-2", "mil": 1, "text": "Internal and external information sources to support threat management activities are identified, at least in an ad hoc manner"},
	"THREAT-2b": {"domain": "THREAT", "objective": "THREAT-2", "mil": 1, "text": "Information about cybersecurity threats is gathered and interpreted for the function, at least in an ad hoc manner"},
	"THREAT-2c": {"domain": "THREAT", "objective": "THREAT-2", "mil": 1, "text": "Threat objectives for the function are identified, at least in an ad hoc manner"},
	"THREAT-2d": {"domain": "THREAT", "objective": "THREAT-2", "mil": 1, "text": "Threats that are relevant to the delivery of the function are addressed, at least in an ad hoc manner"},
	"THREAT-2e": {"domain": "THREAT", "objective": "THREAT-2", "mil": 2, "text": "A threat profile for the function is established that includes threat objectives and additional threat characteristics (for example, threat actor types, motives, capabilities, and targets)"},
	"THREAT-2f": {"domain": "THREAT", "objective": "THREAT-2", "mil": 2, "text": "Threat information sources that collectively address all components of the threat profile are prioritized and monitored"},
	"THREAT-2g": {"domain": "THREAT", "objective": "THREAT-2", "mil": 2, "text": "Identified threats are analyzed and prioritized and are addressed accordingly"},
	"THREAT-2h": {"domain": "THREAT", "objective": "THREAT-2", "mil": 2, "text": "Threat information is exchanged with stakeholders (for example, executives, operations staff, government, connected organizations, vendors, sector organizations, regulators, Information Sharing and Analysis Centers [ISACs])"},
	"THREAT-2i": {"domain": "THREAT", "objective": "THREAT-2", "mil": 3, "text": "The threat profile for the function is updated periodically and according to defined triggers, such as system changes and external events"},
	"THREAT-2j": {"domain": "THREAT", "objective": "THREAT-2", "mil": 3, "text": "Threat monitoring and response activities leverage and trigger predefined states of operation (SITUATION-3g)"},
	"THREAT-2k": {"domain": "THREAT", "objective": "THREAT-2", "mil": 3, "text": "Secure, near-real-time methods are used for receiving and sharing threat information to enable rapid analysis and action"},
	"THREAT-3a": {"domain": "THREAT", "objective": "THREAT-3", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the THREAT domain"},
	"THREAT-3b": {"domain": "THREAT", "objective": "THREAT-3", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the THREAT domain"},
	"THREAT-3c": {"domain": "THREAT", "objective": "THREAT-3", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the THREAT domain"},
	"THREAT-3d": {"domain": "THREAT", "objective": "THREAT-3", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the THREAT domain are assigned to personnel"},
	"THREAT-3e": {"domain": "THREAT", "objective": "THREAT-3", "mil": 3, "text": "Personnel performing activities in the THREAT domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"THREAT-3f": {"domain": "THREAT", "objective": "THREAT-3", "mil": 3, "text": "The effectiveness of activities in the THREAT domain is evaluated and tracked"},
	# ── RISK — Risk Management ──
	"RISK-1a": {"domain": "RISK", "objective": "RISK-1", "mil": 1, "text": "The organization has a strategy for cyber risk management, which may be developed and managed in an ad hoc manner"},
	"RISK-1b": {"domain": "RISK", "objective": "RISK-1", "mil": 2, "text": "A strategy for cyber risk management is established and maintained in alignment with the organization’s cybersecurity program strategy (PROGRAM-1b) and enterprise architecture"},
	"RISK-1c": {"domain": "RISK", "objective": "RISK-1", "mil": 2, "text": "The cyber risk management program is established and maintained to perform cyber risk management activities according to the cyber risk management strategy"},
	"RISK-1d": {"domain": "RISK", "objective": "RISK-1", "mil": 2, "text": "Information from RISK domain activities is communicated to relevant stakeholders"},
	"RISK-1e": {"domain": "RISK", "objective": "RISK-1", "mil": 2, "text": "Governance for the cyber risk management program is established and maintained"},
	"RISK-1f": {"domain": "RISK", "objective": "RISK-1", "mil": 2, "text": "Senior management sponsorship for the cyber risk management program is visible and active"},
	"RISK-1g": {"domain": "RISK", "objective": "RISK-1", "mil": 3, "text": "The cyber risk management program aligns with the organization's mission and objectives"},
	"RISK-1h": {"domain": "RISK", "objective": "RISK-1", "mil": 3, "text": "The cyber risk management program is coordinated with the organization’s enterprise-wide risk management program"},
	"RISK-2a": {"domain": "RISK", "objective": "RISK-2", "mil": 1, "text": "Cyber risks are identified, at least in an ad hoc manner"},
	"RISK-2b": {"domain": "RISK", "objective": "RISK-2", "mil": 2, "text": "A defined method is used to identify cyber risks"},
	"RISK-2c": {"domain": "RISK", "objective": "RISK-2", "mil": 2, "text": "Stakeholders from appropriate operations and business areas participate in the identification of cyber risks"},
	"RISK-2d": {"domain": "RISK", "objective": "RISK-2", "mil": 2, "text": "Identified cyber risks are consolidated into categories (for example, data breaches, insider mistakes, ransomware, OT control takeover) to facilitate management at the category level"},
	"RISK-2e": {"domain": "RISK", "objective": "RISK-2", "mil": 2, "text": "Cyber risk categories and cyber risks are documented in a risk register or other artifact"},
	"RISK-2f": {"domain": "RISK", "objective": "RISK-2", "mil": 2, "text": "Cyber risk categories and cyber risks are assigned to risk owners"},
	"RISK-2g": {"domain": "RISK", "objective": "RISK-2", "mil": 2, "text": "Cyber risk identification activities are performed periodically and according to defined triggers, such as system changes and external events"},
	"RISK-2h": {"domain": "RISK", "objective": "RISK-2", "mil": 3, "text": "Cyber risk identification activities leverage asset inventory and prioritization information from the ASSET domain, such as IT and OT asset end of support, single points of failure, information asset risk of disclosure, tampering, or destruction"},
	"RISK-2i": {"domain": "RISK", "objective": "RISK-2", "mil": 3, "text": "Vulnerability management information from THREAT domain activities is used to update cyber risks and identify new risks (such as risks arising from vulnerabilities that pose an ongoing risk to the organization or newly identified vulnerabilities)"},
	"RISK-2j": {"domain": "RISK", "objective": "RISK-2", "mil": 3, "text": "Threat management information from THREAT domain activities is used to update cyber risks and identify new risks"},
	"RISK-2k": {"domain": "RISK", "objective": "RISK-2", "mil": 3, "text": "Information from THIRD-PARTIES domain activities is used to update cyber risks and identify new risks"},
	"RISK-2l": {"domain": "RISK", "objective": "RISK-2", "mil": 3, "text": "Information from ARCHITECTURE domain activities (such as unmitigated architectural conformance gaps) is used to update cyber risks and identify new risks"},
	"RISK-2m": {"domain": "RISK", "objective": "RISK-2", "mil": 3, "text": "Cyber risk identification considers risks that may arise from or impact critical infrastructure or other interdependent organizations"},
	"RISK-3a": {"domain": "RISK", "objective": "RISK-3", "mil": 1, "text": "Cyber risks are prioritized based on estimated impact, at least in an ad hoc manner"},
	"RISK-3b": {"domain": "RISK", "objective": "RISK-3", "mil": 2, "text": "Defined criteria are used to prioritize cyber risks (for example, impact to the organization, impact to the community, likelihood, susceptibility, risk tolerance)"},
	"RISK-3c": {"domain": "RISK", "objective": "RISK-3", "mil": 2, "text": "A defined method is used to estimate impact for higher priority cyber risks (for example, comparison to actual events, risk quantification)"},
	"RISK-3d": {"domain": "RISK", "objective": "RISK-3", "mil": 2, "text": "Defined methods are used to analyze higher priority cyber risks (for example, analyzing the prevalence of types of attacks to estimate likelihood, using the results of controls assessments to estimate susceptibility)"},
	"RISK-3e": {"domain": "RISK", "objective": "RISK-3", "mil": 2, "text": "Organizational stakeholders from appropriate operations and business functions participate in the analysis of higher priority cyber risks"},
	"RISK-3f": {"domain": "RISK", "objective": "RISK-3", "mil": 2, "text": "Cyber risks are removed from the risk register or other artifact used to document and manage identified risks when they no longer require tracking or response"},
	"RISK-3g": {"domain": "RISK", "objective": "RISK-3", "mil": 3, "text": "Cyber risk analyses are updated periodically and according to defined triggers, such as system changes, external events, and information from other model domains"},
	"RISK-4a": {"domain": "RISK", "objective": "RISK-4", "mil": 1, "text": "Risk responses (such as mitigate, accept, avoid, or transfer) are implemented to address cyber risks, at least in an ad hoc manner"},
	"RISK-4b": {"domain": "RISK", "objective": "RISK-4", "mil": 2, "text": "A defined method is used to select and implement risk responses based on analysis and prioritization"},
	"RISK-4c": {"domain": "RISK", "objective": "RISK-4", "mil": 3, "text": "Cybersecurity controls are evaluated to determine whether they are designed appropriately and are operating as intended to mitigate identified cyber risks"},
	"RISK-4d": {"domain": "RISK", "objective": "RISK-4", "mil": 3, "text": "Results from cyber risk impact analyses and cybersecurity control evaluations are reviewed together by enterprise leadership to determine whether cyber risks are sufficiently mitigated, and risk tolerances are not exceeded"},
	"RISK-4e": {"domain": "RISK", "objective": "RISK-4", "mil": 3, "text": "Risk responses (such as mitigate, accept, avoid, or transfer) are reviewed periodically by leadership to determine whether they are still appropriate"},
	"RISK-5a": {"domain": "RISK", "objective": "RISK-5", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the RISK domain"},
	"RISK-5b": {"domain": "RISK", "objective": "RISK-5", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the RISK domain"},
	"RISK-5c": {"domain": "RISK", "objective": "RISK-5", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the RISK domain"},
	"RISK-5d": {"domain": "RISK", "objective": "RISK-5", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the RISK domain are assigned to personnel"},
	"RISK-5e": {"domain": "RISK", "objective": "RISK-5", "mil": 3, "text": "Personnel performing activities in the RISK domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"RISK-5f": {"domain": "RISK", "objective": "RISK-5", "mil": 3, "text": "The effectiveness of activities in the RISK domain is evaluated and tracked"},
	# ── ACCESS — Identity and Access Management ──
	"ACCESS-1a": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 1, "text": "Identities are provisioned, at least in an ad hoc manner, for personnel and other entities such as services and devices that require access to assets (note that this does not preclude shared identities)"},
	"ACCESS-1b": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 1, "text": "Credentials (such as passwords, smartcards, certificates, and keys) are issued for personnel and other entities that require access to assets, at least in an ad hoc manner"},
	"ACCESS-1c": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 1, "text": "Identities are deprovisioned, at least in an ad hoc manner, when no longer required"},
	"ACCESS-1d": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 2, "text": "Password strength and reuse restrictions are defined and enforced"},
	"ACCESS-1e": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 2, "text": "Identity repositories are reviewed and updated periodically and according to defined triggers, such as system changes and changes to organizational structure"},
	"ACCESS-1f": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 2, "text": "Identities are deprovisioned within organization-defined time thresholds when no longer required"},
	"ACCESS-1g": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 2, "text": "The use of privileged credentials is limited to processes for which they are required"},
	"ACCESS-1h": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 2, "text": "Stronger credentials, multifactor authentication, or single use credentials are required for higher risk access (such as privileged accounts, service accounts, shared accounts, and remote access)"},
	"ACCESS-1i": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 3, "text": "Multifactor authentication is required for all access, where feasible"},
	"ACCESS-1j": {"domain": "ACCESS", "objective": "ACCESS-1", "mil": 3, "text": "Identities are disabled after a defined period of inactivity, where feasible"},
	"ACCESS-2a": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 1, "text": "Logical access controls are implemented, at least in an ad hoc manner"},
	"ACCESS-2b": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 1, "text": "Logical access privileges are revoked when no longer needed, at least in an ad hoc manner"},
	"ACCESS-2c": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 2, "text": "Logical access requirements are established and maintained (for example, rules for which types of entities are allowed to access an asset, limits of allowed access, constraints on remote access, authentication parameters)"},
	"ACCESS-2d": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 2, "text": "Logical access requirements incorporate the principle of least privilege"},
	"ACCESS-2e": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 2, "text": "Logical access requirements incorporate the principle of separation of duties"},
	"ACCESS-2f": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 2, "text": "Logical access requests are reviewed and approved by the asset owner"},
	"ACCESS-2g": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 2, "text": "Logical access privileges that pose higher risk to the function receive additional scrutiny and monitoring"},
	"ACCESS-2h": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 3, "text": "Logical access privileges are reviewed and updated to ensure conformance with access requirements periodically and according to defined triggers, such as changes to organizational structure, and after any temporary elevation of privileges"},
	"ACCESS-2i": {"domain": "ACCESS", "objective": "ACCESS-2", "mil": 3, "text": "Anomalous logical access attempts are monitored as indicators of cybersecurity events"},
	"ACCESS-3a": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 1, "text": "Physical access controls (such as fences, locks, and signage) are implemented, at least in an ad hoc manner"},
	"ACCESS-3b": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 1, "text": "Physical access privileges are revoked when no longer needed, at least in an ad hoc manner"},
	"ACCESS-3c": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 1, "text": "Physical access logs are maintained, at least in an ad hoc manner"},
	"ACCESS-3d": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 2, "text": "Physical access requirements are established and maintained (for example, rules for who is allowed to access an asset, how access is granted, limits of allowed access)"},
	"ACCESS-3e": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 2, "text": "Physical access requirements incorporate the principle of least privilege"},
	"ACCESS-3f": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 2, "text": "Physical access requirements incorporate the principle of separation of duties"},
	"ACCESS-3g": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 2, "text": "Physical access requests are reviewed and approved by the asset owner"},
	"ACCESS-3h": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 2, "text": "Physical access privileges that pose higher risk to the function receive additional scrutiny and monitoring"},
	"ACCESS-3i": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 3, "text": "Physical access privileges are reviewed and updated"},
	"ACCESS-3j": {"domain": "ACCESS", "objective": "ACCESS-3", "mil": 3, "text": "Physical access is monitored to identify potential cybersecurity events"},
	"ACCESS-4a": {"domain": "ACCESS", "objective": "ACCESS-4", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the ACCESS domain"},
	"ACCESS-4b": {"domain": "ACCESS", "objective": "ACCESS-4", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the ACCESS domain"},
	"ACCESS-4c": {"domain": "ACCESS", "objective": "ACCESS-4", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the ACCESS domain"},
	"ACCESS-4d": {"domain": "ACCESS", "objective": "ACCESS-4", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the ACCESS domain are assigned to personnel"},
	"ACCESS-4e": {"domain": "ACCESS", "objective": "ACCESS-4", "mil": 3, "text": "Personnel performing activities in the ACCESS domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"ACCESS-4f": {"domain": "ACCESS", "objective": "ACCESS-4", "mil": 3, "text": "The effectiveness of activities in the ACCESS domain is evaluated and tracked"},
	# ── SITUATION — Situational Awareness ──
	"SITUATION-1a": {"domain": "SITUATION", "objective": "SITUATION-1", "mil": 1, "text": "Logging is occurring for assets that are important to the delivery of the function, at least in an ad hoc manner"},
	"SITUATION-1b": {"domain": "SITUATION", "objective": "SITUATION-1", "mil": 2, "text": "Logging is occurring for assets within the function that may be leveraged to achieve a threat objective, wherever feasible"},
	"SITUATION-1c": {"domain": "SITUATION", "objective": "SITUATION-1", "mil": 2, "text": "Logging requirements are established and maintained for IT and OT assets that are important to the delivery of the function and assets within the function that may be leveraged to achieve a threat objective"},
	"SITUATION-1d": {"domain": "SITUATION", "objective": "SITUATION-1", "mil": 2, "text": "Logging requirements are established and maintained for network and host monitoring infrastructure (for example, web gateways, endpoint detection and response software, intrusion detection and prevention systems)"},
	"SITUATION-1e": {"domain": "SITUATION", "objective": "SITUATION-1", "mil": 2, "text": "Log data are being aggregated within the function"},
	"SITUATION-1f": {"domain": "SITUATION", "objective": "SITUATION-1", "mil": 3, "text": "More rigorous logging is performed for higher priority assets"},
	"SITUATION-2a": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 1, "text": "Periodic reviews of log data or other cybersecurity monitoring activities are performed, at least in an ad hoc manner"},
	"SITUATION-2b": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 1, "text": "Data and alerts from network and host monitoring infrastructure assets are periodically reviewed, at least in an ad hoc manner"},
	"SITUATION-2c": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 2, "text": "Monitoring and analysis requirements are established and maintained for the function and address timely review of event data"},
	"SITUATION-2d": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 2, "text": "Indicators of anomalous activity are established and maintained based on system logs, data flows, network baselines, cybersecurity events, and architecture and are monitored across the IT and OT environments"},
	"SITUATION-2e": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 2, "text": "Alarms and alerts are configured and maintained to support the identification of cybersecurity events"},
	"SITUATION-2f": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 2, "text": "Monitoring activities are aligned with the threat profile (THREAT-2e)"},
	"SITUATION-2g": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 3, "text": "More rigorous monitoring is performed for higher priority assets"},
	"SITUATION-2h": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 3, "text": "Risk analysis information (RISK-3d) is used to identify indicators of anomalous activity"},
	"SITUATION-2i": {"domain": "SITUATION", "objective": "SITUATION-2", "mil": 3, "text": "Indicators of anomalous activity are evaluated and updated periodically and according to defined triggers, such as system changes and external events"},
	"SITUATION-3a": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 2, "text": "Methods of communicating the current state of cybersecurity for the function are established and maintained"},
	"SITUATION-3b": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 2, "text": "Monitoring data are aggregated to provide an understanding of the operational state of the function"},
	"SITUATION-3c": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 2, "text": "Relevant information from across the organization is available to enhance situational awareness"},
	"SITUATION-3d": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 3, "text": "Situational awareness reporting requirements have been defined and address timely dissemination of cybersecurity information to organization-defined stakeholders"},
	"SITUATION-3e": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 3, "text": "Relevant information from outside the organization is collected and made available across the organization to enhance situational awareness"},
	"SITUATION-3f": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 3, "text": "A capability is established and maintained to aggregate, correlate, and analyze the outputs of cybersecurity monitoring activities and provide a near-real-time understanding of the cybersecurity state of the function"},
	"SITUATION-3g": {"domain": "SITUATION", "objective": "SITUATION-3", "mil": 3, "text": "Predefined states of operation are documented and can be implemented based on the cybersecurity state of the function or when triggered by activities in other domains"},
	"SITUATION-4a": {"domain": "SITUATION", "objective": "SITUATION-4", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the SITUATION domain"},
	"SITUATION-4b": {"domain": "SITUATION", "objective": "SITUATION-4", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the SITUATION domain"},
	"SITUATION-4c": {"domain": "SITUATION", "objective": "SITUATION-4", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the SITUATION domain"},
	"SITUATION-4d": {"domain": "SITUATION", "objective": "SITUATION-4", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the SITUATION domain are assigned to personnel"},
	"SITUATION-4e": {"domain": "SITUATION", "objective": "SITUATION-4", "mil": 3, "text": "Personnel performing activities in the SITUATION domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"SITUATION-4f": {"domain": "SITUATION", "objective": "SITUATION-4", "mil": 3, "text": "The effectiveness of activities in the SITUATION domain is evaluated and tracked"},
	# ── RESPONSE — Event and Incident Response, Continuity of Operations ──
	"RESPONSE-1a": {"domain": "RESPONSE", "objective": "RESPONSE-1", "mil": 1, "text": "Detected cybersecurity events are reported to a specified person or role and documented, at least in an ad hoc manner"},
	"RESPONSE-1b": {"domain": "RESPONSE", "objective": "RESPONSE-1", "mil": 2, "text": "Criteria are established for cybersecurity event detection (for example, what constitutes a cybersecurity event, where to look for cybersecurity events)"},
	"RESPONSE-1c": {"domain": "RESPONSE", "objective": "RESPONSE-1", "mil": 2, "text": "Cybersecurity events are documented based on the established criteria"},
	"RESPONSE-1d": {"domain": "RESPONSE", "objective": "RESPONSE-1", "mil": 3, "text": "Event information is correlated to support incident analysis by identifying patterns, trends, and other common features"},
	"RESPONSE-1e": {"domain": "RESPONSE", "objective": "RESPONSE-1", "mil": 3, "text": "Cybersecurity event detection activities are adjusted based on identified risks and the organization’s threat profile (THREAT-2e)"},
	"RESPONSE-1f": {"domain": "RESPONSE", "objective": "RESPONSE-1", "mil": 3, "text": "Situational awareness for the function is monitored to support the identification of cybersecurity events"},
	"RESPONSE-2a": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 1, "text": "Criteria for declaring cybersecurity incidents are established, at least in an ad hoc manner"},
	"RESPONSE-2b": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 1, "text": "Cybersecurity events are analyzed to support the declaration of cybersecurity incidents, at least in an ad hoc manner"},
	"RESPONSE-2c": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 2, "text": "Cybersecurity incident declaration criteria are formally established based on potential impact to the function"},
	"RESPONSE-2d": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 2, "text": "Cybersecurity events are declared to be incidents based on established criteria"},
	"RESPONSE-2e": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 2, "text": "Cybersecurity incident declaration criteria are updated periodically and according to defined triggers, such as organizational changes, lessons learned from plan execution, or newly identified threats"},
	"RESPONSE-2f": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 2, "text": "There is a repository where cybersecurity events and incidents are documented and tracked to closure"},
	"RESPONSE-2g": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 2, "text": "Internal and external stakeholders (for example, executives, attorneys, government agencies, connected organizations, vendors, sector organizations, regulators) are identified and notified of incidents based on situational awareness reporting requirements (SITUATION-3d)"},
	"RESPONSE-2h": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 3, "text": "Criteria for cybersecurity incident declaration are aligned with cyber risk prioritization criteria (RISK-3b)"},
	"RESPONSE-2i": {"domain": "RESPONSE", "objective": "RESPONSE-2", "mil": 3, "text": "Cybersecurity incidents are correlated to identify patterns, trends, and other common features across multiple incidents"},
	"RESPONSE-3a": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 1, "text": "Cybersecurity incident response personnel are identified, and roles are assigned, at least in an ad hoc manner"},
	"RESPONSE-3b": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 1, "text": "Responses to cybersecurity incidents are executed, at least in an ad hoc manner, to limit impact to the function and restore normal operations"},
	"RESPONSE-3c": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 1, "text": "Reporting of incidents is performed (for example, internal reporting, ICS-CERT, relevant ISACs), at least in an ad hoc manner"},
	"RESPONSE-3d": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 2, "text": "Cybersecurity incident response plans that address all phases of the incident lifecycle are established and maintained"},
	"RESPONSE-3e": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 2, "text": "Cybersecurity incident response is executed according to defined plans and procedures"},
	"RESPONSE-3f": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 2, "text": "Cybersecurity incident response plans include a communications plan for internal and external stakeholders"},
	"RESPONSE-3g": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 2, "text": "Cybersecurity incident response plan exercises are conducted periodically and according to defined triggers, such as system changes and external events"},
	"RESPONSE-3h": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 2, "text": "Cybersecurity incident lessons-learned activities are performed and corrective actions are taken, including updates to the incident response plan"},
	"RESPONSE-3i": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 3, "text": "Cybersecurity incident root-cause analysis is performed and corrective actions are taken, including updates to the incident response plan"},
	"RESPONSE-3j": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 3, "text": "Cybersecurity incident responses are coordinated with vendors, law enforcement, and other external entities as appropriate, including support for evidence collection and preservation"},
	"RESPONSE-3k": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 3, "text": "Cybersecurity incident response personnel participate in joint cybersecurity exercises with other organizations"},
	"RESPONSE-3l": {"domain": "RESPONSE", "objective": "RESPONSE-3", "mil": 3, "text": "Cybersecurity incident responses leverage and trigger predefined states of operation (SITUATION-3g)"},
	"RESPONSE-4a": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 1, "text": "Continuity plans are developed to sustain and restore operation of the function if a cybersecurity event or incident occurs, at least in an ad hoc manner"},
	"RESPONSE-4b": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 1, "text": "Data backups are available and tested, at least in an ad hoc manner"},
	"RESPONSE-4c": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 1, "text": "IT and OT assets requiring spares are identified, at least in an ad hoc manner"},
	"RESPONSE-4d": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Continuity plans address potential impacts from cybersecurity incidents"},
	"RESPONSE-4e": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "The assets and activities necessary to sustain minimum operations of the function are identified and documented in continuity plans"},
	"RESPONSE-4f": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Continuity plans address IT, OT, and information assets that are important to the delivery of the function, including the availability of backup data and replacement, redundant, and spare IT and OT assets"},
	"RESPONSE-4g": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Recovery time objectives (RTOs) and recovery point objectives (RPOs) for assets that are important to the delivery of the function are incorporated into continuity plans"},
	"RESPONSE-4h": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Cybersecurity incident criteria that trigger the execution of continuity plans are established and communicated to incident response and continuity management personnel"},
	"RESPONSE-4i": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Continuity plans are tested through evaluations and exercises periodically and according to defined triggers, such as system changes and external events"},
	"RESPONSE-4j": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Cybersecurity controls protecting backup data are equivalent to or more rigorous than controls protecting source data"},
	"RESPONSE-4k": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Data backups are logically or physically separated from source data"},
	"RESPONSE-4l": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 2, "text": "Spares for selected IT and OT assets are available"},
	"RESPONSE-4m": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 3, "text": "Continuity plans are aligned with identified risks and the organization’s threat profile (THREAT-2e) to ensure coverage of identified risk categories and threats"},
	"RESPONSE-4n": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 3, "text": "Continuity plan exercises address higher priority risks"},
	"RESPONSE-4o": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 3, "text": "The results of continuity plan testing or activation are compared to recovery objectives, and plans are improved accordingly"},
	"RESPONSE-4p": {"domain": "RESPONSE", "objective": "RESPONSE-4", "mil": 3, "text": "Continuity plans are periodically reviewed and updated"},
	"RESPONSE-5a": {"domain": "RESPONSE", "objective": "RESPONSE-5", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the RESPONSE domain"},
	"RESPONSE-5b": {"domain": "RESPONSE", "objective": "RESPONSE-5", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the RESPONSE domain"},
	"RESPONSE-5c": {"domain": "RESPONSE", "objective": "RESPONSE-5", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the RESPONSE domain"},
	"RESPONSE-5d": {"domain": "RESPONSE", "objective": "RESPONSE-5", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the RESPONSE domain are assigned to personnel"},
	"RESPONSE-5e": {"domain": "RESPONSE", "objective": "RESPONSE-5", "mil": 3, "text": "Personnel performing activities in the RESPONSE domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"RESPONSE-5f": {"domain": "RESPONSE", "objective": "RESPONSE-5", "mil": 3, "text": "The effectiveness of activities in the RESPONSE domain is evaluated and tracked"},
	# ── THIRD-PARTIES — Third-Party Risk Management ──
	"THIRD-PARTIES-1a": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-1", "mil": 1, "text": "Important IT and OT third-party dependencies are identified (that is, internal and external parties on which the delivery of the function depends, including operating partners), at least in an ad hoc manner"},
	"THIRD-PARTIES-1b": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-1", "mil": 1, "text": "Third parties that have access to, control of, or custody of any IT, OT, or information assets that are important to the delivery of the function are identified, at least in an ad hoc manner"},
	"THIRD-PARTIES-1c": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-1", "mil": 2, "text": "A defined method is followed to identify risks arising from suppliers and other third parties"},
	"THIRD-PARTIES-1d": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-1", "mil": 2, "text": "Third parties are prioritized according to established criteria (for example, importance to the delivery of the function, impact of a compromise or disruption, ability to negotiate cybersecurity requirements within contracts)"},
	"THIRD-PARTIES-1e": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-1", "mil": 2, "text": "Escalated prioritization is assigned to suppliers and other third parties whose compromise or disruption could cause significant consequences (for example, single-source suppliers, suppliers with privileged access)"},
	"THIRD-PARTIES-1f": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-1", "mil": 3, "text": "Prioritization of suppliers and other third parties is updated periodically and according to defined triggers, such as system changes and external events"},
	"THIRD-PARTIES-2a": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 1, "text": "The selection of suppliers and other third parties includes consideration of their cybersecurity qualifications, at least in an ad hoc manner"},
	"THIRD-PARTIES-2b": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 1, "text": "The selection of products and services includes consideration of their cybersecurity capabilities, at least in an ad hoc manner"},
	"THIRD-PARTIES-2c": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 2, "text": "A defined method is followed to identify cybersecurity requirements and implement associated controls that protect against the risks arising from suppliers and other third parties"},
	"THIRD-PARTIES-2d": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 2, "text": "A defined method is followed to evaluate and select suppliers and other third parties"},
	"THIRD-PARTIES-2e": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 2, "text": "More rigorous cybersecurity controls are implemented for higher priority suppliers and other third parties"},
	"THIRD-PARTIES-2f": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 2, "text": "Cybersecurity requirements (for example, vulnerability notification, incident-related SLA requirements) are formalized in agreements with suppliers and other third parties"},
	"THIRD-PARTIES-2g": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 2, "text": "Suppliers and other third parties periodically attest to their ability to meet cybersecurity requirements"},
	"THIRD-PARTIES-2h": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 3, "text": "Cybersecurity requirements for suppliers and other third parties include secure software and secure product development requirements where appropriate"},
	"THIRD-PARTIES-2i": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 3, "text": "Selection criteria for products include consideration of end-of-life and end-of-support timelines"},
	"THIRD-PARTIES-2j": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 3, "text": "Selection criteria include consideration of safeguards against counterfeit or compromised software, hardware, and services"},
	"THIRD-PARTIES-2k": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 3, "text": "Selection criteria for higher priority assets include evaluation of bills of material for key asset elements, such as hardware and software"},
	"THIRD-PARTIES-2l": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 3, "text": "Selection criteria for higher priority assets include evaluation of any associated third-party hosting environments and source data"},
	"THIRD-PARTIES-2m": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-2", "mil": 3, "text": "Acceptance testing of procured assets includes consideration of cybersecurity requirements"},
	"THIRD-PARTIES-3a": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-3", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the THIRD-PARTIES domain"},
	"THIRD-PARTIES-3b": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-3", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the THIRD-PARTIES domain"},
	"THIRD-PARTIES-3c": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-3", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the THIRD-PARTIES domain"},
	"THIRD-PARTIES-3d": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-3", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the THIRD-PARTIES domain are assigned to personnel"},
	"THIRD-PARTIES-3e": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-3", "mil": 3, "text": "Personnel performing activities in the THIRD-PARTIES domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"THIRD-PARTIES-3f": {"domain": "THIRD-PARTIES", "objective": "THIRD-PARTIES-3", "mil": 3, "text": "The effectiveness of activities in the THIRD-PARTIES domain is evaluated and tracked"},
	# ── WORKFORCE — Workforce Management ──
	"WORKFORCE-1a": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 1, "text": "Personnel vetting (for example, background checks, drug tests) is performed at hire, at least in an ad hoc manner"},
	"WORKFORCE-1b": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 1, "text": "Personnel separation procedures address cybersecurity, at least in an ad hoc manner"},
	"WORKFORCE-1c": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 2, "text": "Personnel vetting is performed at hire and periodically for positions that have access to assets that are important to the delivery of the function"},
	"WORKFORCE-1d": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 2, "text": "Personnel separation and transfer procedures address cybersecurity, including supplementary vetting as appropriate"},
	"WORKFORCE-1e": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 2, "text": "Personnel are made aware of their responsibilities for protection and acceptable use of IT, OT, and information assets"},
	"WORKFORCE-1f": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 3, "text": "Vetting is performed for all positions (including employees, vendors, and contractors) at a level commensurate with position risk"},
	"WORKFORCE-1g": {"domain": "WORKFORCE", "objective": "WORKFORCE-1", "mil": 3, "text": "A formal accountability process that includes disciplinary actions is implemented for personnel who fail to comply with established security policies and procedures"},
	"WORKFORCE-2a": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 1, "text": "Cybersecurity awareness activities occur, at least in an ad hoc manner"},
	"WORKFORCE-2b": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 2, "text": "Cybersecurity awareness objectives are established and maintained"},
	"WORKFORCE-2c": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 2, "text": "Cybersecurity awareness objectives are aligned with the defined threat profile (THREAT-2e)"},
	"WORKFORCE-2d": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 2, "text": "Cybersecurity awareness activities are conducted periodically"},
	"WORKFORCE-2e": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 3, "text": "Cybersecurity awareness activities are tailored to job role"},
	"WORKFORCE-2f": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 3, "text": "Cybersecurity awareness activities address predefined states of operation (SITUATION-3g)"},
	"WORKFORCE-2g": {"domain": "WORKFORCE", "objective": "WORKFORCE-2", "mil": 3, "text": "The effectiveness of cybersecurity awareness activities is evaluated periodically and according to defined triggers, such as system changes and external events, and improvements are made as appropriate"},
	"WORKFORCE-3a": {"domain": "WORKFORCE", "objective": "WORKFORCE-3", "mil": 1, "text": "Cybersecurity responsibilities for the function are identified, at least in an ad hoc manner"},
	"WORKFORCE-3b": {"domain": "WORKFORCE", "objective": "WORKFORCE-3", "mil": 1, "text": "Cybersecurity responsibilities are assigned to specific people, at least in an ad hoc manner"},
	"WORKFORCE-3c": {"domain": "WORKFORCE", "objective": "WORKFORCE-3", "mil": 2, "text": "Cybersecurity responsibilities are assigned to specific roles, including external service providers"},
	"WORKFORCE-3d": {"domain": "WORKFORCE", "objective": "WORKFORCE-3", "mil": 2, "text": "Cybersecurity responsibilities are documented"},
	"WORKFORCE-3e": {"domain": "WORKFORCE", "objective": "WORKFORCE-3", "mil": 3, "text": "Cybersecurity responsibilities and job requirements are reviewed and updated periodically and according to defined triggers, such as system changes and changes to organizational structure"},
	"WORKFORCE-3f": {"domain": "WORKFORCE", "objective": "WORKFORCE-3", "mil": 3, "text": "Assigned cybersecurity responsibilities are managed to ensure adequacy and redundancy of coverage, including succession planning"},
	"WORKFORCE-4a": {"domain": "WORKFORCE", "objective": "WORKFORCE-4", "mil": 1, "text": "Cybersecurity training is made available to personnel with assigned cybersecurity responsibilities, at least in an ad hoc manner"},
	"WORKFORCE-4b": {"domain": "WORKFORCE", "objective": "WORKFORCE-4", "mil": 1, "text": "Cybersecurity knowledge, skill, and ability requirements and gaps are identified for both current and future operational needs, at least in an ad hoc manner"},
	"WORKFORCE-4c": {"domain": "WORKFORCE", "objective": "WORKFORCE-4", "mil": 2, "text": "Identified cybersecurity knowledge, skill, and ability gaps are addressed through training, recruiting, and retention efforts"},
	"WORKFORCE-4d": {"domain": "WORKFORCE", "objective": "WORKFORCE-4", "mil": 2, "text": "Cybersecurity training is provided as a prerequisite to granting access to assets that are important to the delivery of the function"},
	"WORKFORCE-4e": {"domain": "WORKFORCE", "objective": "WORKFORCE-4", "mil": 3, "text": "The effectiveness of training programs is evaluated periodically, and improvements are made as appropriate"},
	"WORKFORCE-4f": {"domain": "WORKFORCE", "objective": "WORKFORCE-4", "mil": 3, "text": "Training programs include continuing education and professional development opportunities for personnel with significant cybersecurity responsibilities"},
	"WORKFORCE-5a": {"domain": "WORKFORCE", "objective": "WORKFORCE-5", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the WORKFORCE domain"},
	"WORKFORCE-5b": {"domain": "WORKFORCE", "objective": "WORKFORCE-5", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the WORKFORCE domain"},
	"WORKFORCE-5c": {"domain": "WORKFORCE", "objective": "WORKFORCE-5", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the WORKFORCE domain"},
	"WORKFORCE-5d": {"domain": "WORKFORCE", "objective": "WORKFORCE-5", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the WORKFORCE domain are assigned to personnel"},
	"WORKFORCE-5e": {"domain": "WORKFORCE", "objective": "WORKFORCE-5", "mil": 3, "text": "Personnel performing activities in the WORKFORCE domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"WORKFORCE-5f": {"domain": "WORKFORCE", "objective": "WORKFORCE-5", "mil": 3, "text": "The effectiveness of activities in the WORKFORCE domain is evaluated and tracked"},
	# ── ARCHITECTURE — Cybersecurity Architecture ──
	"ARCHITECTURE-1a": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 1, "text": "The organization has a strategy for cybersecurity architecture, which may be developed and managed in an ad hoc manner"},
	"ARCHITECTURE-1b": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 2, "text": "A strategy for cybersecurity architecture is established and maintained in alignment with the organization’s cybersecurity program strategy (PROGRAM-1b) and enterprise architecture"},
	"ARCHITECTURE-1c": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 2, "text": "A documented cybersecurity architecture is established and maintained that includes IT and OT systems and networks and aligns with system and asset categorization and prioritization"},
	"ARCHITECTURE-1d": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 2, "text": "Governance for cybersecurity architecture (such as an architecture review process) is established and maintained that includes provisions for periodic architectural reviews and an exceptions process"},
	"ARCHITECTURE-1e": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 2, "text": "Senior management sponsorship for the cybersecurity architecture program is visible and active"},
	"ARCHITECTURE-1f": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 2, "text": "The cybersecurity architecture establishes and maintains cybersecurity requirements for the organization’s assets"},
	"ARCHITECTURE-1g": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 2, "text": "Cybersecurity controls are selected and implemented to meet cybersecurity requirements"},
	"ARCHITECTURE-1h": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 3, "text": "The cybersecurity architecture strategy and program are aligned with the organization’s enterprise architecture strategy and program"},
	"ARCHITECTURE-1i": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 3, "text": "Conformance of the organization’s systems and networks to the cybersecurity architecture is evaluated periodically and according to defined triggers, such as system changes and external events"},
	"ARCHITECTURE-1j": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 3, "text": "The cybersecurity architecture is guided by the organization’s risk analysis information (RISK-3d) and threat profile (THREAT-2e)"},
	"ARCHITECTURE-1k": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-1", "mil": 3, "text": "The cybersecurity architecture addresses predefined states of operation (SITUATION-3g)"},
	"ARCHITECTURE-2a": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 1, "text": "Network protections are implemented, at least in an ad hoc manner"},
	"ARCHITECTURE-2b": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 1, "text": "The organization’s IT systems are separated from OT systems through segmentation, either through physical means or logical means, at least in an ad hoc manner"},
	"ARCHITECTURE-2c": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 2, "text": "Network protections are defined and enforced for selected asset types according to asset risk and priority (for example, internal assets, perimeter assets, assets connected to the organization’s Wi-Fi, cloud assets, remote access, and externally owned devices)"},
	"ARCHITECTURE-2d": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 2, "text": "Assets that are important to the delivery of the function are logically or physically segmented into distinct security zones based on asset cybersecurity requirements"},
	"ARCHITECTURE-2e": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 2, "text": "Network protections incorporate the principles of least privilege and least functionality"},
	"ARCHITECTURE-2f": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 2, "text": "Network protections include monitoring, analysis, and control of network traffic for selected security zones (for example, firewalls, allowlisting, intrusion detection and prevention systems (IDPS))"},
	"ARCHITECTURE-2g": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 2, "text": "Web traffic and email are monitored, analyzed, and controlled (for example, malicious link blocking, suspicious download blocking, email authentication techniques, IP address blocking)"},
	"ARCHITECTURE-2h": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 3, "text": "All assets are segmented into distinct security zones based on cybersecurity requirements"},
	"ARCHITECTURE-2i": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 3, "text": "Separate networks are implemented, where warranted, that logically or physically segment assets into security zones with independent authentication"},
	"ARCHITECTURE-2j": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 3, "text": "OT systems are operationally independent from IT systems so that OT operations can be sustained during an outage of IT systems"},
	"ARCHITECTURE-2k": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 3, "text": "Device connections to the network are controlled to ensure that only authorized devices can connect (for example, network access control (NAC))"},
	"ARCHITECTURE-2l": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-2", "mil": 3, "text": "The cybersecurity architecture enables the isolation of compromised assets"},
	"ARCHITECTURE-3a": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 1, "text": "Logical and physical access controls are implemented to protect assets that are important to the delivery of the function, where feasible, at least in an ad hoc manner"},
	"ARCHITECTURE-3b": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 1, "text": "Endpoint protections (such as secure configuration, security applications, and host monitoring) are implemented to protect assets that are important to the delivery of the function, where feasible, at least in an ad hoc manner"},
	"ARCHITECTURE-3c": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "The principle of least privilege (for example, limiting administrative access for users and service accounts) is enforced"},
	"ARCHITECTURE-3d": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "The principle of least functionality (for example, limiting services, limiting applications, limiting ports, limiting connected devices) is enforced"},
	"ARCHITECTURE-3e": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "Secure configurations are established and maintained as part of the asset deployment process where feasible"},
	"ARCHITECTURE-3f": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "Security applications are required as an element of device configuration where feasible (for example, endpoint detection and response, host-based firewalls)"},
	"ARCHITECTURE-3g": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "The use of removeable media is controlled (for example, limiting the use of USB devices, managing external hard drives)"},
	"ARCHITECTURE-3h": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "Cybersecurity controls are implemented for all assets within the function either at the asset level or as compensating controls where asset-level controls are not feasible"},
	"ARCHITECTURE-3i": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "Maintenance and capacity management activities are performed for all assets within the function"},
	"ARCHITECTURE-3j": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "The physical operating environment is controlled to protect the operation of assets within the function"},
	"ARCHITECTURE-3k": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 2, "text": "More rigorous cybersecurity controls are implemented for higher priority assets"},
	"ARCHITECTURE-3l": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 3, "text": "Configuration of and changes to firmware are controlled throughout the asset lifecycle"},
	"ARCHITECTURE-3m": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-3", "mil": 3, "text": "Controls (such as allowlists, blocklists, and configuration settings) are implemented to prevent the execution of unauthorized code"},
	"ARCHITECTURE-4a": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 2, "text": "Software developed in-house for deployment on higher priority assets is developed using secure software development practices"},
	"ARCHITECTURE-4b": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 2, "text": "The selection of procured software for deployment on higher priority assets includes consideration of the vendor’s secure software development practices"},
	"ARCHITECTURE-4c": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 2, "text": "Secure software configurations are required as part of the software deployment process for both procured software and software developed in-house"},
	"ARCHITECTURE-4d": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 3, "text": "All software developed in-house is developed using secure software development practices"},
	"ARCHITECTURE-4e": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 3, "text": "The selection of all procured software includes consideration of the vendor’s secure software development practices"},
	"ARCHITECTURE-4f": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 3, "text": "The architecture review process evaluates the security of new and revised applications prior to deployment"},
	"ARCHITECTURE-4g": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 3, "text": "The authenticity of all software and firmware is validated prior to deployment"},
	"ARCHITECTURE-4h": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-4", "mil": 3, "text": "Security testing (for example, static testing, dynamic testing, fuzz testing, penetration testing) is performed for in-house-developed and in-house-tailored applications periodically and according to defined triggers, such as system changes and external events"},
	"ARCHITECTURE-5a": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 1, "text": "Sensitive data is protected at rest, at least in an ad hoc manner"},
	"ARCHITECTURE-5b": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 2, "text": "All data at rest is protected for selected data categories"},
	"ARCHITECTURE-5c": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 2, "text": "All data in transit is protected for selected data categories"},
	"ARCHITECTURE-5d": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 2, "text": "Cryptographic controls are implemented for data at rest and data in transit for selected data categories"},
	"ARCHITECTURE-5e": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 2, "text": "Key management infrastructure (that is, key generation, key storage, key destruction, key update, and key revocation) is implemented to support cryptographic controls"},
	"ARCHITECTURE-5f": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 2, "text": "Controls to restrict the exfiltration of data (for example, data loss prevention tools) are implemented"},
	"ARCHITECTURE-5g": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 3, "text": "The cybersecurity architecture includes protections (such as full disk encryption) for data that is stored on assets that may be lost or stolen"},
	"ARCHITECTURE-5h": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-5", "mil": 3, "text": "The cybersecurity architecture includes protections against unauthorized changes to software, firmware, and data"},
	"ARCHITECTURE-6a": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-6", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the ARCHITECTURE domain"},
	"ARCHITECTURE-6b": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-6", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the ARCHITECTURE domain"},
	"ARCHITECTURE-6c": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-6", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the ARCHITECTURE domain"},
	"ARCHITECTURE-6d": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-6", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the ARCHITECTURE domain are assigned to personnel"},
	"ARCHITECTURE-6e": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-6", "mil": 3, "text": "Personnel performing activities in the ARCHITECTURE domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"ARCHITECTURE-6f": {"domain": "ARCHITECTURE", "objective": "ARCHITECTURE-6", "mil": 3, "text": "The effectiveness of activities in the ARCHITECTURE domain is evaluated and tracked"},
	# ── PROGRAM — Cybersecurity Program Management ──
	"PROGRAM-1a": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 1, "text": "The organization has a cybersecurity program strategy, which may be developed and managed in an ad hoc manner"},
	"PROGRAM-1b": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 2, "text": "The cybersecurity program strategy defines goals and objectives for the organization’s cybersecurity activities"},
	"PROGRAM-1c": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 2, "text": "The cybersecurity program strategy and priorities are documented and aligned with the organization’s mission, strategic objectives, and risk to critical infrastructure"},
	"PROGRAM-1d": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 2, "text": "The cybersecurity program strategy defines the organization’s approach to provide program oversight and governance for cybersecurity activities"},
	"PROGRAM-1e": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 2, "text": "The cybersecurity program strategy defines the structure and organization of the cybersecurity program"},
	"PROGRAM-1f": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 2, "text": "The cybersecurity program strategy identifies standards and guidelines intended to be followed by the program"},
	"PROGRAM-1g": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 2, "text": "The cybersecurity program strategy identifies any applicable compliance requirements that must be satisfied by the program (for example, NERC CIP, TSA Pipeline Security Guidelines, PCI DSS, ISO, DoD CMMC)"},
	"PROGRAM-1h": {"domain": "PROGRAM", "objective": "PROGRAM-1", "mil": 3, "text": "The cybersecurity program strategy is updated periodically and according to defined triggers, such as business changes, changes in the operating environment, and changes in the threat profile (THREAT-2e)"},
	"PROGRAM-2a": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 1, "text": "Senior management with proper authority provides support for the cybersecurity program, at least in an ad hoc manner"},
	"PROGRAM-2b": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 2, "text": "The cybersecurity program is established according to the cybersecurity program strategy"},
	"PROGRAM-2c": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 2, "text": "Senior management sponsorship for the cybersecurity program is visible and active"},
	"PROGRAM-2d": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 2, "text": "Senior management sponsorship is provided for the development, maintenance, and enforcement of cybersecurity policies"},
	"PROGRAM-2e": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 2, "text": "Responsibility for the cybersecurity program is assigned to a role with sufficient authority"},
	"PROGRAM-2f": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 2, "text": "Stakeholders for cybersecurity program management activities are identified and involved"},
	"PROGRAM-2g": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 3, "text": "Cybersecurity program activities are periodically reviewed to ensure that they align with the cybersecurity program strategy"},
	"PROGRAM-2h": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 3, "text": "Cybersecurity activities are independently reviewed to ensure conformance with cybersecurity policies and procedures, periodically and according to defined triggers, such as process changes"},
	"PROGRAM-2i": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 3, "text": "The cybersecurity program addresses and enables the achievement of legal and regulatory compliance, as appropriate"},
	"PROGRAM-2j": {"domain": "PROGRAM", "objective": "PROGRAM-2", "mil": 3, "text": "The organization collaborates with external entities to contribute to the development and implementation of cybersecurity standards, guidelines, leading practices, lessons learned, and emerging technologies"},
	"PROGRAM-3a": {"domain": "PROGRAM", "objective": "PROGRAM-3", "mil": 2, "text": "Documented procedures are established, followed, and maintained for activities in the PROGRAM domain"},
	"PROGRAM-3b": {"domain": "PROGRAM", "objective": "PROGRAM-3", "mil": 2, "text": "Adequate resources (people, funding, and tools) are provided to support activities in the PROGRAM domain"},
	"PROGRAM-3c": {"domain": "PROGRAM", "objective": "PROGRAM-3", "mil": 3, "text": "Up-to-date policies or other organizational directives define requirements for activities in the PROGRAM domain"},
	"PROGRAM-3d": {"domain": "PROGRAM", "objective": "PROGRAM-3", "mil": 3, "text": "Responsibility, accountability, and authority for the performance of activities in the PROGRAM domain are assigned to personnel"},
	"PROGRAM-3e": {"domain": "PROGRAM", "objective": "PROGRAM-3", "mil": 3, "text": "Personnel performing activities in the PROGRAM domain have the skills and knowledge needed to perform their assigned responsibilities"},
	"PROGRAM-3f": {"domain": "PROGRAM", "objective": "PROGRAM-3", "mil": 3, "text": "The effectiveness of activities in the PROGRAM domain is evaluated and tracked"},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "c2m2", {})

_given := p if {
	p := _in.practices
	is_object(p)
}

_supplied if _given

_true(id) if _given[id] == true

_mils := {1, 2, 3}

_target_declared if "target_mil" in object.keys(_in)

_target_valid if {
	t := _in.target_mil
	is_number(t)
	t in _mils
}

target_mil := _in.target_mil if _target_valid

else := 3

applicable[id] := p if {
	some id, p in practices
	p.mil <= target_mil
}

violations contains "C2M2 V2.1: FAIL-CLOSED - practice attestations 'input.c2m2.practices' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, p in applicable
	not _true(id)
	msg := sprintf("C2M2 V2.1 %v (MIL%v, %v): not performed — %v", [id, p.mil, model_domains[p.domain], p.text])
}

violations contains msg if {
	some id, _ in _given
	not practices[id]
	msg := sprintf("C2M2 V2.1 Input Contract: unknown practice id %v — ids follow the model's notation such as ASSET-1a or THIRD-PARTIES-2k", [id])
}

violations contains msg if {
	_target_declared
	not _target_valid
	msg := sprintf("C2M2 V2.1 Input Contract: input.c2m2.target_mil must be 1, 2 or 3; got %v — MIL3 (all practices) is evaluated", [_in.target_mil])
}

_domain_ids(d) := {id | some id, p in practices; p.domain == d}

# a domain achieves MIL l when every one of its practices at MIL <= l is performed (each domain has MIL1 practices)
_mil_achieved(d, l) if {
	l in _mils
	ids := {id | some id in _domain_ids(d); practices[id].mil <= l}
	count(ids) > 0
	every id in ids { _true(id) }
}

domain_reports[d] := r if {
	some d, label in model_domains
	ids := {id | some id in _domain_ids(d); applicable[id]}
	r := {
		"name": label,
		"practices": count(_domain_ids(d)),
		"evaluated": count(ids),
		"performed": count({id | some id in ids; _true(id)}),
		"mil_achieved": max({l | some l in _mils; _mil_achieved(d, l)} | {0}),
		"gaps": sort([id | some id in ids; not _true(id)]),
	}
}

mil_reports[k] := r if {
	some l in _mils
	k := sprintf("MIL%v", [l])
	ids := {id | some id, p in practices; p.mil == l}
	r := {
		"practices": count(ids),
		"evaluated": l <= target_mil,
		"performed": count({id | some id in ids; _true(id)}),
		"domains_achieved": sort([d | some d, _ in model_domains; _mil_achieved(d, l)]),
	}
}

compliance_report := {
	"framework": "DOE Cybersecurity Capability Maturity Model (C2M2)",
	"standard": "C2M2 Version 2.1 (June 2022) — 356 practices in 10 domains",
	"source": source,
	"compliant": compliant,
	"standard_total": 356, # "The C2M2 includes 356 cybersecurity practices" (§4.1, p. 21)
	"target_mil": target_mil,
	"practices_evaluated": count(applicable),
	"practices_performed": count({id | some id, _ in applicable; _true(id)}),
	"domains": domain_reports,
	"mils": mil_reports,
	"violation_count": count(violations),
	"violations": violations,
}
