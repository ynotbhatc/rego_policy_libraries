# NIST Cybersecurity Framework (CSF) 2.0 — master module: all 106 current subcategories, decided by facts or attestation.
#
# Source of truth: NIST Cybersecurity and Privacy Reference Tool (CPRT) JSON export of CSF 2.0
# (doc_identifier CSF_2_0_0, "NIST Cybersecurity Framework Version 2.0", NIST CSWP 29),
#   https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/CSF_2_0_0/export/json?element=all
#   sha256 de36759d2f3f70a0f28ab9a95505259e568467923295a13d510a068939773e5a, retrieved 2026-10-13.
# NIST text is public domain. Every id and text string below is copied verbatim from that export by a generator;
# nothing is paraphrased. Parentage (function -> category -> subcategory -> implementation example) is taken from
# the export's `projection` relationships and agrees with the id spelling everywhere; order follows its `sort` elements.
#
# Measured in the export: 6 functions; 34 category elements, of which 22 are current and 12 are CSF 1.1 categories
# marked withdrawn; 185 subcategory elements, of which 106 are current and 79 are CSF 1.1 subcategories marked
# withdrawn; 363 implementation examples (all on current subcategories). Withdrawal is not a field on the element:
# CPRT links the withdrawn element by `projection` to a `withdraw_reason` element (91 of them) and records the
# destination with `incorporated_into` / `moved_to` relationships. Not carried: the 2 `party` elements (unlinked)
# and the 408 `external_reference` links to SP 800-53 (a crosswalk, which lives in crosswalk/, not here).
#
# Id scheme (exactly the CPRT element_identifier values):
#   function       GV, ID, PR, DE, RS, RC                                  (6)
#   category       GV.OC, ID.AM, PR.AA, …                                  (22 current; 12 withdrawn kept as data)
#   subcategory    GV.OC-01, ID.AM-01, PR.AA-01, …                         (106: the controls of this module)
#   example        GV.OC-01.001 (label Ex1)                                (363: data on each subcategory, not controls)
#   withdrawn      ID.BE-01, PR.AC-01, …                                   (79: data with CPRT's reason, never controls)
#
# Functions:
#   GV GOVERN     6 categories,  31 subcategories (1 facts, 30 attestation)
#   ID IDENTIFY   3 categories,  21 subcategories (9 facts, 12 attestation)
#   PR PROTECT    5 categories,  22 subcategories (9 facts, 13 attestation)
#   DE DETECT     2 categories,  11 subcategories (6 facts, 5 attestation)
#   RS RESPOND    4 categories,  13 subcategories (3 facts, 10 attestation)
#   RC RECOVER    2 categories,   8 subcategories (1 facts, 7 attestation)
#   total                   22 categories, 106 subcategories (29 facts, 77 attestation)
#
# Basis — how each subcategory is decided (reported per subcategory as `basis`):
#   facts         29  by the fact checks of the function modules (nist.csf.govern/identify/protect/detect/
#                     respond/recover), which read the collector facts under input.governance, input.identify,
#                     input.access_control, input.awareness_training, input.data_security,
#                     input.information_protection, input.detect, input.respond, input.recover. A facts
#                     subcategory is satisfied when its module emits no violation labelled with its id; every
#                     one of them fails on missing facts (tested), so absence is never a pass.
#   attestation   77  input.nist_csf.subcategories["GV.OC-01"] == true, the assessor's attestation.
# The fact checks were written against CSF 1.1. A check decides a 2.0 subcategory only when its id is current in
# CSF 2.0 and it tests that outcome, or CPRT records its 1.1 id as `moved_to` exactly one current subcategory and the
# check is a fair reading of that text
# (carried: RS.AN-05->ID.RA-08, PR.AC-06->PR.AA-02, PR.AC-07->PR.AA-03, PR.AC-04->PR.AA-05, PR.AC-02->PR.AA-06, PR.IP-04->PR.DS-11, PR.DS-04->PR.IR-04).
# The other legacy checks were removed; their lineage is each module's `legacy` table (merged in the report as
# `legacy_fact_checks`): 46 `retired` (1.1 id
# withdrawn and folded into a broader or several 2.0 outcomes) and 26 `unmapped` (current id, different outcome).
#
# Input contract: input.nist_csf.subcategories is an object of CSF 2.0 subcategory id -> true. Fail-closed: a missing
# or non-object container is a FAIL-CLOSED violation; an attestation-basis subcategory whose value is missing,
# false or not exactly true is a violation; an unknown id is a violation; a withdrawn CSF 1.1 id is a violation
# naming CPRT's withdraw reason. A value supplied for a facts-basis id is accepted and ignored: facts decide it.
#
# Query: POST /v1/data/nist/csf/main/compliance_report

# METADATA
# title: "NIST Cybersecurity Framework 2.0 — 106 subcategories (CPRT ids), facts or attestation"
# custom:
#   class: compliance
#   framework: nist_cybersecurity_framework_2_0
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 112
#     cited: 109
#     expected: 106
#     found: 138
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.csf.main

import rego.v1

import data.nist.csf.detect as de
import data.nist.csf.govern as gv
import data.nist.csf.identify as id_
import data.nist.csf.protect as pr
import data.nist.csf.recover as rc
import data.nist.csf.respond as rs

source := {
	"publication": "NIST Cybersecurity Framework (CSF) 2.0 (NIST CSWP 29)",
	"doc_identifier": "CSF_2_0_0",
	"version": "Version  2.0",
	"export_url": "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/CSF_2_0_0/export/json?element=all",
	"export_sha256": "de36759d2f3f70a0f28ab9a95505259e568467923295a13d510a068939773e5a",
	"retrieved": "2026-10-13",
}

# Functions, categories and withdrawn elements are rows of arrays (keyed objects are built from them below) so
# that only the 106 subcategories read as controls.
_function_rows := [
	{
		"function": "GV",
		"title": "GOVERN",
		"text": "The organization's cybersecurity risk management strategy, expectations, and policy are established, communicated, and monitored",
	},
	{
		"function": "ID",
		"title": "IDENTIFY",
		"text": "The organization's current cybersecurity risks are understood",
	},
	{
		"function": "PR",
		"title": "PROTECT",
		"text": "Safeguards to manage the organization's cybersecurity risks are used",
	},
	{
		"function": "DE",
		"title": "DETECT",
		"text": "Possible cybersecurity attacks and compromises are found and analyzed",
	},
	{
		"function": "RS",
		"title": "RESPOND",
		"text": "Actions regarding a detected cybersecurity incident are taken",
	},
	{
		"function": "RC",
		"title": "RECOVER",
		"text": "Assets and operations affected by a cybersecurity incident are restored",
	},
]

functions := {r.function: {"title": r.title, "text": r.text} | some r in _function_rows}

_category_rows := [
	{
		"category": "GV.OC",
		"function": "GV",
		"title": "Organizational Context",
		"text": "The circumstances - mission, stakeholder expectations, dependencies, and legal, regulatory, and contractual requirements - surrounding the organization's cybersecurity risk management decisions are understood",
	},
	{
		"category": "GV.RM",
		"function": "GV",
		"title": "Risk Management Strategy",
		"text": "The organization's priorities, constraints, risk tolerance and appetite statements, and assumptions are established, communicated, and used to support operational risk decisions",
	},
	{
		"category": "GV.RR",
		"function": "GV",
		"title": "Roles, Responsibilities, and Authorities",
		"text": "Cybersecurity roles, responsibilities, and authorities to foster accountability, performance assessment, and continuous improvement are established and communicated",
	},
	{
		"category": "GV.PO",
		"function": "GV",
		"title": "Policy",
		"text": "Organizational cybersecurity policy is established, communicated, and enforced",
	},
	{
		"category": "GV.OV",
		"function": "GV",
		"title": "Oversight",
		"text": "Results of organization-wide cybersecurity risk management activities and performance are used to inform, improve, and adjust the risk management strategy",
	},
	{
		"category": "GV.SC",
		"function": "GV",
		"title": "Cybersecurity Supply Chain Risk Management",
		"text": "Cyber supply chain risk management processes are identified, established, managed, monitored, and improved by organizational stakeholders",
	},
	{
		"category": "ID.AM",
		"function": "ID",
		"title": "Asset Management",
		"text": "Assets (e.g., data, hardware, software, systems, facilities, services, people) that enable the organization to achieve business purposes are identified and managed consistent with their relative importance to organizational objectives and the organization's risk strategy",
	},
	{
		"category": "ID.RA",
		"function": "ID",
		"title": "Risk Assessment",
		"text": "The cybersecurity risk to the organization, assets, and individuals is understood by the organization",
	},
	{
		"category": "ID.IM",
		"function": "ID",
		"title": "Improvement",
		"text": "Improvements to organizational cybersecurity risk management processes, procedures and activities are identified across all CSF Functions",
	},
	{
		"category": "PR.AA",
		"function": "PR",
		"title": "Identity Management, Authentication, and Access Control",
		"text": "Access to physical and logical assets is limited to authorized users, services, and hardware and  managed commensurate with the assessed risk of unauthorized access",
	},
	{
		"category": "PR.AT",
		"function": "PR",
		"title": "Awareness and Training",
		"text": "The organization's personnel are provided with cybersecurity awareness and training so that they can perform their cybersecurity-related tasks",
	},
	{
		"category": "PR.DS",
		"function": "PR",
		"title": "Data Security",
		"text": "Data are managed consistent with the organization's risk strategy to protect the confidentiality, integrity, and availability of information",
	},
	{
		"category": "PR.PS",
		"function": "PR",
		"title": "Platform Security",
		"text": "The hardware, software (e.g., firmware, operating systems, applications), and services of physical and virtual platforms are managed consistent with the organization's risk strategy to protect their confidentiality, integrity, and availability",
	},
	{
		"category": "PR.IR",
		"function": "PR",
		"title": "Technology Infrastructure Resilience",
		"text": "Security architectures are managed with the organization's risk strategy to protect asset confidentiality, integrity, and availability, and organizational resilience",
	},
	{
		"category": "DE.AE",
		"function": "DE",
		"title": "Adverse Event Analysis",
		"text": "Anomalies, indicators of compromise, and other potentially adverse events are analyzed to characterize the events and detect cybersecurity incidents",
	},
	{
		"category": "DE.CM",
		"function": "DE",
		"title": "Continuous Monitoring",
		"text": "Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events",
	},
	{
		"category": "RS.MA",
		"function": "RS",
		"title": "Incident Management",
		"text": "Responses to detected cybersecurity incidents are managed",
	},
	{
		"category": "RS.AN",
		"function": "RS",
		"title": "Incident Analysis",
		"text": "Investigations are conducted to ensure effective response and support forensics and recovery activities",
	},
	{
		"category": "RS.CO",
		"function": "RS",
		"title": "Incident Response Reporting and Communication",
		"text": "Response activities are coordinated with internal and external stakeholders as required by laws, regulations, or policies",
	},
	{
		"category": "RS.MI",
		"function": "RS",
		"title": "Incident Mitigation",
		"text": "Activities are performed to prevent expansion of an event and mitigate its effects",
	},
	{
		"category": "RC.RP",
		"function": "RC",
		"title": "Incident Recovery Plan Execution",
		"text": "Restoration activities are performed to ensure operational availability of systems and services affected by cybersecurity incidents",
	},
	{
		"category": "RC.CO",
		"function": "RC",
		"title": "Incident Recovery Communication",
		"text": "Restoration activities are coordinated with internal and external parties",
	},
]

categories := {r.category: {"function": r.function, "title": r.title, "text": r.text} | some r in _category_rows}

# CSF 1.1 categories withdrawn in CSF 2.0 (CPRT withdraw_reason, verbatim).
_withdrawn_category_rows := [
	{
		"category": "ID.BE",
		"title": "Business Environment",
		"reason": "Incorporated into GV.OC",
		"incorporated_into": ["GV.OC"],
		"moved_to": [],
	},
	{
		"category": "ID.GV",
		"title": "Governance",
		"reason": "Incorporated into GV",
		"incorporated_into": ["GV"],
		"moved_to": [],
	},
	{
		"category": "ID.RM",
		"title": "Risk Management Strategy",
		"reason": "Incorporated into GV.RM",
		"incorporated_into": ["GV.RM"],
		"moved_to": [],
	},
	{
		"category": "ID.SC",
		"title": "Supply Chain Risk Management",
		"reason": "Incorporated into GV.SC",
		"incorporated_into": ["GV.SC"],
		"moved_to": [],
	},
	{
		"category": "PR.AC",
		"title": "Identity Management, Authentication and Access Control",
		"reason": "Moved to PR.AA",
		"incorporated_into": [],
		"moved_to": ["PR.AA"],
	},
	{
		"category": "PR.IP",
		"title": "Information Protection Processes and Procedures",
		"reason": "Incorporated into other Categories and Functions",
		"incorporated_into": [],
		"moved_to": [],
	},
	{
		"category": "PR.MA",
		"title": "Maintenance",
		"reason": "Incorporated into ID.AM-08",
		"incorporated_into": ["ID.AM-08"],
		"moved_to": [],
	},
	{
		"category": "PR.PT",
		"title": "Protective Technology",
		"reason": "Incorporated into other Protect Categories",
		"incorporated_into": [],
		"moved_to": [],
	},
	{
		"category": "DE.DP",
		"title": "Detection Processes",
		"reason": "Incorporated into other Categories and Functions",
		"incorporated_into": [],
		"moved_to": [],
	},
	{
		"category": "RS.RP",
		"title": "Response Planning",
		"reason": "Incorporated into RS.MA",
		"incorporated_into": [],
		"moved_to": [],
	},
	{
		"category": "RS.IM",
		"title": "Improvements",
		"reason": "Incorporated into ID.IM",
		"incorporated_into": ["ID.IM"],
		"moved_to": [],
	},
	{
		"category": "RC.IM",
		"title": "Improvements",
		"reason": "Incorporated into ID.IM",
		"incorporated_into": ["ID.IM"],
		"moved_to": [],
	},
]

withdrawn_categories := {r.category: object.remove(r, ["category"]) | some r in _withdrawn_category_rows}

# CSF 1.1 subcategories withdrawn in CSF 2.0 (CPRT withdraw_reason, verbatim). Never controls; an attestation
# for one of these ids is a violation.
_withdrawn_rows := [
	{
		"subcategory": "ID.AM-06",
		"text": "Cybersecurity roles and responsibilities for the entire workforce and third-party stakeholders (e.g., suppliers, customers, partners) are established",
		"reason": "Incorporated into GV.RR-02, GV.SC-02",
		"incorporated_into": ["GV.RR-02", "GV.SC-02"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.BE-01",
		"text": "The organization’s role in the supply chain is identified and communicated",
		"reason": "Incorporated into GV.OC-05",
		"incorporated_into": ["GV.OC-05"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.BE-02",
		"text": "The organization’s place in critical infrastructure and its industry sector is identified and communicated",
		"reason": "Incorporated into GV.OC-01",
		"incorporated_into": ["GV.OC-01"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.BE-03",
		"text": "Priorities for organizational mission, objectives, and activities are established and communicated",
		"reason": "Incorporated into GV.OC-01",
		"incorporated_into": ["GV.OC-01"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.BE-04",
		"text": "Dependencies and critical functions for delivery of critical services are established",
		"reason": "Incorporated into GV.OC-04, GV.OC-05",
		"incorporated_into": ["GV.OC-04", "GV.OC-05"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.BE-05",
		"text": "Resilience requirements to support delivery of critical services are established for all operating states (e.g. under duress/attack, during recovery, normal operations)",
		"reason": "Incorporated into GV.OC-04",
		"incorporated_into": ["GV.OC-04"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.GV-01",
		"text": "Organizational cybersecurity policy is established and communicated",
		"reason": "Incorporated into GV.PO, GV.PO-01, GV.PO-02",
		"incorporated_into": ["GV.PO", "GV.PO-01", "GV.PO-02"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.GV-02",
		"text": "Cybersecurity roles and responsibilities are coordinated and aligned with internal roles and external partners",
		"reason": "Incorporated into GV.OC-02, GV.RR, GV.RR-02",
		"incorporated_into": ["GV.OC-02", "GV.RR", "GV.RR-02"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.GV-03",
		"text": "Legal and regulatory requirements regarding cybersecurity, including privacy and civil liberties obligations, are understood and managed",
		"reason": "Moved to GV.OC-03",
		"incorporated_into": [],
		"moved_to": ["GV.OC-03"],
	},
	{
		"subcategory": "ID.GV-04",
		"text": "Governance and risk management processes address cybersecurity risks",
		"reason": "Moved to GV.RM-04",
		"incorporated_into": [],
		"moved_to": ["GV.RM-04"],
	},
	{
		"subcategory": "ID.RM-01",
		"text": "Risk management processes are established, managed, and agreed to by organizational stakeholders",
		"reason": "Incorporated into GV.RM-01, GV.RM-06, GV.RR-03",
		"incorporated_into": ["GV.RM-01", "GV.RM-06", "GV.RR-03"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.RM-02",
		"text": "Organizational risk tolerance is determined and clearly expressed",
		"reason": "Incorporated into GV.RM-02, GV.RM-04",
		"incorporated_into": ["GV.RM-02", "GV.RM-04"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.RM-03",
		"text": "The organization’s determination of risk tolerance is informed by its role in critical infrastructure and sector specific risk analysis",
		"reason": "Moved into GV.RM-02",
		"incorporated_into": [],
		"moved_to": ["GV.RM-02"],
	},
	{
		"subcategory": "ID.SC-01",
		"text": "Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders",
		"reason": "Incorporated into GV.RM-05, GV.SC-01, GV.SC-06, GV.SC-09, GV.SC-10",
		"incorporated_into": ["GV.RM-05", "GV.SC-01", "GV.SC-06", "GV.SC-09", "GV.SC-10"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.SC-02",
		"text": "Suppliers and third party partners of information systems, components, and services are identified, prioritized, and assessed using a cyber supply chain risk assessment process",
		"reason": "Incorporated into GV.OC-02, GV.SC-03, GV.SC-04, GV.SC-07, ID.RA-10",
		"incorporated_into": ["GV.OC-02", "GV.SC-03", "GV.SC-04", "GV.SC-07", "ID.RA-10"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.SC-03",
		"text": "Contracts with suppliers and third-party partners are used to implement appropriate measures designed to meet the objectives of an organization’s cybersecurity program and Cyber Supply Chain Risk Management Plan.",
		"reason": "Moved to GV.SC-05",
		"incorporated_into": [],
		"moved_to": ["GV.SC-05"],
	},
	{
		"subcategory": "ID.SC-04",
		"text": "Suppliers and third-party partners are routinely assessed using audits, test results, or other forms of evaluations to confirm they are meeting their contractual obligations.",
		"reason": "Incorporated into GV.SC-07, ID.RA-10",
		"incorporated_into": ["GV.SC-07", "ID.RA-10"],
		"moved_to": [],
	},
	{
		"subcategory": "ID.SC-05",
		"text": "Response and recovery planning and testing are conducted with suppliers and third-party providers",
		"reason": "Incorporated into GV.SC-08, ID.IM-02",
		"incorporated_into": ["GV.SC-08", "ID.IM-02"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.AC-01",
		"text": "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
		"reason": "Incorporated into PR.AA-01, PR.AA-05",
		"incorporated_into": ["PR.AA-01", "PR.AA-05"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.AC-02",
		"text": "Physical access to assets is managed and protected",
		"reason": "Moved to PR.AA-06",
		"incorporated_into": [],
		"moved_to": ["PR.AA-06"],
	},
	{
		"subcategory": "PR.AC-03",
		"text": "Remote access is managed",
		"reason": "Incorporated into PR.AA-03, PR.AA-05, PR.IR-01",
		"incorporated_into": ["PR.AA-03", "PR.AA-05", "PR.IR-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.AC-04",
		"text": "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties",
		"reason": "Moved to PR.AA-05",
		"incorporated_into": [],
		"moved_to": ["PR.AA-05"],
	},
	{
		"subcategory": "PR.AC-05",
		"text": "Network integrity is protected (e.g., network segregation, network segmentation)",
		"reason": "Incorporated into PR.IR-01",
		"incorporated_into": ["PR.IR-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.AC-06",
		"text": "Identities are proofed and bound to credentials and asserted in interactions",
		"reason": "Moved to PR.AA-02",
		"incorporated_into": [],
		"moved_to": ["PR.AA-02"],
	},
	{
		"subcategory": "PR.AC-07",
		"text": "Users, devices, and other assets are authenticated (e.g., single-factor, multi-factor) commensurate with the risk of the transaction (e.g., individuals’ security and privacy risks and other organizational risks)",
		"reason": "Moved to PR.AA-03",
		"incorporated_into": [],
		"moved_to": ["PR.AA-03"],
	},
	{
		"subcategory": "PR.AT-03",
		"text": "Third-party stakeholders (e.g., suppliers, customers, partners) understand their roles and responsibilities",
		"reason": "Incorporated into PR.AT-01, PR.AT-02",
		"incorporated_into": ["PR.AT-01", "PR.AT-02"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.AT-04",
		"text": "Senior executives understand their roles and responsibilities",
		"reason": "Incorporated into PR.AT-02",
		"incorporated_into": ["PR.AT-02"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.AT-05",
		"text": "Physical and cybersecurity personnel understand their roles and responsibilities",
		"reason": "Incorporated into PR.AT-02",
		"incorporated_into": ["PR.AT-02"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.DS-03",
		"text": "Assets are formally managed throughout removal, transfers, and disposition",
		"reason": "Incorporated into ID.AM-08, PR.PS-03",
		"incorporated_into": ["ID.AM-08", "PR.PS-03"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.DS-04",
		"text": "Adequate capacity to ensure availability is maintained",
		"reason": "Moved to PR.IR-04",
		"incorporated_into": [],
		"moved_to": ["PR.IR-04"],
	},
	{
		"subcategory": "PR.DS-05",
		"text": "Protections against data leaks are implemented",
		"reason": "Incorporated into PR.DS-01, PR.DS-02, PR.DS-10",
		"incorporated_into": ["PR.DS-01", "PR.DS-02", "PR.DS-10"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.DS-06",
		"text": "Integrity checking mechanisms are used to verify software, firmware, and information integrity",
		"reason": "Incorporated into PR.DS-01, DE.CM-09",
		"incorporated_into": ["PR.DS-01", "DE.CM-09"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.DS-07",
		"text": "The development and testing environment(s) are separate from the production environment",
		"reason": "Incorporated into PR.IR-01",
		"incorporated_into": ["PR.IR-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.DS-08",
		"text": "Integrity checking mechanisms are used to verify hardware integrity",
		"reason": "Incorporated into ID.RA-09, DE.CM-09",
		"incorporated_into": ["ID.RA-09", "DE.CM-09"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-01",
		"text": "A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles (e.g. concept of least functionality)",
		"reason": "Incorporated into PR.PS-01",
		"incorporated_into": ["PR.PS-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-02",
		"text": "A System Development Life Cycle to manage systems is implemented",
		"reason": "Incorporated into ID.AM-08, PR.PS-06",
		"incorporated_into": ["ID.AM-08", "PR.PS-06"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-03",
		"text": "Configuration change control processes are in place",
		"reason": "Incorporated into PR.PS-01, ID.RA-07",
		"incorporated_into": ["PR.PS-01", "ID.RA-07"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-04",
		"text": "Backups of information are conducted, maintained, and tested",
		"reason": "Moved to PR.DS-11",
		"incorporated_into": [],
		"moved_to": ["PR.DS-11"],
	},
	{
		"subcategory": "PR.IP-05",
		"text": "Policy and regulations regarding the physical operating environment for organizational assets are met",
		"reason": "Moved to PR.IR-02",
		"incorporated_into": ["PR.IR-02"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-06",
		"text": "Data is destroyed according to policy",
		"reason": "Incorporated into ID.AM-08",
		"incorporated_into": ["ID.AM-08"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-07",
		"text": "Protection processes are improved",
		"reason": "Incorporated into ID.IM, ID.IM-03",
		"incorporated_into": ["ID.IM", "ID.IM-03"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.IP-08",
		"text": "Effectiveness of protection technologies is shared",
		"reason": "Moved to ID.IM-03",
		"incorporated_into": [],
		"moved_to": ["ID.IM-03"],
	},
	{
		"subcategory": "PR.IP-09",
		"text": "Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed",
		"reason": "Moved to ID.IM-04",
		"incorporated_into": [],
		"moved_to": ["ID.IM-04"],
	},
	{
		"subcategory": "PR.IP-10",
		"text": "Response and recovery plans are tested",
		"reason": "Incorporated into ID.IM-02, ID.IM-04",
		"incorporated_into": [],
		"moved_to": ["ID.IM-02", "ID.IM-04"],
	},
	{
		"subcategory": "PR.IP-11",
		"text": "Cybersecurity is included in human resources practices (e.g., deprovisioning, personnel screening)",
		"reason": "Moved to GV.RR-04",
		"incorporated_into": [],
		"moved_to": ["GV.RR-04"],
	},
	{
		"subcategory": "PR.IP-12",
		"text": "A vulnerability management plan is developed and implemented",
		"reason": "Incorporated into ID.RA-01, PR.PS-02",
		"incorporated_into": [],
		"moved_to": ["ID.RA-01", "PR.PS-02"],
	},
	{
		"subcategory": "PR.MA-01",
		"text": "Maintenance and repair of organizational assets are performed and logged, with approved and controlled tools",
		"reason": "Incorporated into ID.AM-08, PR.PS-03",
		"incorporated_into": [],
		"moved_to": ["ID.AM-08", "PR.PS-03"],
	},
	{
		"subcategory": "PR.MA-02",
		"text": "Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access",
		"reason": "Incorporated into ID.AM-08, PR.PS-02",
		"incorporated_into": [],
		"moved_to": ["ID.AM-08", "PR.PS-02"],
	},
	{
		"subcategory": "PR.PT-01",
		"text": "Audit/log records are determined, documented, implemented, and reviewed in accordance with policy",
		"reason": "Incorporated into PR.PS-04",
		"incorporated_into": ["PR.PS-04"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.PT-02",
		"text": "Removable media is protected and its use restricted according to policy",
		"reason": "Incorporated into PR.DS-01, PR.PS-01",
		"incorporated_into": ["PR.DS-01", "PR.PS-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.PT-03",
		"text": "The principle of least functionality is incorporated by configuring systems to provide only essential capabilities",
		"reason": "Incorporated into PR.PS-01",
		"incorporated_into": ["PR.PS-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.PT-04",
		"text": "Communications and control networks are protected",
		"reason": "Incorporated into PR.AA-06, PR.IR-01",
		"incorporated_into": ["PR.AA-06", "PR.IR-01"],
		"moved_to": [],
	},
	{
		"subcategory": "PR.PT-05",
		"text": "Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve resilience requirements in normal and adverse situations",
		"reason": "Moved to PR.IR-03",
		"incorporated_into": ["PR.IR-03"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.AE-01",
		"text": "A baseline of network operations and expected data flows for users and systems is established and managed",
		"reason": "Incorporated into ID.AM-03",
		"incorporated_into": ["ID.AM-03"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.AE-05",
		"text": "Incident alert thresholds are established",
		"reason": "Moved to DE.AE-08",
		"incorporated_into": [],
		"moved_to": ["DE.AE-08"],
	},
	{
		"subcategory": "DE.CM-04",
		"text": "Malicious code is detected",
		"reason": "Incorporated into DE.CM-01, DE.CM-09",
		"incorporated_into": ["DE.CM-01", "DE.CM-09"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.CM-05",
		"text": "Unauthorized mobile code is detected",
		"reason": "Incorporated into DE.CM-01, DE.CM-09",
		"incorporated_into": ["DE.CM-01", "DE.CM-09"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.CM-07",
		"text": "Monitoring for unauthorized personnel, connections, devices, and software is performed",
		"reason": "Incorporated into DE.CM-01, DE.CM-03, DE.CM-06, DE.CM-09",
		"incorporated_into": ["DE.CM-01", "DE.CM-03", "DE.CM-06", "DE.CM-09"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.CM-08",
		"text": "Vulnerability scans are performed",
		"reason": "Incorporated into ID.RA-01",
		"incorporated_into": ["ID.RA-01"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.DP-01",
		"text": "Roles and responsibilities for detection are well defined to ensure accountability",
		"reason": "Incorporated into GV.RR-02",
		"incorporated_into": ["GV.RR-02"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.DP-02",
		"text": "Detection activities comply with all applicable requirements",
		"reason": "Incorporated into DE.AE",
		"incorporated_into": ["DE.AE"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.DP-03",
		"text": "Detection processes are tested",
		"reason": "Incorporated into ID.IM-02",
		"incorporated_into": ["ID.IM-02"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.DP-04",
		"text": "Event detection information is communicated",
		"reason": "Incorporated into DE.AE-06",
		"incorporated_into": ["DE.AE-06"],
		"moved_to": [],
	},
	{
		"subcategory": "DE.DP-05",
		"text": "Detection processes are continuously improved",
		"reason": "Incorporated into ID.IM, ID.IM-03",
		"incorporated_into": ["ID.IM", "ID.IM-03"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.RP-01",
		"text": "Response plan is executed during or after an incident",
		"reason": "Incorporated into RS.MA-01",
		"incorporated_into": ["RS.MA-01"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.AN-01",
		"text": "Notifications from detection systems are investigated",
		"reason": "Incorporated into RS.MA-02",
		"incorporated_into": ["RS.MA-02"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.AN-02",
		"text": "The impact of the incident is understood",
		"reason": "Incorporated into RS.MA-02, RS.MA-03, RS.MA-04",
		"incorporated_into": ["RS.MA-02", "RS.MA-03", "RS.MA-04"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.AN-04",
		"text": "Incidents are categorized consistent with response plans",
		"reason": "Moved to RS.MA-03",
		"incorporated_into": [],
		"moved_to": ["RS.MA-03"],
	},
	{
		"subcategory": "RS.AN-05",
		"text": "Processes are established to receive, analyze and respond to vulnerabilities disclosed to the organization from internal and external sources (e.g. internal testing, security bulletins, or security researchers)",
		"reason": "Moved to ID.RA-08",
		"incorporated_into": [],
		"moved_to": ["ID.RA-08"],
	},
	{
		"subcategory": "RS.CO-01",
		"text": "Personnel know their roles and order of operations when a response is needed",
		"reason": "Incorporated into PR.AT-01",
		"incorporated_into": ["PR.AT-01"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.CO-04",
		"text": "Coordination with stakeholders occurs consistent with response plans",
		"reason": "Incorporated into RS.MA-01, RS.MA-04",
		"incorporated_into": ["RS.MA-01", "RS.MA-04"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.CO-05",
		"text": "Voluntary information sharing occurs with external stakeholders to achieve broader cybersecurity situational awareness",
		"reason": "Incorporated into RS.CO-03",
		"incorporated_into": ["RS.CO-03"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.MI-03",
		"text": "Newly identified vulnerabilities are mitigated or documented as accepted risks",
		"reason": "Incorporated into ID.RA-06",
		"incorporated_into": ["ID.RA-06"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.IM-01",
		"text": "Response plans incorporate lessons learned",
		"reason": "Incorporated into ID.IM-03, ID.IM-04",
		"incorporated_into": ["ID.IM-03", "ID.IM-04"],
		"moved_to": [],
	},
	{
		"subcategory": "RS.IM-02",
		"text": "Response strategies are updated",
		"reason": "Incorporated into ID.IM-03",
		"incorporated_into": ["ID.IM-03"],
		"moved_to": [],
	},
	{
		"subcategory": "RC.CO-01",
		"text": "Public relations are managed",
		"reason": "Incorporated into RC.CO-04",
		"incorporated_into": ["RC.CO-04"],
		"moved_to": [],
	},
	{
		"subcategory": "RC.IM-01",
		"text": "Recovery plans incorporate lessons learned",
		"reason": "Incorporated into ID.IM-03, ID.IM-04",
		"incorporated_into": ["ID.IM-03", "ID.IM-04"],
		"moved_to": [],
	},
	{
		"subcategory": "RC.CO-02",
		"text": "Reputation is repaired after an incident",
		"reason": "Incorporated into RC.CO-04",
		"incorporated_into": ["RC.CO-04"],
		"moved_to": [],
	},
	{
		"subcategory": "RC.IM-02",
		"text": "Recovery strategies are updated",
		"reason": "Incorporated into ID.IM-03",
		"incorporated_into": ["ID.IM-03"],
		"moved_to": [],
	},
]

withdrawn := {r.subcategory: object.remove(r, ["subcategory"]) | some r in _withdrawn_rows}

# The 106 current CSF 2.0 subcategories. basis "facts": decided by fact_package; "attestation": by
# input.nist_csf.subcategories[id]. examples: CPRT implementation examples, data only.
subcategories := {
	"GV.OC-01": {
		"function": "GV",
		"category": "GV.OC",
		"text": "The organizational mission is understood and informs cybersecurity risk management",
		"basis": "attestation",
		"examples": [{"ref": "GV.OC-01.001", "label": "Ex1", "text": "Share the organization's mission (e.g., through vision and mission statements, marketing, and service strategies) to provide a basis for identifying risks that may impede that mission"}],
	},
	"GV.OC-02": {
		"function": "GV",
		"category": "GV.OC",
		"text": "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OC-02.002", "label": "Ex1", "text": "Identify relevant internal stakeholders and their cybersecurity-related expectations (e.g., performance and risk expectations of officers, directors, and advisors; cultural expectations of employees)"},
			{"ref": "GV.OC-02.003", "label": "Ex2", "text": "Identify relevant external stakeholders and their cybersecurity-related expectations (e.g., privacy expectations of customers, business expectations of partnerships, compliance expectations of regulators, ethics expectations of society)"},
		],
	},
	"GV.OC-03": {
		"function": "GV",
		"category": "GV.OC",
		"text": "Legal, regulatory, and contractual requirements regarding cybersecurity - including privacy and civil liberties obligations - are understood and managed",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OC-03.004", "label": "Ex1", "text": "Determine a process to track and manage legal and regulatory requirements regarding protection of individuals' information (e.g., Health Insurance Portability and Accountability Act, California Consumer Privacy Act, General Data Protection Regulation)"},
			{"ref": "GV.OC-03.005", "label": "Ex2", "text": "Determine a process to track and manage contractual requirements for cybersecurity management of supplier, customer, and partner information"},
			{"ref": "GV.OC-03.006", "label": "Ex3", "text": "Align the organization's cybersecurity strategy with legal, regulatory, and contractual requirements"},
		],
	},
	"GV.OC-04": {
		"function": "GV",
		"category": "GV.OC",
		"text": "Critical objectives, capabilities, and services that external stakeholders depend on or expect from the organization are understood and communicated",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OC-04.007", "label": "Ex1", "text": "Establish criteria for determining the criticality of capabilities and services as viewed by internal and external stakeholders"},
			{"ref": "GV.OC-04.008", "label": "Ex2", "text": "Determine (e.g., from a business impact analysis) assets and business operations that are vital to achieving mission objectives and the potential impact of a loss (or partial loss) of such operations"},
			{"ref": "GV.OC-04.009", "label": "Ex3", "text": "Establish and communicate resilience objectives (e.g., recovery time objectives) for delivering critical capabilities and services in various operating states (e.g., under attack, during recovery, normal operation)"},
		],
	},
	"GV.OC-05": {
		"function": "GV",
		"category": "GV.OC",
		"text": "Outcomes, capabilities, and services that the organization depends on are understood and communicated",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OC-05.010", "label": "Ex1", "text": "Create an inventory of the organization's dependencies on external resources (e.g., facilities, cloud-based hosting providers) and their relationships to organizational assets and business functions"},
			{"ref": "GV.OC-05.011", "label": "Ex2", "text": "Identify and document external dependencies that are potential points of failure for the organization's critical capabilities and services, and share that information with appropriate personnel"},
		],
	},
	"GV.RM-01": {
		"function": "GV",
		"category": "GV.RM",
		"text": "Risk management objectives are established and agreed to by organizational stakeholders",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RM-01.012", "label": "Ex1", "text": "Update near-term and long-term cybersecurity risk management objectives as part of annual strategic planning and when major changes occur"},
			{"ref": "GV.RM-01.013", "label": "Ex2", "text": "Establish measurable objectives for cybersecurity risk management (e.g., manage the quality of user training, ensure adequate risk protection for industrial control systems)"},
			{"ref": "GV.RM-01.014", "label": "Ex3", "text": "Senior leaders agree about cybersecurity objectives and use them for measuring and managing risk and performance"},
		],
	},
	"GV.RM-02": {
		"function": "GV",
		"category": "GV.RM",
		"text": "Risk appetite and risk tolerance statements are established, communicated, and maintained",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RM-02.015", "label": "Ex1", "text": "Determine and communicate risk appetite statements that convey expectations about the appropriate level of risk for the organization"},
			{"ref": "GV.RM-02.016", "label": "Ex2", "text": "Translate risk appetite statements into specific, measurable, and broadly understandable risk tolerance statements"},
			{"ref": "GV.RM-02.017", "label": "Ex3", "text": "Refine organizational objectives and risk appetite periodically based on known risk exposure and residual risk"},
		],
	},
	"GV.RM-03": {
		"function": "GV",
		"category": "GV.RM",
		"text": "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RM-03.018", "label": "Ex1", "text": "Aggregate and manage cybersecurity risks alongside other enterprise risks (e.g., compliance, financial, operational, regulatory, reputational, safety)"},
			{"ref": "GV.RM-03.019", "label": "Ex2", "text": "Include cybersecurity risk managers in enterprise risk management planning"},
			{"ref": "GV.RM-03.020", "label": "Ex3", "text": "Establish criteria for escalating cybersecurity risks within enterprise risk management"},
		],
	},
	"GV.RM-04": {
		"function": "GV",
		"category": "GV.RM",
		"text": "Strategic direction that describes appropriate risk response options is established and communicated",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RM-04.021", "label": "Ex1", "text": "Specify criteria for accepting and avoiding cybersecurity risk for various classifications of data"},
			{"ref": "GV.RM-04.022", "label": "Ex2", "text": "Determine whether to purchase cybersecurity insurance"},
			{"ref": "GV.RM-04.023", "label": "Ex3", "text": "Document conditions under which shared responsibility models are acceptable (e.g., outsourcing certain cybersecurity functions, having a third party perform financial transactions on behalf of the organization, using public cloud-based services)"},
		],
	},
	"GV.RM-05": {
		"function": "GV",
		"category": "GV.RM",
		"text": "Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RM-05.024", "label": "Ex1", "text": "Determine how to update senior executives, directors, and management on the organization's cybersecurity posture at agreed-upon intervals"},
			{"ref": "GV.RM-05.025", "label": "Ex2", "text": "Identify how all departments across the organization - such as management, operations, internal auditors, legal, acquisition, physical security, and HR - will communicate with each other about cybersecurity risks"},
		],
	},
	"GV.RM-06": {
		"function": "GV",
		"category": "GV.RM",
		"text": "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated",
		"basis": "facts",
		"fact_package": "nist.csf.govern",
		"legacy_label": "GV.RM-06",
		"examples": [
			{"ref": "GV.RM-06.026", "label": "Ex1", "text": "Establish criteria for using a quantitative approach to cybersecurity risk analysis, and specify probability and exposure formulas"},
			{"ref": "GV.RM-06.027", "label": "Ex2", "text": "Create and use templates (e.g., a risk register) to document cybersecurity risk information (e.g., risk description, exposure, treatment, and ownership)"},
			{"ref": "GV.RM-06.028", "label": "Ex3", "text": "Establish criteria for risk prioritization at the appropriate levels within the enterprise"},
			{"ref": "GV.RM-06.029", "label": "Ex4", "text": "Use a consistent list of risk categories to support integrating, aggregating, and comparing cybersecurity risks"},
		],
	},
	"GV.RM-07": {
		"function": "GV",
		"category": "GV.RM",
		"text": "Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RM-07.030", "label": "Ex1", "text": "Define and communicate guidance and methods for identifying opportunities and including them in risk discussions (e.g., strengths, weaknesses, opportunities, and threats [SWOT] analysis)"},
			{"ref": "GV.RM-07.031", "label": "Ex2", "text": "Identify stretch goals and document them"},
			{"ref": "GV.RM-07.032", "label": "Ex3", "text": "Calculate, document, and prioritize positive risks alongside negative risks"},
		],
	},
	"GV.RR-01": {
		"function": "GV",
		"category": "GV.RR",
		"text": "Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RR-01.033", "label": "Ex1", "text": "Leaders (e.g., directors) agree on their roles and responsibilities in developing, implementing, and assessing the organization's cybersecurity strategy"},
			{"ref": "GV.RR-01.034", "label": "Ex2", "text": "Share leaders' expectations regarding a secure and ethical culture, especially when current events present the opportunity to highlight positive or negative examples of cybersecurity risk management"},
			{"ref": "GV.RR-01.035", "label": "Ex3", "text": "Leaders direct the CISO to maintain a comprehensive cybersecurity risk strategy and review and update it at least annually and after major events"},
			{"ref": "GV.RR-01.036", "label": "Ex4", "text": "Conduct reviews to ensure adequate authority and coordination among those responsible for managing cybersecurity risk"},
		],
	},
	"GV.RR-02": {
		"function": "GV",
		"category": "GV.RR",
		"text": "Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RR-02.037", "label": "Ex1", "text": "Document risk management roles and responsibilities in policy"},
			{"ref": "GV.RR-02.038", "label": "Ex2", "text": "Document who is responsible and accountable for cybersecurity risk management activities and how those teams and individuals are to be consulted and informed"},
			{"ref": "GV.RR-02.039", "label": "Ex3", "text": "Include cybersecurity responsibilities and performance requirements in personnel descriptions"},
			{"ref": "GV.RR-02.040", "label": "Ex4", "text": "Document performance goals for personnel with cybersecurity risk management responsibilities, and periodically measure performance to identify areas for improvement"},
			{"ref": "GV.RR-02.041", "label": "Ex5", "text": "Clearly articulate cybersecurity responsibilities within operations, risk functions, and internal audit functions"},
		],
	},
	"GV.RR-03": {
		"function": "GV",
		"category": "GV.RR",
		"text": "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RR-03.042", "label": "Ex1", "text": "Conduct periodic management reviews to ensure that those given cybersecurity risk management responsibilities have the necessary authority"},
			{"ref": "GV.RR-03.043", "label": "Ex2", "text": "Identify resource allocation and investment in line with risk tolerance and response"},
			{"ref": "GV.RR-03.044", "label": "Ex3", "text": "Provide adequate and sufficient people, process, and technical resources to support the cybersecurity strategy"},
		],
	},
	"GV.RR-04": {
		"function": "GV",
		"category": "GV.RR",
		"text": "Cybersecurity is included in human resources practices",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.RR-04.045", "label": "Ex1", "text": "Integrate cybersecurity risk management considerations into human resources processes (e.g., personnel screening, onboarding, change notification, offboarding)"},
			{"ref": "GV.RR-04.046", "label": "Ex2", "text": "Consider cybersecurity knowledge to be a positive factor in hiring, training, and retention decisions"},
			{"ref": "GV.RR-04.047", "label": "Ex3", "text": "Conduct background checks prior to onboarding new personnel for sensitive roles, and periodically repeat background checks for personnel with such roles"},
			{"ref": "GV.RR-04.048", "label": "Ex4", "text": "Define and enforce obligations for personnel to be aware of, adhere to, and uphold security policies as they relate to their roles"},
		],
	},
	"GV.PO-01": {
		"function": "GV",
		"category": "GV.PO",
		"text": "Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.PO-01.049", "label": "Ex1", "text": "Create, disseminate, and maintain an understandable, usable risk management policy with statements of management intent, expectations, and direction"},
			{"ref": "GV.PO-01.050", "label": "Ex2", "text": "Periodically review policy and supporting processes and procedures to ensure that they align with risk management strategy objectives and priorities, as well as the high-level direction of the cybersecurity policy"},
			{"ref": "GV.PO-01.051", "label": "Ex3", "text": "Require approval from senior management on policy"},
			{"ref": "GV.PO-01.052", "label": "Ex4", "text": "Communicate cybersecurity risk management policy and supporting processes and procedures across the organization"},
			{"ref": "GV.PO-01.053", "label": "Ex5", "text": "Require personnel to acknowledge receipt of policy when first hired, annually, and whenever policy is updated"},
		],
	},
	"GV.PO-02": {
		"function": "GV",
		"category": "GV.PO",
		"text": "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.PO-02.054", "label": "Ex1", "text": "Update policy based on periodic reviews of cybersecurity risk management results to ensure that policy and supporting processes and procedures adequately maintain risk at an acceptable level"},
			{"ref": "GV.PO-02.055", "label": "Ex2", "text": "Provide a timeline for reviewing changes to the organization's risk environment (e.g., changes in risk or in the organization's mission objectives), and communicate recommended policy updates"},
			{"ref": "GV.PO-02.056", "label": "Ex3", "text": "Update policy to reflect changes in legal and regulatory requirements"},
			{"ref": "GV.PO-02.057", "label": "Ex4", "text": "Update policy to reflect changes in technology (e.g., adoption of artificial intelligence) and changes to the business (e.g., acquisition of a new business, new contract requirements)"},
		],
	},
	"GV.OV-01": {
		"function": "GV",
		"category": "GV.OV",
		"text": "Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OV-01.058", "label": "Ex1", "text": "Measure how well the risk management strategy and risk results have helped leaders make decisions and achieve organizational objectives"},
			{"ref": "GV.OV-01.059", "label": "Ex2", "text": "Examine whether cybersecurity risk strategies that impede operations or innovation should be adjusted"},
		],
	},
	"GV.OV-02": {
		"function": "GV",
		"category": "GV.OV",
		"text": "The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OV-02.060", "label": "Ex1", "text": "Review audit findings to confirm whether the existing cybersecurity strategy has ensured compliance with internal and external requirements"},
			{"ref": "GV.OV-02.061", "label": "Ex2", "text": "Review the performance oversight of those in cybersecurity-related roles to determine whether policy changes are necessary"},
			{"ref": "GV.OV-02.062", "label": "Ex3", "text": "Review strategy in light of cybersecurity incidents"},
		],
	},
	"GV.OV-03": {
		"function": "GV",
		"category": "GV.OV",
		"text": "Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.OV-03.063", "label": "Ex1", "text": "Review key performance indicators (KPIs) to ensure that organization-wide policies and procedures achieve objectives"},
			{"ref": "GV.OV-03.064", "label": "Ex2", "text": "Review key risk indicators (KRIs) to identify risks the organization faces, including likelihood and potential impact"},
			{"ref": "GV.OV-03.065", "label": "Ex3", "text": "Collect and communicate metrics on cybersecurity risk management with senior leadership"},
		],
	},
	"GV.SC-01": {
		"function": "GV",
		"category": "GV.SC",
		"text": "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-01.066", "label": "Ex1", "text": "Establish a strategy that expresses the objectives of the cybersecurity supply chain risk management program"},
			{"ref": "GV.SC-01.067", "label": "Ex2", "text": "Develop the cybersecurity supply chain risk management program, including a plan (with milestones), policies, and procedures that guide implementation and improvement of the program, and share the policies and procedures with the organizational stakeholders"},
			{"ref": "GV.SC-01.068", "label": "Ex3", "text": "Develop and implement program processes based on the strategy, objectives, policies, and procedures that are agreed upon and performed by the organizational stakeholders"},
			{"ref": "GV.SC-01.069", "label": "Ex4", "text": "Establish a cross-organizational mechanism that ensures alignment between functions that contribute to cybersecurity supply chain risk management, such as cybersecurity, IT, operations, legal, human resources, and engineering"},
		],
	},
	"GV.SC-02": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-02.070", "label": "Ex1", "text": "Identify one or more specific roles or positions that will be responsible and accountable for planning, resourcing, and executing cybersecurity supply chain risk management activities"},
			{"ref": "GV.SC-02.071", "label": "Ex2", "text": "Document cybersecurity supply chain risk management roles and responsibilities in policy"},
			{"ref": "GV.SC-02.072", "label": "Ex3", "text": "Create responsibility matrixes to document who will be responsible and accountable for cybersecurity supply chain risk management activities and how those teams and individuals will be consulted and informed"},
			{"ref": "GV.SC-02.073", "label": "Ex4", "text": "Include cybersecurity supply chain risk management responsibilities and performance requirements in personnel descriptions to ensure clarity and improve accountability"},
			{"ref": "GV.SC-02.074", "label": "Ex5", "text": "Document performance goals for personnel with cybersecurity risk management-specific responsibilities, and periodically measure them to demonstrate and improve performance"},
			{"ref": "GV.SC-02.075", "label": "Ex6", "text": "Develop roles and responsibilities for suppliers, customers, and business partners to address shared responsibilities for applicable cybersecurity risks, and integrate them into organizational policies and applicable third-party agreements"},
			{"ref": "GV.SC-02.076", "label": "Ex7", "text": "Internally communicate cybersecurity supply chain risk management roles and responsibilities for third parties"},
			{"ref": "GV.SC-02.077", "label": "Ex8", "text": "Establish rules and protocols for information sharing and reporting processes between the organization and its suppliers"},
		],
	},
	"GV.SC-03": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-03.078", "label": "Ex1", "text": "Identify areas of alignment and overlap with cybersecurity and enterprise risk management"},
			{"ref": "GV.SC-03.079", "label": "Ex2", "text": "Establish integrated control sets for cybersecurity risk management and cybersecurity supply chain risk management"},
			{"ref": "GV.SC-03.080", "label": "Ex3", "text": "Integrate cybersecurity supply chain risk management into improvement processes"},
			{"ref": "GV.SC-03.081", "label": "Ex4", "text": "Escalate material cybersecurity risks in supply chains to senior management, and address them at the enterprise risk management level"},
		],
	},
	"GV.SC-04": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Suppliers are known and prioritized by criticality",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-04.082", "label": "Ex1", "text": "Develop criteria for supplier criticality based on, for example, the sensitivity of data processed or possessed by suppliers, the degree of access to the organization's systems, and the importance of the products or services to the organization's mission"},
			{"ref": "GV.SC-04.083", "label": "Ex2", "text": "Keep a record of all suppliers, and prioritize suppliers based on the criticality criteria"},
		],
	},
	"GV.SC-05": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other relevant third parties",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-05.084", "label": "Ex1", "text": "Establish security requirements for suppliers, products, and services commensurate with their criticality level and potential impact if compromised"},
			{"ref": "GV.SC-05.085", "label": "Ex2", "text": "Include all cybersecurity and supply chain requirements that third parties must follow and how compliance with the requirements may be verified in default contractual language"},
			{"ref": "GV.SC-05.086", "label": "Ex3", "text": "Define the rules and protocols for information sharing between the organization and its suppliers and sub-tier suppliers in agreements"},
			{"ref": "GV.SC-05.087", "label": "Ex4", "text": "Manage risk by including security requirements in agreements based on their criticality and potential impact if compromised"},
			{"ref": "GV.SC-05.088", "label": "Ex5", "text": "Define security requirements in service-level agreements (SLAs) for monitoring suppliers for acceptable security performance throughout the supplier relationship lifecycle"},
			{"ref": "GV.SC-05.089", "label": "Ex6", "text": "Contractually require suppliers to disclose cybersecurity features, functions, and vulnerabilities of their products and services for the life of the product or the term of service"},
			{"ref": "GV.SC-05.090", "label": "Ex7", "text": "Contractually require suppliers to provide and maintain a current component inventory (e.g., software or hardware bill of materials) for critical products"},
			{"ref": "GV.SC-05.091", "label": "Ex8", "text": "Contractually require suppliers to vet their employees and guard against insider threats"},
			{"ref": "GV.SC-05.092", "label": "Ex9", "text": "Contractually require suppliers to provide evidence of performing acceptable security practices through, for example, self-attestation, conformance to known standards, certifications, or inspections"},
			{"ref": "GV.SC-05.093", "label": "Ex10", "text": "Specify in contracts and other agreements the rights and responsibilities of the organization, its suppliers, and their supply chains, with respect to potential cybersecurity risks"},
		],
	},
	"GV.SC-06": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-06.094", "label": "Ex1", "text": "Perform thorough due diligence on prospective suppliers that is consistent with procurement planning and commensurate with the level of risk, criticality, and complexity of each supplier relationship"},
			{"ref": "GV.SC-06.095", "label": "Ex2", "text": "Assess the suitability of the technology and cybersecurity capabilities and the risk management practices of prospective suppliers"},
			{"ref": "GV.SC-06.096", "label": "Ex3", "text": "Conduct supplier risk assessments against business and applicable cybersecurity requirements"},
			{"ref": "GV.SC-06.097", "label": "Ex4", "text": "Assess the authenticity, integrity, and security of critical products prior to acquisition and use"},
		],
	},
	"GV.SC-07": {
		"function": "GV",
		"category": "GV.SC",
		"text": "The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of the relationship",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-07.098", "label": "Ex1", "text": "Adjust assessment formats and frequencies based on the third party's reputation and the criticality of the products or services they provide"},
			{"ref": "GV.SC-07.099", "label": "Ex2", "text": "Evaluate third parties' evidence of compliance with contractual cybersecurity requirements, such as self-attestations, warranties, certifications, and other artifacts"},
			{"ref": "GV.SC-07.100", "label": "Ex3", "text": "Monitor critical suppliers to ensure that they are fulfilling their security obligations throughout the supplier relationship lifecycle using a variety of methods and techniques, such as inspections, audits, tests, or other forms of evaluation"},
			{"ref": "GV.SC-07.101", "label": "Ex4", "text": "Monitor critical suppliers, services, and products for changes to their risk profiles, and reevaluate supplier criticality and risk impact accordingly"},
			{"ref": "GV.SC-07.102", "label": "Ex5", "text": "Plan for unexpected supplier and supply chain-related interruptions to ensure business continuity"},
		],
	},
	"GV.SC-08": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Relevant suppliers and other third parties are included in incident planning, response, and recovery activities",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-08.103", "label": "Ex1", "text": "Define and use rules and protocols for reporting incident response and recovery activities and the status between the organization and its suppliers"},
			{"ref": "GV.SC-08.104", "label": "Ex2", "text": "Identify and document the roles and responsibilities of the organization and its suppliers for incident response"},
			{"ref": "GV.SC-08.105", "label": "Ex3", "text": "Include critical suppliers in incident response exercises and simulations"},
			{"ref": "GV.SC-08.106", "label": "Ex4", "text": "Define and coordinate crisis communication methods and protocols between the organization and its critical suppliers"},
			{"ref": "GV.SC-08.107", "label": "Ex5", "text": "Conduct collaborative lessons learned sessions with critical suppliers"},
		],
	},
	"GV.SC-09": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-09.108", "label": "Ex1", "text": "Policies and procedures require provenance records for all acquired technology products and services"},
			{"ref": "GV.SC-09.109", "label": "Ex2", "text": "Periodically provide risk reporting to leaders about how acquired components are proven to be untampered and authentic"},
			{"ref": "GV.SC-09.110", "label": "Ex3", "text": "Communicate regularly among cybersecurity risk managers and operations personnel about the need to acquire software patches, updates, and upgrades only from authenticated and trustworthy software providers"},
			{"ref": "GV.SC-09.111", "label": "Ex4", "text": "Review policies to ensure that they require approved supplier personnel to perform maintenance on supplier products"},
			{"ref": "GV.SC-09.112", "label": "Ex5", "text": "Policies and procedure require checking upgrades to critical hardware for unauthorized changes"},
		],
	},
	"GV.SC-10": {
		"function": "GV",
		"category": "GV.SC",
		"text": "Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement",
		"basis": "attestation",
		"examples": [
			{"ref": "GV.SC-10.113", "label": "Ex1", "text": "Establish processes for terminating critical relationships under both normal and adverse circumstances"},
			{"ref": "GV.SC-10.114", "label": "Ex2", "text": "Define and implement plans for component end-of-life maintenance support and obsolescence"},
			{"ref": "GV.SC-10.115", "label": "Ex3", "text": "Verify that supplier access to organization resources is deactivated promptly when it is no longer needed"},
			{"ref": "GV.SC-10.116", "label": "Ex4", "text": "Verify that assets containing the organization's data are returned or properly disposed of in a timely, controlled, and safe manner"},
			{"ref": "GV.SC-10.117", "label": "Ex5", "text": "Develop and execute a plan for terminating or transitioning supplier relationships that takes supply chain security risk and resiliency into account"},
			{"ref": "GV.SC-10.118", "label": "Ex6", "text": "Mitigate risks to data and systems created by supplier termination"},
			{"ref": "GV.SC-10.119", "label": "Ex7", "text": "Manage data leakage risks associated with supplier termination"},
		],
	},
	"ID.AM-01": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Inventories of hardware managed by the organization are maintained",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.AM-01",
		"examples": [
			{"ref": "ID.AM-01.120", "label": "Ex1", "text": "Maintain inventories for all types of hardware, including IT, IoT, OT, and mobile devices"},
			{"ref": "ID.AM-01.121", "label": "Ex2", "text": "Constantly monitor networks to detect new hardware and automatically update inventories"},
		],
	},
	"ID.AM-02": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Inventories of software, services, and systems managed by the organization are maintained",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.AM-02.122", "label": "Ex1", "text": "Maintain inventories for all types of software and services, including commercial-off-the-shelf, open-source, custom applications, API services, and cloud-based applications and services"},
			{"ref": "ID.AM-02.123", "label": "Ex2", "text": "Constantly monitor all platforms, including containers and virtual machines, for software and service inventory changes"},
			{"ref": "ID.AM-02.124", "label": "Ex3", "text": "Maintain an inventory of the organization's systems"},
		],
	},
	"ID.AM-03": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Representations of the organization's authorized network communication and internal and external network data flows are maintained",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.AM-03",
		"examples": [
			{"ref": "ID.AM-03.125", "label": "Ex1", "text": "Maintain baselines of communication and data flows within the organization's wired and wireless networks"},
			{"ref": "ID.AM-03.126", "label": "Ex2", "text": "Maintain baselines of communication and data flows between the organization and third parties"},
			{"ref": "ID.AM-03.127", "label": "Ex3", "text": "Maintain baselines of communication and data flows for the organization's infrastructure-as-a-service (IaaS) usage"},
			{"ref": "ID.AM-03.128", "label": "Ex4", "text": "Maintain documentation of expected network ports, protocols, and services that are typically used among authorized systems"},
		],
	},
	"ID.AM-04": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Inventories of services provided by suppliers are maintained",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.AM-04.129", "label": "Ex1", "text": "Inventory all external services used by the organization, including third-party infrastructure-as-a-service (IaaS), platform-as-a-service (PaaS), and software-as-a-service (SaaS) offerings; APIs; and other externally hosted application services"},
			{"ref": "ID.AM-04.130", "label": "Ex2", "text": "Update the inventory when a new external service is going to be utilized to ensure adequate cybersecurity risk management monitoring of the organization's use of that service"},
		],
	},
	"ID.AM-05": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Assets are prioritized based on classification, criticality, resources, and impact on the mission",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.AM-05",
		"examples": [
			{"ref": "ID.AM-05.131", "label": "Ex1", "text": "Define criteria for prioritizing each class of assets"},
			{"ref": "ID.AM-05.132", "label": "Ex2", "text": "Apply the prioritization criteria to assets"},
			{"ref": "ID.AM-05.133", "label": "Ex3", "text": "Track the asset priorities and update them periodically or when significant changes to the organization occur"},
		],
	},
	"ID.AM-07": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Inventories of data and corresponding metadata for designated data types are maintained",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.AM-07.134", "label": "Ex1", "text": "Maintain a list of the designated data types of interest (e.g., personally identifiable information, protected health information, financial account numbers, organization intellectual property, operational technology data)"},
			{"ref": "ID.AM-07.135", "label": "Ex2", "text": "Continuously discover and analyze ad hoc data to identify new instances of designated data types"},
			{"ref": "ID.AM-07.136", "label": "Ex3", "text": "Assign data classifications to designated data types through tags or labels"},
			{"ref": "ID.AM-07.137", "label": "Ex4", "text": "Track the provenance, data owner, and geolocation of each instance of designated data types"},
		],
	},
	"ID.AM-08": {
		"function": "ID",
		"category": "ID.AM",
		"text": "Systems, hardware, software, services, and data are managed throughout their life cycles",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.AM-08.138", "label": "Ex1", "text": "Integrate cybersecurity considerations throughout the life cycles of systems, hardware, software, and services"},
			{"ref": "ID.AM-08.139", "label": "Ex2", "text": "Integrate cybersecurity considerations into product life cycles"},
			{"ref": "ID.AM-08.140", "label": "Ex3", "text": "Identify unofficial uses of technology to meet mission objectives (i.e., shadow IT)"},
			{"ref": "ID.AM-08.141", "label": "Ex4", "text": "Periodically identify redundant systems, hardware, software, and services that unnecessarily increase the organization's attack surface"},
			{"ref": "ID.AM-08.142", "label": "Ex5", "text": "Properly configure and secure systems, hardware, software, and services prior to their deployment in production"},
			{"ref": "ID.AM-08.143", "label": "Ex6", "text": "Update inventories when systems, hardware, software, and services are moved or transferred within the organization"},
			{"ref": "ID.AM-08.144", "label": "Ex7", "text": "Securely destroy stored data based on the organization's data retention policy using the prescribed destruction method, and keep and manage a record of the destructions"},
			{"ref": "ID.AM-08.145", "label": "Ex8", "text": "Securely sanitize data storage when hardware is being retired, decommissioned, reassigned, or sent for repairs or replacement"},
			{"ref": "ID.AM-08.146", "label": "Ex9", "text": "Offer methods for destroying paper, storage media, and other physical forms of data storage"},
		],
	},
	"ID.RA-01": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Vulnerabilities in assets are identified, validated, and recorded",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.RA-01",
		"examples": [
			{"ref": "ID.RA-01.147", "label": "Ex1", "text": "Use vulnerability management technologies to identify unpatched and misconfigured software"},
			{"ref": "ID.RA-01.148", "label": "Ex2", "text": "Assess network and system architectures for design and implementation weaknesses that affect cybersecurity"},
			{"ref": "ID.RA-01.149", "label": "Ex3", "text": "Review, analyze, or test organization-developed software to identify design, coding, and default configuration vulnerabilities"},
			{"ref": "ID.RA-01.150", "label": "Ex4", "text": "Assess facilities that house critical computing assets for physical vulnerabilities and resilience issues"},
			{"ref": "ID.RA-01.151", "label": "Ex5", "text": "Monitor sources of cyber threat intelligence for information on new vulnerabilities in products and services"},
			{"ref": "ID.RA-01.152", "label": "Ex6", "text": "Review processes and procedures for weaknesses that could be exploited to affect cybersecurity"},
		],
	},
	"ID.RA-02": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Cyber threat intelligence is received from information sharing forums and sources",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.RA-02",
		"examples": [
			{"ref": "ID.RA-02.153", "label": "Ex1", "text": "Configure cybersecurity tools and technologies with detection or response capabilities to securely ingest cyber threat intelligence feeds"},
			{"ref": "ID.RA-02.154", "label": "Ex2", "text": "Receive and review advisories from reputable third parties on current threat actors and their tactics, techniques, and procedures (TTPs)"},
			{"ref": "ID.RA-02.155", "label": "Ex3", "text": "Monitor sources of cyber threat intelligence for information on the types of vulnerabilities that emerging technologies may have"},
		],
	},
	"ID.RA-03": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Internal and external threats to the organization are identified and recorded",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.RA-03",
		"examples": [
			{"ref": "ID.RA-03.156", "label": "Ex1", "text": "Use cyber threat intelligence to maintain awareness of the types of threat actors likely to target the organization and the TTPs they are likely to use"},
			{"ref": "ID.RA-03.157", "label": "Ex2", "text": "Perform threat hunting to look for signs of threat actors within the environment"},
			{"ref": "ID.RA-03.158", "label": "Ex3", "text": "Implement processes for identifying internal threat actors"},
		],
	},
	"ID.RA-04": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.RA-04",
		"examples": [
			{"ref": "ID.RA-04.159", "label": "Ex1", "text": "Business leaders and cybersecurity risk management practitioners work together to estimate the likelihood and impact of risk scenarios and record them in risk registers"},
			{"ref": "ID.RA-04.160", "label": "Ex2", "text": "Enumerate the potential business impacts of unauthorized access to the organization's communications, systems, and data processed in or by those systems"},
			{"ref": "ID.RA-04.161", "label": "Ex3", "text": "Account for the potential impacts of cascading failures for systems of systems"},
		],
	},
	"ID.RA-05": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization",
		"basis": "facts",
		"fact_package": "nist.csf.identify",
		"legacy_label": "ID.RA-05",
		"examples": [
			{"ref": "ID.RA-05.162", "label": "Ex1", "text": "Develop threat models to better understand risks to the data and identify appropriate risk responses"},
			{"ref": "ID.RA-05.163", "label": "Ex2", "text": "Prioritize cybersecurity resource allocations and investments based on estimated likelihoods and impacts"},
		],
	},
	"ID.RA-06": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Risk responses are chosen, prioritized, planned, tracked, and communicated",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.RA-06.164", "label": "Ex1", "text": "Apply the vulnerability management plan's criteria for deciding whether to accept, transfer, mitigate, or avoid risk"},
			{"ref": "ID.RA-06.165", "label": "Ex2", "text": "Apply the vulnerability management plan's criteria for selecting compensating controls to mitigate risk"},
			{"ref": "ID.RA-06.166", "label": "Ex3", "text": "Track the progress of risk response implementation (e.g., plan of action and milestones [POA&M], risk register, risk detail report)"},
			{"ref": "ID.RA-06.167", "label": "Ex4", "text": "Use risk assessment findings to inform risk response decisions and actions"},
			{"ref": "ID.RA-06.168", "label": "Ex5", "text": "Communicate planned risk responses to affected stakeholders in priority order"},
		],
	},
	"ID.RA-07": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.RA-07.169", "label": "Ex1", "text": "Implement and follow procedures for the formal documentation, review, testing, and approval of proposed changes and requested exceptions"},
			{"ref": "ID.RA-07.170", "label": "Ex2", "text": "Document the possible risks of making or not making each proposed change, and provide guidance on rolling back changes"},
			{"ref": "ID.RA-07.171", "label": "Ex3", "text": "Document the risks related to each requested exception and the plan for responding to those risks"},
			{"ref": "ID.RA-07.172", "label": "Ex4", "text": "Periodically review risks that were accepted based upon planned future actions or milestones"},
		],
	},
	"ID.RA-08": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Processes for receiving, analyzing, and responding to vulnerability disclosures are established",
		"basis": "facts",
		"fact_package": "nist.csf.respond",
		"legacy_label": "RS.AN-05",
		"examples": [
			{"ref": "ID.RA-08.173", "label": "Ex1", "text": "Conduct vulnerability information sharing between the organization and its suppliers following the rules and protocols defined in contracts"},
			{"ref": "ID.RA-08.174", "label": "Ex2", "text": "Assign responsibilities and verify the execution of procedures for processing, analyzing the impact of, and responding to cybersecurity threat, vulnerability, or incident disclosures by suppliers, customers, partners, and government cybersecurity organizations"},
		],
	},
	"ID.RA-09": {
		"function": "ID",
		"category": "ID.RA",
		"text": "The authenticity and integrity of hardware and software are assessed prior to acquisition and use",
		"basis": "attestation",
		"examples": [{"ref": "ID.RA-09.175", "label": "Ex1", "text": "Assess the authenticity and cybersecurity of critical technology products and services prior to acquisition and use"}],
	},
	"ID.RA-10": {
		"function": "ID",
		"category": "ID.RA",
		"text": "Critical suppliers are assessed prior to acquisition",
		"basis": "attestation",
		"examples": [{"ref": "ID.RA-10.176", "label": "Ex1", "text": "Conduct supplier risk assessments against business and applicable cybersecurity requirements, including the supply chain"}],
	},
	"ID.IM-01": {
		"function": "ID",
		"category": "ID.IM",
		"text": "Improvements are identified from evaluations",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.IM-01.177", "label": "Ex1", "text": "Perform self-assessments of critical services that take current threats and TTPs into consideration"},
			{"ref": "ID.IM-01.178", "label": "Ex2", "text": "Invest in third-party assessments or independent audits of the effectiveness of the organization's cybersecurity program to identify areas that need improvement"},
			{"ref": "ID.IM-01.179", "label": "Ex3", "text": "Constantly evaluate compliance with selected cybersecurity requirements through automated means"},
		],
	},
	"ID.IM-02": {
		"function": "ID",
		"category": "ID.IM",
		"text": "Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.IM-02.180", "label": "Ex1", "text": "Identify improvements for future incident response activities based on findings from incident response assessments (e.g., tabletop exercises and simulations, tests, internal reviews, independent audits)"},
			{"ref": "ID.IM-02.181", "label": "Ex2", "text": "Identify improvements for future business continuity, disaster recovery, and incident response activities based on exercises performed in coordination with critical service providers and product suppliers"},
			{"ref": "ID.IM-02.182", "label": "Ex3", "text": "Involve internal stakeholders (e.g., senior executives, legal department, HR) in security tests and exercises as appropriate"},
			{"ref": "ID.IM-02.183", "label": "Ex4", "text": "Perform penetration testing to identify opportunities to improve the security posture of selected high-risk systems as approved by leadership"},
			{"ref": "ID.IM-02.184", "label": "Ex5", "text": "Exercise contingency plans for responding to and recovering from the discovery that products or services did not originate with the contracted supplier or partner or were altered before receipt"},
			{"ref": "ID.IM-02.185", "label": "Ex6", "text": "Collect and analyze performance metrics using security tools and services to inform improvements to the cybersecurity program"},
		],
	},
	"ID.IM-03": {
		"function": "ID",
		"category": "ID.IM",
		"text": "Improvements are identified from execution of operational processes, procedures, and activities",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.IM-03.186", "label": "Ex1", "text": "Conduct collaborative lessons learned sessions with suppliers"},
			{"ref": "ID.IM-03.187", "label": "Ex2", "text": "Annually review cybersecurity policies, processes, and procedures to take lessons learned into account"},
			{"ref": "ID.IM-03.188", "label": "Ex3", "text": "Use metrics to assess operational cybersecurity performance over time"},
		],
	},
	"ID.IM-04": {
		"function": "ID",
		"category": "ID.IM",
		"text": "Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved",
		"basis": "attestation",
		"examples": [
			{"ref": "ID.IM-04.189", "label": "Ex1", "text": "Establish contingency plans (e.g., incident response, business continuity, disaster recovery) for responding to and recovering from adverse events that can interfere with operations, expose confidential information, or otherwise endanger the organization's mission and viability"},
			{"ref": "ID.IM-04.190", "label": "Ex2", "text": "Include contact and communication information, processes for handling common scenarios, and criteria for prioritization, escalation, and elevation in all contingency plans"},
			{"ref": "ID.IM-04.191", "label": "Ex3", "text": "Create a vulnerability management plan to identify and assess all types of vulnerabilities and to prioritize, test, and implement risk responses"},
			{"ref": "ID.IM-04.192", "label": "Ex4", "text": "Communicate cybersecurity plans (including updates) to those responsible for carrying them out and to affected parties"},
			{"ref": "ID.IM-04.193", "label": "Ex5", "text": "Review and update all cybersecurity plans annually or when a need for significant improvements is identified"},
		],
	},
	"PR.AA-01": {
		"function": "PR",
		"category": "PR.AA",
		"text": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.AA-01.194", "label": "Ex1", "text": "Initiate requests for new access or additional access for employees, contractors, and others, and track, review, and fulfill the requests, with permission from system or data owners when needed"},
			{"ref": "PR.AA-01.195", "label": "Ex2", "text": "Issue, manage, and revoke cryptographic certificates and identity tokens, cryptographic keys (i.e., key management), and other credentials"},
			{"ref": "PR.AA-01.196", "label": "Ex3", "text": "Select a unique identifier for each device from immutable hardware characteristics or an identifier securely provisioned to the device"},
			{"ref": "PR.AA-01.197", "label": "Ex4", "text": "Physically label authorized hardware with an identifier for inventory and servicing purposes"},
		],
	},
	"PR.AA-02": {
		"function": "PR",
		"category": "PR.AA",
		"text": "Identities are proofed and bound to credentials based on the context of interactions",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.AC-06",
		"examples": [
			{"ref": "PR.AA-02.198", "label": "Ex1", "text": "Verify a person's claimed identity at enrollment time using government-issued identity credentials (e.g., passport, visa, driver's license)"},
			{"ref": "PR.AA-02.199", "label": "Ex2", "text": "Issue a different credential for each person (i.e., no credential sharing)"},
		],
	},
	"PR.AA-03": {
		"function": "PR",
		"category": "PR.AA",
		"text": "Users, services, and hardware are authenticated",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.AC-07",
		"examples": [
			{"ref": "PR.AA-03.200", "label": "Ex1", "text": "Require multifactor authentication"},
			{"ref": "PR.AA-03.201", "label": "Ex2", "text": "Enforce policies for the minimum strength of passwords, PINs, and similar authenticators"},
			{"ref": "PR.AA-03.202", "label": "Ex3", "text": "Periodically reauthenticate users, services, and hardware based on risk (e.g., in zero trust architectures)"},
			{"ref": "PR.AA-03.203", "label": "Ex4", "text": "Ensure that authorized personnel can access accounts essential for protecting safety under emergency conditions"},
		],
	},
	"PR.AA-04": {
		"function": "PR",
		"category": "PR.AA",
		"text": "Identity assertions are protected, conveyed, and verified",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.AA-04.204", "label": "Ex1", "text": "Protect identity assertions that are used to convey authentication and user information through single sign-on systems"},
			{"ref": "PR.AA-04.205", "label": "Ex2", "text": "Protect identity assertions that are used to convey authentication and user information between federated systems"},
			{"ref": "PR.AA-04.206", "label": "Ex3", "text": "Implement standards-based approaches for identity assertions in all contexts, and follow all guidance for the generation (e.g., data models, metadata), protection (e.g., digital signing, encryption), and verification (e.g., signature validation) of identity assertions"},
		],
	},
	"PR.AA-05": {
		"function": "PR",
		"category": "PR.AA",
		"text": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.AC-04",
		"examples": [
			{"ref": "PR.AA-05.207", "label": "Ex1", "text": "Review logical and physical access privileges periodically and whenever someone changes roles or leaves the organization, and promptly rescind privileges that are no longer needed"},
			{"ref": "PR.AA-05.208", "label": "Ex2", "text": "Take attributes of the requester and the requested resource into account for authorization decisions (e.g., geolocation, day/time, requester endpoint's cyber health)"},
			{"ref": "PR.AA-05.209", "label": "Ex3", "text": "Restrict access and privileges to the minimum necessary (e.g., zero trust architecture)"},
			{"ref": "PR.AA-05.210", "label": "Ex4", "text": "Periodically review the privileges associated with critical business functions to confirm proper separation of duties"},
		],
	},
	"PR.AA-06": {
		"function": "PR",
		"category": "PR.AA",
		"text": "Physical access to assets is managed, monitored, and enforced commensurate with risk",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.AC-02",
		"examples": [
			{"ref": "PR.AA-06.211", "label": "Ex1", "text": "Use security guards, security cameras, locked entrances, alarm systems, and other physical controls to monitor facilities and restrict access"},
			{"ref": "PR.AA-06.212", "label": "Ex2", "text": "Employ additional physical security controls for areas that contain high-risk assets"},
			{"ref": "PR.AA-06.213", "label": "Ex3", "text": "Escort guests, vendors, and other third parties within areas that contain business-critical assets"},
		],
	},
	"PR.AT-01": {
		"function": "PR",
		"category": "PR.AT",
		"text": "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.AT-01",
		"examples": [
			{"ref": "PR.AT-01.214", "label": "Ex1", "text": "Provide basic cybersecurity awareness and training to employees, contractors, partners, suppliers, and all other users of the organization's non-public resources"},
			{"ref": "PR.AT-01.215", "label": "Ex2", "text": "Train personnel to recognize social engineering attempts and other common attacks, report attacks and suspicious activity, comply with acceptable use policies, and perform basic cyber hygiene tasks (e.g., patching software, choosing passwords, protecting credentials)"},
			{"ref": "PR.AT-01.216", "label": "Ex3", "text": "Explain the consequences of cybersecurity policy violations, both to individual users and the organization as a whole"},
			{"ref": "PR.AT-01.217", "label": "Ex4", "text": "Periodically assess or test users on their understanding of basic cybersecurity practices"},
			{"ref": "PR.AT-01.218", "label": "Ex5", "text": "Require annual refreshers to reinforce existing practices and introduce new practices"},
		],
	},
	"PR.AT-02": {
		"function": "PR",
		"category": "PR.AT",
		"text": "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.AT-02.219", "label": "Ex1", "text": "Identify the specialized roles within the organization that require additional cybersecurity training, such as physical and cybersecurity personnel, finance personnel, senior leadership, and anyone with access to business-critical data"},
			{"ref": "PR.AT-02.220", "label": "Ex2", "text": "Provide role-based cybersecurity awareness and training to all those in specialized roles, including contractors, partners, suppliers, and other third parties"},
			{"ref": "PR.AT-02.221", "label": "Ex3", "text": "Periodically assess or test users on their understanding of cybersecurity practices for their specialized roles"},
			{"ref": "PR.AT-02.222", "label": "Ex4", "text": "Require annual refreshers to reinforce existing practices and introduce new practices"},
		],
	},
	"PR.DS-01": {
		"function": "PR",
		"category": "PR.DS",
		"text": "The confidentiality, integrity, and availability of data-at-rest are protected",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.DS-01",
		"examples": [
			{"ref": "PR.DS-01.223", "label": "Ex1", "text": "Use encryption, digital signatures, and cryptographic hashes to protect the confidentiality and integrity of stored data in files, databases, virtual machine disk images, container images, and other resources"},
			{"ref": "PR.DS-01.224", "label": "Ex2", "text": "Use full disk encryption to protect data stored on user endpoints"},
			{"ref": "PR.DS-01.225", "label": "Ex3", "text": "Confirm the integrity of software by validating signatures"},
			{"ref": "PR.DS-01.226", "label": "Ex4", "text": "Restrict the use of removable media to prevent data exfiltration"},
			{"ref": "PR.DS-01.227", "label": "Ex5", "text": "Physically secure removable media containing unencrypted sensitive information, such as within locked offices or file cabinets"},
		],
	},
	"PR.DS-02": {
		"function": "PR",
		"category": "PR.DS",
		"text": "The confidentiality, integrity, and availability of data-in-transit are protected",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.DS-02",
		"examples": [
			{"ref": "PR.DS-02.228", "label": "Ex1", "text": "Use encryption, digital signatures, and cryptographic hashes to protect the confidentiality and integrity of network communications"},
			{"ref": "PR.DS-02.229", "label": "Ex2", "text": "Automatically encrypt or block outbound emails and other communications that contain sensitive data, depending on the data classification"},
			{"ref": "PR.DS-02.230", "label": "Ex3", "text": "Block access to personal email, file sharing, file storage services, and other personal communications applications and services from organizational systems and networks"},
			{"ref": "PR.DS-02.231", "label": "Ex4", "text": "Prevent reuse of sensitive data from production environments (e.g., customer records) in development, testing, and other non-production environments"},
		],
	},
	"PR.DS-10": {
		"function": "PR",
		"category": "PR.DS",
		"text": "The confidentiality, integrity, and availability of data-in-use are protected",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.DS-10.232", "label": "Ex1", "text": "Remove data that must remain confidential (e.g., from processors and memory) as soon as it is no longer needed"},
			{"ref": "PR.DS-10.233", "label": "Ex2", "text": "Protect data in use from access by other users and processes of the same platform"},
		],
	},
	"PR.DS-11": {
		"function": "PR",
		"category": "PR.DS",
		"text": "Backups of data are created, protected, maintained, and tested",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.IP-04",
		"examples": [
			{"ref": "PR.DS-11.234", "label": "Ex1", "text": "Continuously back up critical data in near-real-time, and back up other data frequently at agreed-upon schedules"},
			{"ref": "PR.DS-11.235", "label": "Ex2", "text": "Test backups and restores for all types of data sources at least annually"},
			{"ref": "PR.DS-11.236", "label": "Ex3", "text": "Securely store some backups offline and offsite so that an incident or disaster will not damage them"},
			{"ref": "PR.DS-11.237", "label": "Ex4", "text": "Enforce geographic separation and geolocation restrictions for data backup storage"},
		],
	},
	"PR.PS-01": {
		"function": "PR",
		"category": "PR.PS",
		"text": "Configuration management practices are established and applied",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.PS-01.238", "label": "Ex1", "text": "Establish, test, deploy, and maintain hardened baselines that enforce the organization's cybersecurity policies and provide only essential capabilities (i.e., principle of least functionality)"},
			{"ref": "PR.PS-01.239", "label": "Ex2", "text": "Review all default configuration settings that may potentially impact cybersecurity when installing or upgrading software"},
			{"ref": "PR.PS-01.240", "label": "Ex3", "text": "Monitor implemented software for deviations from approved baselines"},
		],
	},
	"PR.PS-02": {
		"function": "PR",
		"category": "PR.PS",
		"text": "Software is maintained, replaced, and removed commensurate with risk",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.PS-02.241", "label": "Ex1", "text": "Perform routine and emergency patching within the timeframes specified in the vulnerability management plan"},
			{"ref": "PR.PS-02.242", "label": "Ex2", "text": "Update container images, and deploy new container instances to replace rather than update existing instances"},
			{"ref": "PR.PS-02.243", "label": "Ex3", "text": "Replace end-of-life software and service versions with supported, maintained versions"},
			{"ref": "PR.PS-02.244", "label": "Ex4", "text": "Uninstall and remove unauthorized software and services that pose undue risks"},
			{"ref": "PR.PS-02.245", "label": "Ex5", "text": "Uninstall and remove any unnecessary software components (e.g., operating system utilities) that attackers might misuse"},
			{"ref": "PR.PS-02.246", "label": "Ex6", "text": "Define and implement plans for software and service end-of-life maintenance support and obsolescence"},
		],
	},
	"PR.PS-03": {
		"function": "PR",
		"category": "PR.PS",
		"text": "Hardware is maintained, replaced, and removed commensurate with risk",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.PS-03.247", "label": "Ex1", "text": "Replace hardware when it lacks needed security capabilities or when it cannot support software with needed security capabilities"},
			{"ref": "PR.PS-03.248", "label": "Ex2", "text": "Define and implement plans for hardware end-of-life maintenance support and obsolescence"},
			{"ref": "PR.PS-03.249", "label": "Ex3", "text": "Perform hardware disposal in a secure, responsible, and auditable manner"},
		],
	},
	"PR.PS-04": {
		"function": "PR",
		"category": "PR.PS",
		"text": "Log records are generated and made available for continuous monitoring",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.PS-04.250", "label": "Ex1", "text": "Configure all operating systems, applications, and services (including cloud-based services) to generate log records"},
			{"ref": "PR.PS-04.251", "label": "Ex2", "text": "Configure log generators to securely share their logs with the organization's logging infrastructure systems and services"},
			{"ref": "PR.PS-04.252", "label": "Ex3", "text": "Configure log generators to record the data needed by zero-trust architectures"},
		],
	},
	"PR.PS-05": {
		"function": "PR",
		"category": "PR.PS",
		"text": "Installation and execution of unauthorized software are prevented",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.PS-05.253", "label": "Ex1", "text": "When risk warrants it, restrict software execution to permitted products only or deny the execution of prohibited and unauthorized software"},
			{"ref": "PR.PS-05.254", "label": "Ex2", "text": "Verify the source of new software and the software's integrity before installing it"},
			{"ref": "PR.PS-05.255", "label": "Ex3", "text": "Configure platforms to use only approved DNS services that block access to known malicious domains"},
			{"ref": "PR.PS-05.256", "label": "Ex4", "text": "Configure platforms to allow the installation of organization-approved software only"},
		],
	},
	"PR.PS-06": {
		"function": "PR",
		"category": "PR.PS",
		"text": "Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.PS-06.257", "label": "Ex1", "text": "Protect all components of organization-developed software from tampering and unauthorized access"},
			{"ref": "PR.PS-06.258", "label": "Ex2", "text": "Secure all software produced by the organization, with minimal vulnerabilities in their releases"},
			{"ref": "PR.PS-06.259", "label": "Ex3", "text": "Maintain the software used in production environments, and securely dispose of software once it is no longer needed"},
		],
	},
	"PR.IR-01": {
		"function": "PR",
		"category": "PR.IR",
		"text": "Networks and environments are protected from unauthorized logical access and usage",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.IR-01.260", "label": "Ex1", "text": "Logically segment organization networks and cloud-based platforms according to trust boundaries and platform types (e.g., IT, IoT, OT, mobile, guests), and permit required communications only between segments"},
			{"ref": "PR.IR-01.261", "label": "Ex2", "text": "Logically segment organization networks from external networks, and permit only necessary communications to enter the organization's networks from the external networks"},
			{"ref": "PR.IR-01.262", "label": "Ex3", "text": "Implement zero trust architectures to restrict network access to each resource to the minimum necessary"},
			{"ref": "PR.IR-01.263", "label": "Ex4", "text": "Check the cyber health of endpoints before allowing them to access and use production resources"},
		],
	},
	"PR.IR-02": {
		"function": "PR",
		"category": "PR.IR",
		"text": "The organization's technology assets are protected from environmental threats",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.IR-02.264", "label": "Ex1", "text": "Protect organizational equipment from known environmental threats, such as flooding, fire, wind, and excessive heat and humidity"},
			{"ref": "PR.IR-02.265", "label": "Ex2", "text": "Include protection from environmental threats and provisions for adequate operating infrastructure in requirements for service providers that operate systems on the organization's behalf"},
		],
	},
	"PR.IR-03": {
		"function": "PR",
		"category": "PR.IR",
		"text": "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations",
		"basis": "attestation",
		"examples": [
			{"ref": "PR.IR-03.266", "label": "Ex1", "text": "Avoid single points of failure in systems and infrastructure"},
			{"ref": "PR.IR-03.267", "label": "Ex2", "text": "Use load balancing to increase capacity and improve reliability"},
			{"ref": "PR.IR-03.268", "label": "Ex3", "text": "Use high-availability components like redundant storage and power supplies to improve system reliability"},
		],
	},
	"PR.IR-04": {
		"function": "PR",
		"category": "PR.IR",
		"text": "Adequate resource capacity to ensure availability is maintained",
		"basis": "facts",
		"fact_package": "nist.csf.protect",
		"legacy_label": "PR.DS-04",
		"examples": [
			{"ref": "PR.IR-04.269", "label": "Ex1", "text": "Monitor usage of storage, power, compute, network bandwidth, and other resources"},
			{"ref": "PR.IR-04.270", "label": "Ex2", "text": "Forecast future needs, and scale resources accordingly"},
		],
	},
	"DE.AE-02": {
		"function": "DE",
		"category": "DE.AE",
		"text": "Potentially adverse events are analyzed to better understand associated activities",
		"basis": "facts",
		"fact_package": "nist.csf.detect",
		"legacy_label": "DE.AE-02",
		"examples": [
			{"ref": "DE.AE-02.290", "label": "Ex1", "text": "Use security information and event management (SIEM) or other tools to continuously monitor log events for known malicious and suspicious activity"},
			{"ref": "DE.AE-02.291", "label": "Ex2", "text": "Utilize up-to-date cyber threat intelligence in log analysis tools to improve detection accuracy and characterize threat actors, their methods, and indicators of compromise"},
			{"ref": "DE.AE-02.292", "label": "Ex3", "text": "Regularly conduct manual reviews of log events for technologies that cannot be sufficiently monitored through automation"},
			{"ref": "DE.AE-02.293", "label": "Ex4", "text": "Use log analysis tools to generate reports on their findings"},
		],
	},
	"DE.AE-03": {
		"function": "DE",
		"category": "DE.AE",
		"text": "Information is correlated from multiple sources",
		"basis": "facts",
		"fact_package": "nist.csf.detect",
		"legacy_label": "DE.AE-03",
		"examples": [
			{"ref": "DE.AE-03.294", "label": "Ex1", "text": "Constantly transfer log data generated by other sources to a relatively small number of log servers"},
			{"ref": "DE.AE-03.295", "label": "Ex2", "text": "Use event correlation technology (e.g., SIEM) to collect information captured by multiple sources"},
			{"ref": "DE.AE-03.296", "label": "Ex3", "text": "Utilize cyber threat intelligence to help correlate events among log sources"},
		],
	},
	"DE.AE-04": {
		"function": "DE",
		"category": "DE.AE",
		"text": "The estimated impact and scope of adverse events are understood",
		"basis": "facts",
		"fact_package": "nist.csf.detect",
		"legacy_label": "DE.AE-04",
		"examples": [
			{"ref": "DE.AE-04.297", "label": "Ex1", "text": "Use SIEMs or other tools to estimate impact and scope, and review and refine the estimates"},
			{"ref": "DE.AE-04.298", "label": "Ex2", "text": "A person creates their own estimates of impact and scope"},
		],
	},
	"DE.AE-06": {
		"function": "DE",
		"category": "DE.AE",
		"text": "Information on adverse events is provided to authorized staff and tools",
		"basis": "attestation",
		"examples": [
			{"ref": "DE.AE-06.299", "label": "Ex1", "text": "Use cybersecurity software to generate alerts and provide them to the security operations center (SOC), incident responders, and incident response tools"},
			{"ref": "DE.AE-06.300", "label": "Ex2", "text": "Incident responders and other authorized personnel can access log analysis findings at all times"},
			{"ref": "DE.AE-06.301", "label": "Ex3", "text": "Automatically create and assign tickets in the organization's ticketing system when certain types of alerts occur"},
			{"ref": "DE.AE-06.302", "label": "Ex4", "text": "Manually create and assign tickets in the organization's ticketing system when technical staff discover indicators of compromise"},
		],
	},
	"DE.AE-07": {
		"function": "DE",
		"category": "DE.AE",
		"text": "Cyber threat intelligence and other contextual information are integrated into the analysis",
		"basis": "attestation",
		"examples": [
			{"ref": "DE.AE-07.303", "label": "Ex1", "text": "Securely provide cyber threat intelligence feeds to detection technologies, processes, and personnel"},
			{"ref": "DE.AE-07.304", "label": "Ex2", "text": "Securely provide information from asset inventories to detection technologies, processes, and personnel"},
			{"ref": "DE.AE-07.305", "label": "Ex3", "text": "Rapidly acquire and analyze vulnerability disclosures for the organization's technologies from suppliers, vendors, and third-party security advisories"},
		],
	},
	"DE.AE-08": {
		"function": "DE",
		"category": "DE.AE",
		"text": "Incidents are declared when adverse events meet the defined incident criteria",
		"basis": "attestation",
		"examples": [
			{"ref": "DE.AE-08.306", "label": "Ex1", "text": "Apply incident criteria to known and assumed characteristics of activity in order to determine whether an incident should be declared"},
			{"ref": "DE.AE-08.307", "label": "Ex2", "text": "Take known false positives into account when applying incident criteria"},
		],
	},
	"DE.CM-01": {
		"function": "DE",
		"category": "DE.CM",
		"text": "Networks and network services are monitored to find potentially adverse events",
		"basis": "facts",
		"fact_package": "nist.csf.detect",
		"legacy_label": "DE.CM-01",
		"examples": [
			{"ref": "DE.CM-01.271", "label": "Ex1", "text": "Monitor DNS, BGP, and other network services for adverse events"},
			{"ref": "DE.CM-01.272", "label": "Ex2", "text": "Monitor wired and wireless networks for connections from unauthorized endpoints"},
			{"ref": "DE.CM-01.273", "label": "Ex3", "text": "Monitor facilities for unauthorized or rogue wireless networks"},
			{"ref": "DE.CM-01.274", "label": "Ex4", "text": "Compare actual network flows against baselines to detect deviations"},
			{"ref": "DE.CM-01.275", "label": "Ex5", "text": "Monitor network communications to identify changes in security postures for zero trust purposes"},
		],
	},
	"DE.CM-02": {
		"function": "DE",
		"category": "DE.CM",
		"text": "The physical environment is monitored to find potentially adverse events",
		"basis": "facts",
		"fact_package": "nist.csf.detect",
		"legacy_label": "DE.CM-02",
		"examples": [
			{"ref": "DE.CM-02.276", "label": "Ex1", "text": "Monitor logs from physical access control systems (e.g., badge readers) to find unusual access patterns (e.g., deviations from the norm) and failed access attempts"},
			{"ref": "DE.CM-02.277", "label": "Ex2", "text": "Review and monitor physical access records (e.g., from visitor registration, sign-in sheets)"},
			{"ref": "DE.CM-02.278", "label": "Ex3", "text": "Monitor physical access controls (e.g., locks, latches, hinge pins, alarms) for signs of tampering"},
			{"ref": "DE.CM-02.279", "label": "Ex4", "text": "Monitor the physical environment using alarm systems, cameras, and security guards"},
		],
	},
	"DE.CM-03": {
		"function": "DE",
		"category": "DE.CM",
		"text": "Personnel activity and technology usage are monitored to find potentially adverse events",
		"basis": "attestation",
		"examples": [
			{"ref": "DE.CM-03.280", "label": "Ex1", "text": "Use behavior analytics software to detect anomalous user activity to mitigate insider threats"},
			{"ref": "DE.CM-03.281", "label": "Ex2", "text": "Monitor logs from logical access control systems to find unusual access patterns and failed access attempts"},
			{"ref": "DE.CM-03.282", "label": "Ex3", "text": "Continuously monitor deception technology, including user accounts, for any usage"},
		],
	},
	"DE.CM-06": {
		"function": "DE",
		"category": "DE.CM",
		"text": "External service provider activities and services are monitored to find potentially adverse events",
		"basis": "facts",
		"fact_package": "nist.csf.detect",
		"legacy_label": "DE.CM-06",
		"examples": [
			{"ref": "DE.CM-06.283", "label": "Ex1", "text": "Monitor remote and onsite administration and maintenance activities that external providers perform on organizational systems"},
			{"ref": "DE.CM-06.284", "label": "Ex2", "text": "Monitor activity from cloud-based services, internet service providers, and other service providers for deviations from expected behavior"},
		],
	},
	"DE.CM-09": {
		"function": "DE",
		"category": "DE.CM",
		"text": "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events",
		"basis": "attestation",
		"examples": [
			{"ref": "DE.CM-09.285", "label": "Ex1", "text": "Monitor email, web, file sharing, collaboration services, and other common attack vectors to detect malware, phishing, data leaks and exfiltration, and other adverse events"},
			{"ref": "DE.CM-09.286", "label": "Ex2", "text": "Monitor authentication attempts to identify attacks against credentials and unauthorized credential reuse"},
			{"ref": "DE.CM-09.287", "label": "Ex3", "text": "Monitor software configurations for deviations from security baselines"},
			{"ref": "DE.CM-09.288", "label": "Ex4", "text": "Monitor hardware and software for signs of tampering"},
			{"ref": "DE.CM-09.289", "label": "Ex5", "text": "Use technologies with a presence on endpoints to detect cyber health issues (e.g., missing patches, malware infections, unauthorized software), and redirect the endpoints to a remediation environment before access is authorized"},
		],
	},
	"RS.MA-01": {
		"function": "RS",
		"category": "RS.MA",
		"text": "The incident response plan is executed in coordination with relevant third parties once an incident is declared",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.MA-01.308", "label": "Ex1", "text": "Detection technologies automatically report confirmed incidents"},
			{"ref": "RS.MA-01.309", "label": "Ex2", "text": "Request incident response assistance from the organization's incident response outsourcer"},
			{"ref": "RS.MA-01.310", "label": "Ex3", "text": "Designate an incident lead for each incident"},
			{"ref": "RS.MA-01.311", "label": "Ex4", "text": "Initiate execution of additional cybersecurity plans as needed to support incident response (for example, business continuity and disaster recovery)"},
		],
	},
	"RS.MA-02": {
		"function": "RS",
		"category": "RS.MA",
		"text": "Incident reports are triaged and validated",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.MA-02.312", "label": "Ex1", "text": "Preliminarily review incident reports to confirm that they are cybersecurity-related and necessitate incident response activities"},
			{"ref": "RS.MA-02.313", "label": "Ex2", "text": "Apply criteria to estimate the severity of an incident"},
		],
	},
	"RS.MA-03": {
		"function": "RS",
		"category": "RS.MA",
		"text": "Incidents are categorized and prioritized",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.MA-03.314", "label": "Ex1", "text": "Further review and categorize incidents based on the type of incident (e.g., data breach, ransomware, DDoS, account compromise)"},
			{"ref": "RS.MA-03.315", "label": "Ex2", "text": "Prioritize incidents based on their scope, likely impact, and time-critical nature"},
			{"ref": "RS.MA-03.316", "label": "Ex3", "text": "Select incident response strategies for active incidents by balancing the need to quickly recover from an incident with the need to observe the attacker or conduct a more thorough investigation"},
		],
	},
	"RS.MA-04": {
		"function": "RS",
		"category": "RS.MA",
		"text": "Incidents are escalated or elevated as needed",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.MA-04.317", "label": "Ex1", "text": "Track and validate the status of all ongoing incidents"},
			{"ref": "RS.MA-04.318", "label": "Ex2", "text": "Coordinate incident escalation or elevation with designated internal and external stakeholders"},
		],
	},
	"RS.MA-05": {
		"function": "RS",
		"category": "RS.MA",
		"text": "The criteria for initiating incident recovery are applied",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.MA-05.319", "label": "Ex1", "text": "Apply incident recovery criteria to known and assumed characteristics of the incident to determine whether incident recovery processes should be initiated"},
			{"ref": "RS.MA-05.320", "label": "Ex2", "text": "Take the possible operational disruption of incident recovery activities into account"},
		],
	},
	"RS.AN-03": {
		"function": "RS",
		"category": "RS.AN",
		"text": "Analysis is performed to establish what has taken place during an incident and the root cause of the incident",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.AN-03.321", "label": "Ex1", "text": "Determine the sequence of events that occurred during the incident and which assets and resources were involved in each event"},
			{"ref": "RS.AN-03.322", "label": "Ex2", "text": "Attempt to determine what vulnerabilities, threats, and threat actors were directly or indirectly involved in the incident"},
			{"ref": "RS.AN-03.323", "label": "Ex3", "text": "Analyze the incident to find the underlying, systemic root causes"},
			{"ref": "RS.AN-03.324", "label": "Ex4", "text": "Check any cyber deception technology for additional information on attacker behavior"},
		],
	},
	"RS.AN-06": {
		"function": "RS",
		"category": "RS.AN",
		"text": "Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.AN-06.325", "label": "Ex1", "text": "Require each incident responder and others (e.g., system administrators, cybersecurity engineers) who perform incident response tasks to record their actions and make the record immutable"},
			{"ref": "RS.AN-06.326", "label": "Ex2", "text": "Require the incident lead to document the incident in detail and be responsible for preserving the integrity of the documentation and the sources of all information being reported"},
		],
	},
	"RS.AN-07": {
		"function": "RS",
		"category": "RS.AN",
		"text": "Incident data and metadata are collected, and their integrity and provenance are preserved",
		"basis": "attestation",
		"examples": [{"ref": "RS.AN-07.327", "label": "Ex1", "text": "Collect, preserve, and safeguard the integrity of all pertinent incident data and metadata (e.g., data source, date/time of collection) based on evidence preservation and chain-of-custody procedures"}],
	},
	"RS.AN-08": {
		"function": "RS",
		"category": "RS.AN",
		"text": "An incident's magnitude is estimated and validated",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.AN-08.328", "label": "Ex1", "text": "Review other potential targets of the incident to search for indicators of compromise and evidence of persistence"},
			{"ref": "RS.AN-08.329", "label": "Ex2", "text": "Automatically run tools on targets to look for indicators of compromise and evidence of persistence"},
		],
	},
	"RS.CO-02": {
		"function": "RS",
		"category": "RS.CO",
		"text": "Internal and external stakeholders are notified of incidents",
		"basis": "facts",
		"fact_package": "nist.csf.respond",
		"legacy_label": "RS.CO-02",
		"examples": [
			{"ref": "RS.CO-02.330", "label": "Ex1", "text": "Follow the organization's breach notification procedures after discovering a data breach incident, including notifying affected customers"},
			{"ref": "RS.CO-02.331", "label": "Ex2", "text": "Notify business partners and customers of incidents in accordance with contractual requirements"},
			{"ref": "RS.CO-02.332", "label": "Ex3", "text": "Notify law enforcement agencies and regulatory bodies of incidents based on criteria in the incident response plan and management approval"},
		],
	},
	"RS.CO-03": {
		"function": "RS",
		"category": "RS.CO",
		"text": "Information is shared with designated internal and external stakeholders",
		"basis": "facts",
		"fact_package": "nist.csf.respond",
		"legacy_label": "RS.CO-03",
		"examples": [
			{"ref": "RS.CO-03.333", "label": "Ex1", "text": "Securely share information consistent with response plans and information sharing agreements"},
			{"ref": "RS.CO-03.334", "label": "Ex2", "text": "Voluntarily share information about an attacker's observed TTPs, with all sensitive data removed, with an Information Sharing and Analysis Center (ISAC)"},
			{"ref": "RS.CO-03.335", "label": "Ex3", "text": "Notify HR when malicious insider activity occurs"},
			{"ref": "RS.CO-03.336", "label": "Ex4", "text": "Regularly update senior leadership on the status of major incidents"},
			{"ref": "RS.CO-03.337", "label": "Ex5", "text": "Follow the rules and protocols defined in contracts for incident information sharing between the organization and its suppliers"},
			{"ref": "RS.CO-03.338", "label": "Ex6", "text": "Coordinate crisis communication methods between the organization and its critical suppliers"},
		],
	},
	"RS.MI-01": {
		"function": "RS",
		"category": "RS.MI",
		"text": "Incidents are contained",
		"basis": "facts",
		"fact_package": "nist.csf.respond",
		"legacy_label": "RS.MI-01",
		"examples": [
			{"ref": "RS.MI-01.339", "label": "Ex1", "text": "Cybersecurity technologies (e.g., antivirus software) and cybersecurity features of other technologies (e.g., operating systems, network infrastructure devices) automatically perform containment actions"},
			{"ref": "RS.MI-01.340", "label": "Ex2", "text": "Allow incident responders to manually select and perform containment actions"},
			{"ref": "RS.MI-01.341", "label": "Ex3", "text": "Allow a third party (e.g., internet service provider, managed security service provider) to perform containment actions on behalf of the organization"},
			{"ref": "RS.MI-01.342", "label": "Ex4", "text": "Automatically transfer compromised endpoints to a remediation virtual local area network (VLAN)"},
		],
	},
	"RS.MI-02": {
		"function": "RS",
		"category": "RS.MI",
		"text": "Incidents are eradicated",
		"basis": "attestation",
		"examples": [
			{"ref": "RS.MI-02.343", "label": "Ex1", "text": "Cybersecurity technologies and cybersecurity features of other technologies (e.g., operating systems, network infrastructure devices) automatically perform eradication actions"},
			{"ref": "RS.MI-02.344", "label": "Ex2", "text": "Allow incident responders to manually select and perform eradication actions"},
			{"ref": "RS.MI-02.345", "label": "Ex3", "text": "Allow a third party (e.g., managed security service provider) to perform eradication actions on behalf of the organization"},
		],
	},
	"RC.RP-01": {
		"function": "RC",
		"category": "RC.RP",
		"text": "The recovery portion of the incident response plan is executed once initiated from the incident response process",
		"basis": "facts",
		"fact_package": "nist.csf.recover",
		"legacy_label": "RC.RP-01",
		"examples": [
			{"ref": "RC.RP-01.346", "label": "Ex1", "text": "Begin recovery procedures during or after incident response processes"},
			{"ref": "RC.RP-01.347", "label": "Ex2", "text": "Make all individuals with recovery responsibilities aware of the plans for recovery and the authorizations required to implement each aspect of the plans"},
		],
	},
	"RC.RP-02": {
		"function": "RC",
		"category": "RC.RP",
		"text": "Recovery actions are selected, scoped, prioritized, and performed",
		"basis": "attestation",
		"examples": [
			{"ref": "RC.RP-02.348", "label": "Ex1", "text": "Select recovery actions based on the criteria defined in the incident response plan and available resources"},
			{"ref": "RC.RP-02.349", "label": "Ex2", "text": "Change planned recovery actions based on a reassessment of organizational needs and resources"},
		],
	},
	"RC.RP-03": {
		"function": "RC",
		"category": "RC.RP",
		"text": "The integrity of backups and other restoration assets is verified before using them for restoration",
		"basis": "attestation",
		"examples": [{"ref": "RC.RP-03.350", "label": "Ex1", "text": "Check restoration assets for indicators of compromise, file corruption, and other integrity issues before use"}],
	},
	"RC.RP-04": {
		"function": "RC",
		"category": "RC.RP",
		"text": "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms",
		"basis": "attestation",
		"examples": [
			{"ref": "RC.RP-04.351", "label": "Ex1", "text": "Use business impact and system categorization records (including service delivery objectives) to validate that essential services are restored in the appropriate order"},
			{"ref": "RC.RP-04.352", "label": "Ex2", "text": "Work with system owners to confirm the successful restoration of systems and the return to normal operations"},
			{"ref": "RC.RP-04.353", "label": "Ex3", "text": "Monitor the performance of restored systems to verify the adequacy of the restoration"},
		],
	},
	"RC.RP-05": {
		"function": "RC",
		"category": "RC.RP",
		"text": "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed",
		"basis": "attestation",
		"examples": [
			{"ref": "RC.RP-05.354", "label": "Ex1", "text": "Check restored assets for indicators of compromise and remediation of root causes of the incident before production use"},
			{"ref": "RC.RP-05.355", "label": "Ex2", "text": "Verify the correctness and adequacy of the restoration actions taken before putting a restored system online"},
		],
	},
	"RC.RP-06": {
		"function": "RC",
		"category": "RC.RP",
		"text": "The end of incident recovery is declared based on criteria, and incident-related documentation is completed",
		"basis": "attestation",
		"examples": [
			{"ref": "RC.RP-06.356", "label": "Ex1", "text": "Prepare an after-action report that documents the incident itself, the response and recovery actions taken, and lessons learned"},
			{"ref": "RC.RP-06.357", "label": "Ex2", "text": "Declare the end of incident recovery once the criteria are met"},
		],
	},
	"RC.CO-03": {
		"function": "RC",
		"category": "RC.CO",
		"text": "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders",
		"basis": "attestation",
		"examples": [
			{"ref": "RC.CO-03.358", "label": "Ex1", "text": "Securely share recovery information, including restoration progress, consistent with response plans and information sharing agreements"},
			{"ref": "RC.CO-03.359", "label": "Ex2", "text": "Regularly update senior leadership on recovery status and restoration progress for major incidents"},
			{"ref": "RC.CO-03.360", "label": "Ex3", "text": "Follow the rules and protocols defined in contracts for incident information sharing between the organization and its suppliers"},
			{"ref": "RC.CO-03.361", "label": "Ex4", "text": "Coordinate crisis communication between the organization and its critical suppliers"},
		],
	},
	"RC.CO-04": {
		"function": "RC",
		"category": "RC.CO",
		"text": "Public updates on incident recovery are shared using approved methods and messaging",
		"basis": "attestation",
		"examples": [
			{"ref": "RC.CO-04.362", "label": "Ex1", "text": "Follow the organization's breach notification procedures for recovering from a data breach incident"},
			{"ref": "RC.CO-04.363", "label": "Ex2", "text": "Explain the steps being taken to recover from the incident and to prevent a recurrence"},
		],
	},
}

default compliant := false

compliant if count(violations) == 0

default assessed_at := "unknown"

assessed_at := input.assessment_date

_in := object.get(input, "nist_csf", {})

_given := s if {
	s := _in.subcategories
	is_object(s)
}

_supplied if _given

_attested(sid) if _given[sid] == true

# violations of the function modules; each is labelled "CSF <subcategory id>: ..."
_fact_violations := ((((gv.violation | id_.violation) | pr.violation) | de.violation) | rs.violation) | rc.violation

_msg_id(msg) := trim_prefix(split(msg, ":")[0], "CSF ")

_fact_failed := {_msg_id(m) | some m in _fact_violations}

_satisfied(sid) if {
	subcategories[sid].basis == "attestation"
	_attested(sid)
}

_satisfied(sid) if {
	subcategories[sid].basis == "facts"
	not _fact_failed[sid]
}

_satisfied_bool(sid) if _satisfied(sid)

else := false

violations contains "NIST CSF 2.0: FAIL-CLOSED - attestations 'input.nist_csf.subcategories' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some sid, s in subcategories
	s.basis == "attestation"
	not _attested(sid)
	msg := sprintf("NIST CSF 2.0 %v (%v %v): not attested satisfied — %v", [sid, s.category, categories[s.category].title, s.text])
}

violations contains msg if {
	some m in _fact_violations
	sid := _msg_id(m)
	s := subcategories[sid]
	s.basis == "facts"
	msg := sprintf("NIST CSF 2.0 %v (%v %v): facts not satisfied — %v", [sid, s.category, categories[s.category].title, m])
}

# a fact violation that names no facts-basis subcategory would otherwise be dropped: report it, fail closed
violations contains msg if {
	some m in _fact_violations
	not subcategories[_msg_id(m)].basis == "facts"
	msg := sprintf("NIST CSF 2.0 Module Contract: fact violation not attributed to a facts-basis subcategory — %v", [m])
}

violations contains msg if {
	some sid, _ in _given
	not subcategories[sid]
	not withdrawn[sid]
	msg := sprintf("NIST CSF 2.0 Input Contract: unknown subcategory id %v — ids are CPRT element identifiers such as GV.OC-01", [sid])
}

violations contains msg if {
	some sid, _ in _given
	w := withdrawn[sid]
	msg := sprintf("NIST CSF 2.0 Input Contract: subcategory %v is withdrawn in CSF 2.0 (%v) and cannot be attested", [sid, w.reason])
}

subcategory_results[sid] := r if {
	some sid, s in subcategories
	r := {
		"function": s.function,
		"category": s.category,
		"text": s.text,
		"basis": s.basis,
		"satisfied": _satisfied_bool(sid),
		"fact_violations": sort([m | some m in _fact_violations; _msg_id(m) == sid]),
	}
}

category_rollup[c] := r if {
	some c, cat in categories
	ids := {sid | some sid, s in subcategories; s.category == c}
	r := {
		"function": cat.function,
		"title": cat.title,
		"subcategories_total": count(ids),
		"subcategories_satisfied": count({sid | some sid in ids; _satisfied(sid)}),
		"not_satisfied": sort([sid | some sid in ids; not _satisfied(sid)]),
		"facts": count({sid | some sid in ids; subcategories[sid].basis == "facts"}),
		"attestation": count({sid | some sid in ids; subcategories[sid].basis == "attestation"}),
	}
}

function_rollup[f] := r if {
	some f, fn in functions
	ids := {sid | some sid, s in subcategories; s.function == f}
	r := {
		"title": fn.title,
		"categories": sort([c | some c, cat in categories; cat.function == f]),
		"subcategories_total": count(ids),
		"subcategories_satisfied": count({sid | some sid in ids; _satisfied(sid)}),
		"not_satisfied": sort([sid | some sid in ids; not _satisfied(sid)]),
		"facts": count({sid | some sid in ids; subcategories[sid].basis == "facts"}),
		"attestation": count({sid | some sid in ids; subcategories[sid].basis == "attestation"}),
		"compliant": count({sid | some sid in ids; not _satisfied(sid)}) == 0,
	}
}

# kept for consumers of the previous report: one entry per function, by name
_function_names := {"GV": "govern", "ID": "identify", "PR": "protect", "DE": "detect", "RS": "respond", "RC": "recover"}

function_summary[name] := r if {
	some f, name in _function_names
	fr := function_rollup[f]
	r := {
		"violations": count(fr.not_satisfied),
		"compliant": fr.compliant,
		"subcategories_total": fr.subcategories_total,
		"subcategories_satisfied": fr.subcategories_satisfied,
	}
}

# lineage of the removed CSF 1.1-era fact checks (data only), keyed by the label each check carried
legacy_fact_checks := object.union_n([gv.legacy, id_.legacy, pr.legacy, de.legacy, rs.legacy, rc.legacy])

total_controls := count(subcategories)

compliance_report := {
	"framework": "NIST Cybersecurity Framework 2.0",
	"version": "2.0",
	"source": source,
	"assessed_at": assessed_at,
	"compliant": compliant,
	"total_controls": total_controls,
	"standard_total": 106, # current subcategories in the CPRT CSF_2_0_0 export (185 subcategory elements, 79 withdrawn)
	"subcategories_satisfied": count({sid | some sid, _ in subcategories; _satisfied(sid)}),
	"basis_counts": {
		"facts": count({sid | some sid, s in subcategories; s.basis == "facts"}),
		"attestation": count({sid | some sid, s in subcategories; s.basis == "attestation"}),
	},
	"functions_total": count(functions),
	"categories_total": count(categories),
	"withdrawn_subcategories": count(withdrawn),
	"withdrawn_categories": count(withdrawn_categories),
	"functions": function_rollup,
	"categories": category_rollup,
	"subcategories": subcategory_results,
	"function_summary": function_summary,
	"legacy_fact_checks": legacy_fact_checks,
	"violation_count": count(violations),
	"violations": violations,
}
