# NIST Privacy Framework Version 1.0 — Core: 5 Functions, 18 Categories, 100 Subcategories.
# One attested row per Subcategory.
#
# Source of truth: NIST Cybersecurity and Privacy Reference Tool (CPRT) JSON export of the Privacy Framework
# (doc_identifier PF_1_0_0, "NIST Privacy Framework: A Tool for Improving Privacy Through Enterprise Risk Management", Version 1.0),
#   https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/PF_1_0_0/export/json?element=all
#   sha256 c20d7fade235a6e2a23abdfab48e091b150ccf82804e89dbb4d1812e0bc96f20, retrieved 2026-10-13.
#   publication page: https://csrc.nist.gov/publications/detail/white-paper/2020/01/16/nist-privacy-framework-version-10/final
# NIST text is public domain. Every id, title and text string below is copied verbatim from that export by
# a generator; nothing is paraphrased (non-breaking spaces in the GV-P text are kept as \u00a0). The export
# nests its lists under response.elements.{documents, elements, relationships}. Parentage (function ->
# category -> subcategory) is taken from the export's `projection` relationships and was checked against
# the id spelling: zero disagreements. Rows are ordered by the export's `sort` elements.
#
# CSF relationship: the export tags every Function, Category and Subcategory with one of three
# `csf_relationship` elements (csfr_none, csfr_adapted, csfr_identical); their titles and definitions are
# carried verbatim in `csf_relationships` and each row carries its tag. The export holds these tags, not a
# prose note; the counts below are derived from the tags.
#   subcategories: csfr_none 47, csfr_adapted 26, csfr_identical 27
#   PROTECT-P (tagged csfr_adapted): subcategories csfr_identical 22, csfr_adapted 8, csfr_none 0
#
# Id scheme (exactly the CPRT element_identifier values):
#   function     ID-P, GV-P, CT-P, CM-P, PR-P                    (5)
#   category     ID.IM-P, GV.PO-P, …                            (18)
#   subcategory  ID.IM-P1, GV.PO-P1, PR.PT-P4, …               (100)
#
# Functions:
#   ID-P   IDENTIFY-P        4 categories,  21 subcategories
#   GV-P   GOVERN-P          4 categories,  20 subcategories
#   CT-P   CONTROL-P         3 categories,  19 subcategories
#   CM-P   COMMUNICATE-P     2 categories,  10 subcategories
#   PR-P   PROTECT-P         5 categories,  30 subcategories
#
# Input: input.nist_privacy_framework.subcategories["ID.IM-P1"] == true means the organization attests that the
# Subcategory's outcome is achieved. Fail-closed: a missing or non-object subcategories container is a FAIL-CLOSED
# violation; a missing, false or non-true value is a violation; an unknown id is a violation. A Category is
# achieved only when every one of its Subcategories is true (every Category has at least one).
#
# Query: POST /v1/data/nist_privacy_framework/main/compliance_report

# METADATA
# title: "NIST Privacy Framework 1.0 — 100 Core Subcategories (CPRT ids), attested"
# custom:
#   class: compliance
#   framework: nist_privacy_framework
#   source: nist
#   domains: [privacy, us-federal]
#   coverage:
#     checks: 129
#     cited: 127
#     expected: 100
#     found: 127
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist_privacy_framework.main

import rego.v1

source := {
	"publication": "NIST Privacy Framework: A Tool for Improving Privacy Through Enterprise Risk Management",
	"doc_identifier": "PF_1_0_0",
	"version": "Version 1.0",
	"website": "https://csrc.nist.gov/publications/detail/white-paper/2020/01/16/nist-privacy-framework-version-10/final",
	"export_url": "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/PF_1_0_0/export/json?element=all",
	"export_sha256": "c20d7fade235a6e2a23abdfab48e091b150ccf82804e89dbb4d1812e0bc96f20",
	"retrieved": "2026-10-13",
}

csf_relationships := {
	"csfr_none": {"title": "CSF Relationship None", "text": "Elements associated with this element were not formulated directly using Cybersecurity Framework material."},
	"csfr_adapted": {"title": "CSF Relationship Adapted", "text": "The Function, Category, or Subcategory aligns with the Cybersecurity Framework, but the text has been adapted for the Privacy Framework."},
	"csfr_identical": {"title": "CSF Relationship Identical", "text": "The Category or Subcategory is identical to the Cybersecurity Framework."},
}

functions := {
	"ID-P": {"title": "IDENTIFY-P", "text": "Develop the organizational understanding to manage privacy risk for individuals arising from data processing.", "csf_relationship": "csfr_adapted"},
	"GV-P": {"title": "GOVERN-P", "text": "Develop\u00a0and implement\u00a0the organizational governance structure to enable an ongoing understanding of the organization’s risk management priorities\u00a0that are\u00a0informed by privacy risk.", "csf_relationship": "csfr_none"},
	"CT-P": {"title": "CONTROL-P", "text": "Develop and implement appropriate activities to enable organizations or individuals to manage data with sufficient granularity to manage privacy risks.", "csf_relationship": "csfr_none"},
	"CM-P": {"title": "COMMUNICATE-P", "text": "Develop and implement appropriate activities to enable organizations and individuals to have a reliable understanding and engage in a dialogue about how data are processed and associated privacy risks.", "csf_relationship": "csfr_none"},
	"PR-P": {"title": "PROTECT-P", "text": "Develop and implement appropriate data processing safeguards.", "csf_relationship": "csfr_adapted"},
}

categories := {
	"ID.IM-P": {"function": "ID-P", "title": "Inventory and Mapping", "text": "Data processing by systems, products, or services is understood and informs the management of privacy risk.", "csf_relationship": "csfr_none"},
	"ID.BE-P": {"function": "ID-P", "title": "Business Environment", "text": "The organization’s mission, objectives, stakeholders, and activities are understood and prioritized; this information is used to inform privacy roles, responsibilities, and risk management decisions.", "csf_relationship": "csfr_adapted"},
	"ID.RA-P": {"function": "ID-P", "title": "Risk Assessment", "text": "The organization understands the privacy risks to individuals and how such privacy risks may create follow-on impacts on organizational operations, including mission, functions, other risk management priorities (e.g., compliance, financial), reputation, workforce, and culture.", "csf_relationship": "csfr_adapted"},
	"ID.DE-P": {"function": "ID-P", "title": "Data Processing Ecosystem Risk Management", "text": "The organization’s priorities, constraints, risk tolerance, and assumptions are established and used to support risk decisions associated with managing privacy risk and third parties within the data processing ecosystem. The organization has established and implemented the processes to identify, assess, and manage privacy risks within the data processing ecosystem.", "csf_relationship": "csfr_adapted"},
	"GV.PO-P": {"function": "GV-P", "title": "Governance Policies, Processes, and Procedures", "text": "The policies, processes, and procedures to manage and monitor the organization’s regulatory, legal, risk, environmental, and operational requirements are understood and inform the management of privacy risk.", "csf_relationship": "csfr_adapted"},
	"GV.RM-P": {"function": "GV-P", "title": "Risk Management Strategy", "text": "The organization’s priorities, constraints, risk tolerances, and assumptions are established and used to support operational risk decisions.", "csf_relationship": "csfr_identical"},
	"GV.AT-P": {"function": "GV-P", "title": "Awareness and Training", "text": "The organization’s workforce and third parties engaged in data processing are provided privacy awareness education and are trained to perform their privacy-related duties and responsibilities consistent with related policies, processes, procedures, and agreements and organizational privacy values.", "csf_relationship": "csfr_adapted"},
	"GV.MT-P": {"function": "GV-P", "title": "Monitoring and Review", "text": "The policies, processes, and procedures for ongoing review of the organization’s privacy posture are understood and inform the management of privacy risk.", "csf_relationship": "csfr_none"},
	"CT.PO-P": {"function": "CT-P", "title": "Data Processing Policies, Processes, and Procedures", "text": "Policies, processes, and procedures are maintained and used to manage data processing (e.g., purpose, scope, roles and responsibilities in the data processing ecosystem, and management commitment) consistent with the organization’s risk strategy to protect individuals’ privacy.", "csf_relationship": "csfr_none"},
	"CT.DM-P": {"function": "CT-P", "title": "Data Processing Management", "text": "Data are managed consistent with the organization’s risk strategy to protect individuals’ privacy, increase manageability, and enable the implementation of privacy principles (e.g., individual participation, data quality, data minimization).", "csf_relationship": "csfr_none"},
	"CT.DP-P": {"function": "CT-P", "title": "Disassociated Processing", "text": "Data processing solutions increase disassociability consistent with the organization’s risk strategy to protect individuals’ privacy and enable implementation of privacy principles (e.g., data minimization).", "csf_relationship": "csfr_none"},
	"CM.PO-P": {"function": "CM-P", "title": "Communication Policies, Processes, and Procedures", "text": "Policies, processes, and procedures are maintained and used to increase transparency of the organization’s data processing practices (e.g., purpose, scope, roles and responsibilities in the data processing ecosystem, and management commitment) and associated privacy risks.", "csf_relationship": "csfr_none"},
	"CM.AW-P": {"function": "CM-P", "title": "Data Processing Awareness", "text": "Individuals and organizations have reliable knowledge about data processing practices and associated privacy risks, and effective mechanisms are used and maintained to increase predictability consistent with the organization’s risk strategy to protect individuals’ privacy.", "csf_relationship": "csfr_none"},
	"PR.PO-P": {"function": "PR-P", "title": "Data Protection Policies, Processes, and Procedures", "text": "Security and privacy policies (e.g., purpose, scope, roles and responsibilities in the data processing ecosystem, and management commitment), processes, and procedures are maintained and used to manage the protection of data.", "csf_relationship": "csfr_adapted"},
	"PR.AC-P": {"function": "PR-P", "title": "Identity Management, Authentication, and Access Control", "text": "Access to data and devices is limited to authorized individuals, processes, and devices, and is managed consistent with the assessed risk of unauthorized access.", "csf_relationship": "csfr_adapted"},
	"PR.DS-P": {"function": "PR-P", "title": "Data Security", "text": "Data are managed consistent with the organization’s risk strategy to protect individuals’ privacy and maintain data confidentiality, integrity, and availability.", "csf_relationship": "csfr_adapted"},
	"PR.MA-P": {"function": "PR-P", "title": "Maintenance", "text": "System maintenance and repairs are performed consistent with policies, processes, and procedures.", "csf_relationship": "csfr_adapted"},
	"PR.PT-P": {"function": "PR-P", "title": "Protective Technology", "text": "Technical security solutions are managed to ensure the security and resilience of systems/products/services and associated data, consistent with related policies, processes, procedures, and agreements.", "csf_relationship": "csfr_adapted"},
}

subcategories := {
	"ID.IM-P1": {"function": "ID-P", "category": "ID.IM-P", "text": "Systems/products/services that process data are inventoried.", "csf_relationship": "csfr_none"},
	"ID.IM-P2": {"function": "ID-P", "category": "ID.IM-P", "text": "Owners or operators (e.g., the organization or third parties such as service providers, partners, customers, and developers) and their roles with respect to the systems/products/services and components (e.g., internal or external) that process data are inventoried.", "csf_relationship": "csfr_none"},
	"ID.IM-P3": {"function": "ID-P", "category": "ID.IM-P", "text": "Categories of individuals (e.g., customers, employees or prospective employees, consumers) whose data are being processed are inventoried.", "csf_relationship": "csfr_none"},
	"ID.IM-P4": {"function": "ID-P", "category": "ID.IM-P", "text": "Data actions of the systems/products/services are inventoried.", "csf_relationship": "csfr_none"},
	"ID.IM-P5": {"function": "ID-P", "category": "ID.IM-P", "text": "The purposes for the data actions are inventoried.", "csf_relationship": "csfr_none"},
	"ID.IM-P6": {"function": "ID-P", "category": "ID.IM-P", "text": "Data elements within the data actions are inventoried.", "csf_relationship": "csfr_none"},
	"ID.IM-P7": {"function": "ID-P", "category": "ID.IM-P", "text": "The data processing environment is identified (e.g., geographic location, internal, cloud, third parties).", "csf_relationship": "csfr_none"},
	"ID.IM-P8": {"function": "ID-P", "category": "ID.IM-P", "text": "Data processing is mapped, illustrating the data actions and associated data elements for systems/products/services, including components; roles of the component owners/operators; and interactions of individuals or third parties with the systems/products/services.", "csf_relationship": "csfr_none"},
	"ID.BE-P1": {"function": "ID-P", "category": "ID.BE-P", "text": "The organization’s role(s) in the data processing ecosystem are identified and communicated.", "csf_relationship": "csfr_adapted"},
	"ID.BE-P2": {"function": "ID-P", "category": "ID.BE-P", "text": "Priorities for organizational mission, objectives, and activities are established and communicated.", "csf_relationship": "csfr_identical"},
	"ID.BE-P3": {"function": "ID-P", "category": "ID.BE-P", "text": "Systems/products/services that support organizational priorities are identified and key requirements communicated.", "csf_relationship": "csfr_none"},
	"ID.RA-P1": {"function": "ID-P", "category": "ID.RA-P", "text": "Contextual factors related to the systems/products/services and the data actions are identified (e.g., individuals’ demographics and privacy interests or perceptions, data sensitivity and/or types, visibility of data processing to individuals and third parties).", "csf_relationship": "csfr_none"},
	"ID.RA-P2": {"function": "ID-P", "category": "ID.RA-P", "text": "Data analytic inputs and outputs are identified and evaluated for bias.", "csf_relationship": "csfr_none"},
	"ID.RA-P3": {"function": "ID-P", "category": "ID.RA-P", "text": "Potential problematic data actions and associated problems are identified.", "csf_relationship": "csfr_none"},
	"ID.RA-P4": {"function": "ID-P", "category": "ID.RA-P", "text": "Problematic data actions, likelihoods, and impacts are used to determine and prioritize risk.", "csf_relationship": "csfr_adapted"},
	"ID.RA-P5": {"function": "ID-P", "category": "ID.RA-P", "text": "Risk responses are identified, prioritized, and implemented.", "csf_relationship": "csfr_adapted"},
	"ID.DE-P1": {"function": "ID-P", "category": "ID.DE-P", "text": "Data processing ecosystem risk management policies, processes, and procedures are identified, established, assessed, managed, and agreed to by organizational stakeholders.", "csf_relationship": "csfr_adapted"},
	"ID.DE-P2": {"function": "ID-P", "category": "ID.DE-P", "text": "Data processing ecosystem parties (e.g., service providers, customers, partners, product manufacturers, application developers) are identified, prioritized, and assessed using a privacy risk assessment process.", "csf_relationship": "csfr_adapted"},
	"ID.DE-P3": {"function": "ID-P", "category": "ID.DE-P", "text": "Contracts with data processing ecosystem parties are used to implement appropriate measures designed to meet the objectives of an organization’s privacy program.", "csf_relationship": "csfr_adapted"},
	"ID.DE-P4": {"function": "ID-P", "category": "ID.DE-P", "text": "Interoperability frameworks or similar multi-party approaches are used to manage data processing ecosystem privacy risks.", "csf_relationship": "csfr_none"},
	"ID.DE-P5": {"function": "ID-P", "category": "ID.DE-P", "text": "Data processing ecosystem parties are routinely assessed using audits, test results, or other forms of evaluations to confirm they are meeting their contractual, interoperability framework, or other obligations.", "csf_relationship": "csfr_adapted"},
	"GV.PO-P1": {"function": "GV-P", "category": "GV.PO-P", "text": "Organizational privacy values and policies (e.g., conditions on data processing such as data uses or retention periods, individuals’ prerogatives with respect to data processing) are established and communicated.", "csf_relationship": "csfr_adapted"},
	"GV.PO-P2": {"function": "GV-P", "category": "GV.PO-P", "text": "Processes to instill organizational privacy values within system/product/service development and operations are established and in place.", "csf_relationship": "csfr_none"},
	"GV.PO-P3": {"function": "GV-P", "category": "GV.PO-P", "text": "Roles and responsibilities for the workforce are established with respect to privacy.", "csf_relationship": "csfr_adapted"},
	"GV.PO-P4": {"function": "GV-P", "category": "GV.PO-P", "text": "Privacy roles and responsibilities are coordinated and aligned with third-party stakeholders (e.g., service providers, customers, partners).", "csf_relationship": "csfr_adapted"},
	"GV.PO-P5": {"function": "GV-P", "category": "GV.PO-P", "text": "Legal, regulatory, and contractual requirements regarding privacy are understood and managed.", "csf_relationship": "csfr_adapted"},
	"GV.PO-P6": {"function": "GV-P", "category": "GV.PO-P", "text": "Governance and risk management policies, processes, and procedures address privacy risks.", "csf_relationship": "csfr_adapted"},
	"GV.RM-P1": {"function": "GV-P", "category": "GV.RM-P", "text": "Risk management processes are established, managed, and agreed to by organizational stakeholders.", "csf_relationship": "csfr_identical"},
	"GV.RM-P2": {"function": "GV-P", "category": "GV.RM-P", "text": "Organizational risk tolerance is determined and clearly expressed.", "csf_relationship": "csfr_identical"},
	"GV.RM-P3": {"function": "GV-P", "category": "GV.RM-P", "text": "The organization’s determination of risk tolerance is informed by its role(s) in the data processing ecosystem.", "csf_relationship": "csfr_adapted"},
	"GV.AT-P1": {"function": "GV-P", "category": "GV.AT-P", "text": "The workforce is informed and trained on its roles and responsibilities.", "csf_relationship": "csfr_adapted"},
	"GV.AT-P2": {"function": "GV-P", "category": "GV.AT-P", "text": "Senior executives understand their roles and responsibilities.", "csf_relationship": "csfr_identical"},
	"GV.AT-P3": {"function": "GV-P", "category": "GV.AT-P", "text": "Privacy personnel understand their roles and responsibilities.", "csf_relationship": "csfr_adapted"},
	"GV.AT-P4": {"function": "GV-P", "category": "GV.AT-P", "text": "Third parties (e.g., service providers, customers, partners) understand their roles and responsibilities.", "csf_relationship": "csfr_adapted"},
	"GV.MT-P1": {"function": "GV-P", "category": "GV.MT-P", "text": "Privacy risk is re-evaluated on an ongoing basis and as key factors, including the organization’s business environment (e.g., introduction of new technologies), governance (e.g., legal obligations, risk tolerance), data processing, and systems/products/services change.", "csf_relationship": "csfr_none"},
	"GV.MT-P2": {"function": "GV-P", "category": "GV.MT-P", "text": "Privacy values, policies, and training are reviewed and any updates are communicated.", "csf_relationship": "csfr_none"},
	"GV.MT-P3": {"function": "GV-P", "category": "GV.MT-P", "text": "Policies, processes, and procedures for assessing compliance with legal requirements and privacy policies are established and in place.", "csf_relationship": "csfr_none"},
	"GV.MT-P4": {"function": "GV-P", "category": "GV.MT-P", "text": "Policies, processes, and procedures for communicating progress on managing privacy risks are established and in place.", "csf_relationship": "csfr_none"},
	"GV.MT-P5": {"function": "GV-P", "category": "GV.MT-P", "text": "Policies, processes, and procedures are established and in place to receive, analyze, and respond to problematic data actions disclosed to the organization from internal and external sources (e.g., internal discovery, privacy researchers, professional events).", "csf_relationship": "csfr_none"},
	"GV.MT-P6": {"function": "GV-P", "category": "GV.MT-P", "text": "Policies, processes, and procedures incorporate lessons learned from problematic data actions.", "csf_relationship": "csfr_none"},
	"GV.MT-P7": {"function": "GV-P", "category": "GV.MT-P", "text": "Policies, processes, and procedures for receiving, tracking, and responding to complaints, concerns, and questions from individuals about organizational privacy practices are established and in place.", "csf_relationship": "csfr_none"},
	"CT.PO-P1": {"function": "CT-P", "category": "CT.PO-P", "text": "Policies, processes, and procedures for authorizing data processing (e.g., organizational decisions, individual consent), revoking authorizations, and maintaining authorizations are established and in place.", "csf_relationship": "csfr_none"},
	"CT.PO-P2": {"function": "CT-P", "category": "CT.PO-P", "text": "Policies, processes, and procedures for enabling data review, transfer, sharing or disclosure, alteration, and deletion are established and in place (e.g., to maintain data quality, manage data retention).", "csf_relationship": "csfr_none"},
	"CT.PO-P3": {"function": "CT-P", "category": "CT.PO-P", "text": "Policies, processes, and procedures for enabling individuals’ data processing preferences and requests are established and in place.", "csf_relationship": "csfr_none"},
	"CT.PO-P4": {"function": "CT-P", "category": "CT.PO-P", "text": "A data life cycle to manage data is aligned and implemented with the system development life cycle to manage systems.", "csf_relationship": "csfr_adapted"},
	"CT.DM-P1": {"function": "CT-P", "category": "CT.DM-P", "text": "Data elements can be accessed for review.", "csf_relationship": "csfr_none"},
	"CT.DM-P2": {"function": "CT-P", "category": "CT.DM-P", "text": "Data elements can be accessed for transmission or disclosure.", "csf_relationship": "csfr_none"},
	"CT.DM-P3": {"function": "CT-P", "category": "CT.DM-P", "text": "Data elements can be accessed for alteration.", "csf_relationship": "csfr_none"},
	"CT.DM-P4": {"function": "CT-P", "category": "CT.DM-P", "text": "Data elements can be accessed for deletion.", "csf_relationship": "csfr_none"},
	"CT.DM-P5": {"function": "CT-P", "category": "CT.DM-P", "text": "Data are destroyed according to policy.", "csf_relationship": "csfr_identical"},
	"CT.DM-P6": {"function": "CT-P", "category": "CT.DM-P", "text": "Data are transmitted using standardized formats.", "csf_relationship": "csfr_none"},
	"CT.DM-P7": {"function": "CT-P", "category": "CT.DM-P", "text": "Mechanisms for transmitting processing permissions and related data values with data elements are established and in place.", "csf_relationship": "csfr_none"},
	"CT.DM-P8": {"function": "CT-P", "category": "CT.DM-P", "text": "Audit/log records are determined, documented, implemented, and reviewed in accordance with policy and incorporating the principle of data minimization.", "csf_relationship": "csfr_adapted"},
	"CT.DM-P9": {"function": "CT-P", "category": "CT.DM-P", "text": "Technical measures implemented to manage data processing are tested and assessed.", "csf_relationship": "csfr_none"},
	"CT.DM-P10": {"function": "CT-P", "category": "CT.DM-P", "text": "Stakeholder privacy preferences are included in algorithmic design objectives and outputs are evaluated against these preferences.", "csf_relationship": "csfr_none"},
	"CT.DP-P1": {"function": "CT-P", "category": "CT.DP-P", "text": "Data are processed to limit observability and linkability (e.g., data actions take place on local devices, privacy-preserving cryptography).", "csf_relationship": "csfr_none"},
	"CT.DP-P2": {"function": "CT-P", "category": "CT.DP-P", "text": "Data are processed to limit the identification of individuals (e.g., de-identification privacy techniques, tokenization).", "csf_relationship": "csfr_none"},
	"CT.DP-P3": {"function": "CT-P", "category": "CT.DP-P", "text": "Data are processed to limit the formulation of inferences about individuals’ behavior or activities (e.g., data processing is decentralized, distributed architectures).", "csf_relationship": "csfr_none"},
	"CT.DP-P4": {"function": "CT-P", "category": "CT.DP-P", "text": "System or device configurations permit selective collection or disclosure of data elements.", "csf_relationship": "csfr_none"},
	"CT.DP-P5": {"function": "CT-P", "category": "CT.DP-P", "text": "Attribute references are substituted for attribute values.", "csf_relationship": "csfr_none"},
	"CM.PO-P1": {"function": "CM-P", "category": "CM.PO-P", "text": "Transparency policies, processes, and procedures for communicating data processing purposes, practices, and associated privacy risks are established and in place.", "csf_relationship": "csfr_none"},
	"CM.PO-P2": {"function": "CM-P", "category": "CM.PO-P", "text": "Roles and responsibilities (e.g., public relations) for communicating data processing purposes, practices, and associated privacy risks are established.", "csf_relationship": "csfr_none"},
	"CM.AW-P1": {"function": "CM-P", "category": "CM.AW-P", "text": "Mechanisms (e.g., notices, internal or public reports) for communicating data processing purposes, practices, associated privacy risks, and options for enabling individuals’ data processing preferences and requests are established and in place.", "csf_relationship": "csfr_none"},
	"CM.AW-P2": {"function": "CM-P", "category": "CM.AW-P", "text": "Mechanisms for obtaining feedback from individuals (e.g., surveys or focus groups) about data processing and associated privacy risks are established and in place.", "csf_relationship": "csfr_none"},
	"CM.AW-P3": {"function": "CM-P", "category": "CM.AW-P", "text": "System/product/service design enables data processing visibility.", "csf_relationship": "csfr_none"},
	"CM.AW-P4": {"function": "CM-P", "category": "CM.AW-P", "text": "Records of data disclosures and sharing are maintained and can be accessed for review or transmission/disclosure.", "csf_relationship": "csfr_none"},
	"CM.AW-P5": {"function": "CM-P", "category": "CM.AW-P", "text": "Data corrections or deletions can be communicated to individuals or organizations (e.g., data sources) in the data processing ecosystem.", "csf_relationship": "csfr_none"},
	"CM.AW-P6": {"function": "CM-P", "category": "CM.AW-P", "text": "Data provenance and lineage are maintained and can be accessed for review or transmission/disclosure.", "csf_relationship": "csfr_none"},
	"CM.AW-P7": {"function": "CM-P", "category": "CM.AW-P", "text": "Impacted individuals and organizations are notified about a privacy breach or event.", "csf_relationship": "csfr_none"},
	"CM.AW-P8": {"function": "CM-P", "category": "CM.AW-P", "text": "Individuals are provided with mitigation mechanisms (e.g., credit monitoring, consent withdrawal, data alteration or deletion) to address impacts of problematic data actions.", "csf_relationship": "csfr_none"},
	"PR.PO-P1": {"function": "PR-P", "category": "PR.PO-P", "text": "A baseline configuration of information technology is created and maintained incorporating security principles (e.g., concept of least functionality).", "csf_relationship": "csfr_adapted"},
	"PR.PO-P2": {"function": "PR-P", "category": "PR.PO-P", "text": "Configuration change control processes are established and in place.", "csf_relationship": "csfr_adapted"},
	"PR.PO-P3": {"function": "PR-P", "category": "PR.PO-P", "text": "Backups of information are conducted, maintained, and tested.", "csf_relationship": "csfr_identical"},
	"PR.PO-P4": {"function": "PR-P", "category": "PR.PO-P", "text": "Policy and regulations regarding the physical operating environment for organizational assets are met.", "csf_relationship": "csfr_identical"},
	"PR.PO-P5": {"function": "PR-P", "category": "PR.PO-P", "text": "Protection processes are improved.", "csf_relationship": "csfr_identical"},
	"PR.PO-P6": {"function": "PR-P", "category": "PR.PO-P", "text": "Effectiveness of protection technologies is shared.", "csf_relationship": "csfr_identical"},
	"PR.PO-P7": {"function": "PR-P", "category": "PR.PO-P", "text": "Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are established, in place, and managed.", "csf_relationship": "csfr_adapted"},
	"PR.PO-P8": {"function": "PR-P", "category": "PR.PO-P", "text": "Response and recovery plans are tested.", "csf_relationship": "csfr_identical"},
	"PR.PO-P9": {"function": "PR-P", "category": "PR.PO-P", "text": "Privacy procedures are included in human resources practices (e.g., deprovisioning, personnel screening).", "csf_relationship": "csfr_adapted"},
	"PR.PO-P10": {"function": "PR-P", "category": "PR.PO-P", "text": "A vulnerability management plan is developed and implemented.", "csf_relationship": "csfr_identical"},
	"PR.AC-P1": {"function": "PR-P", "category": "PR.AC-P", "text": "Identities and credentials are issued, managed, verified, revoked, and audited for authorized individuals, processes, and devices.", "csf_relationship": "csfr_adapted"},
	"PR.AC-P2": {"function": "PR-P", "category": "PR.AC-P", "text": "Physical access to data and devices is managed.", "csf_relationship": "csfr_adapted"},
	"PR.AC-P3": {"function": "PR-P", "category": "PR.AC-P", "text": "Remote access is managed.", "csf_relationship": "csfr_identical"},
	"PR.AC-P4": {"function": "PR-P", "category": "PR.AC-P", "text": "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties.", "csf_relationship": "csfr_identical"},
	"PR.AC-P5": {"function": "PR-P", "category": "PR.AC-P", "text": "Network integrity is protected (e.g., network segregation, network segmentation).", "csf_relationship": "csfr_identical"},
	"PR.AC-P6": {"function": "PR-P", "category": "PR.AC-P", "text": "Individuals and devices are proofed and bound to credentials, and authenticated commensurate with the risk of the transaction (e.g., individuals’ security and privacy risks and other organizational risks).", "csf_relationship": "csfr_adapted"},
	"PR.DS-P1": {"function": "PR-P", "category": "PR.DS-P", "text": "Data-at-rest are protected.", "csf_relationship": "csfr_identical"},
	"PR.DS-P2": {"function": "PR-P", "category": "PR.DS-P", "text": "Data-in-transit are protected.", "csf_relationship": "csfr_identical"},
	"PR.DS-P3": {"function": "PR-P", "category": "PR.DS-P", "text": "Systems/products/services and associated data are formally managed throughout removal, transfers, and disposition.", "csf_relationship": "csfr_adapted"},
	"PR.DS-P4": {"function": "PR-P", "category": "PR.DS-P", "text": "Adequate capacity to ensure availability is maintained.", "csf_relationship": "csfr_identical"},
	"PR.DS-P5": {"function": "PR-P", "category": "PR.DS-P", "text": "Protections against data leaks are implemented.", "csf_relationship": "csfr_identical"},
	"PR.DS-P6": {"function": "PR-P", "category": "PR.DS-P", "text": "Integrity checking mechanisms are used to verify software, firmware, and information integrity.", "csf_relationship": "csfr_identical"},
	"PR.DS-P7": {"function": "PR-P", "category": "PR.DS-P", "text": "The development and testing environment(s) are separate from the production environment.", "csf_relationship": "csfr_identical"},
	"PR.DS-P8": {"function": "PR-P", "category": "PR.DS-P", "text": "Integrity checking mechanisms are used to verify hardware integrity.", "csf_relationship": "csfr_identical"},
	"PR.MA-P1": {"function": "PR-P", "category": "PR.MA-P", "text": "Maintenance and repair of organizational assets are performed and logged, with approved and controlled tools.", "csf_relationship": "csfr_identical"},
	"PR.MA-P2": {"function": "PR-P", "category": "PR.MA-P", "text": "Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access.", "csf_relationship": "csfr_identical"},
	"PR.PT-P1": {"function": "PR-P", "category": "PR.PT-P", "text": "Removable media is protected and its use restricted according to policy.", "csf_relationship": "csfr_identical"},
	"PR.PT-P2": {"function": "PR-P", "category": "PR.PT-P", "text": "The principle of least functionality is incorporated by configuring systems to provide only essential capabilities.", "csf_relationship": "csfr_identical"},
	"PR.PT-P3": {"function": "PR-P", "category": "PR.PT-P", "text": "Communications and control networks are protected.", "csf_relationship": "csfr_identical"},
	"PR.PT-P4": {"function": "PR-P", "category": "PR.PT-P", "text": "Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve resilience requirements in normal and adverse situations.", "csf_relationship": "csfr_identical"},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_privacy_framework", {})

_given := s if {
	s := _in.subcategories
	is_object(s)
}

_supplied if _given

_true(id) if _given[id] == true

_by_category[c] := ids if {
	some c, _ in categories
	ids := {id | some id; s := subcategories[id]; s.category == c}
}

violations contains "NIST Privacy Framework 1.0: FAIL-CLOSED - subcategories 'input.nist_privacy_framework.subcategories' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, s in subcategories
	not _true(id)
	c := categories[s.category]
	msg := sprintf("NIST Privacy Framework %v (%v %v): not attested achieved — %v", [id, s.category, c.title, s.text])
}

violations contains msg if {
	some id, _ in _given
	not subcategories[id]
	msg := sprintf("NIST Privacy Framework Input Contract: unknown subcategory id %v — ids are CPRT element identifiers such as ID.IM-P1", [id])
}

# a category with no subcategories can never be achieved (no vacuous pass)
_cat_achieved(c) if {
	ids := _by_category[c]
	count(ids) > 0
	every id in ids { _true(id) }
}

_cat_achieved_bool(c) if _cat_achieved(c)

else := false

category_rollup[c] := r if {
	some c, cat in categories
	ids := _by_category[c]
	unmet := sort([id | some id in ids; not _true(id)])
	r := {
		"function": cat.function,
		"title": cat.title,
		"csf_relationship": cat.csf_relationship,
		"subcategories_total": count(ids),
		"subcategories_achieved": count(ids) - count(unmet),
		"achieved": _cat_achieved_bool(c),
		"not_achieved": unmet,
	}
}

function_rollup[f] := r if {
	some f, fn in functions
	cats := {c | some c; cat := categories[c]; cat.function == f}
	ids := {id | some id; s := subcategories[id]; s.function == f}
	r := {
		"title": fn.title,
		"csf_relationship": fn.csf_relationship,
		"subcategories_total": count(ids),
		"subcategories_achieved": count({id | some id in ids; _true(id)}),
		"categories_total": count(cats),
		"categories_achieved": count({c | some c in cats; _cat_achieved(c)}),
		"categories_not_achieved": sort([c | some c in cats; not _cat_achieved(c)]),
	}
}

csf_relationship_counts[k] := n if {
	some k, _ in csf_relationships
	n := count({id | some id; s := subcategories[id]; s.csf_relationship == k})
}

compliance_report := {
	"framework": "NIST Privacy Framework 1.0",
	"standard": "NIST Privacy Framework: A Tool for Improving Privacy Through Enterprise Risk Management, Version 1.0 — Core",
	"source": source,
	"compliant": compliant,
	"total_controls": count(subcategories),
	"standard_total": 100, # subcategory elements in the CPRT PF_1_0_0 export
	"subcategories_total": count(subcategories),
	"subcategories_achieved": count({id | some id; _ = subcategories[id]; _true(id)}),
	"categories_total": count(categories),
	"categories_achieved": count({c | some c; _ = categories[c]; _cat_achieved(c)}),
	"functions_total": count(functions),
	"functions": function_rollup,
	"categories": category_rollup,
	"csf_relationships": csf_relationships,
	"csf_relationship_counts": csf_relationship_counts,
	"violation_count": count(violations),
	"violations": violations,
}
