# CERT Resilience Management Model (CERT-RMM), Version 1.2 — specific practices of the 26 process areas.
# Software Engineering Institute, Carnegie Mellon University (Caralli, Allen, White, Young, Mehravari, Curtis),
# February 2016. One attested row per specific practice (XX:SGn.SPm).
#
# Source: https://www.sei.cmu.edu/documents/1629/CERT_Resilience_Management_Model_Version_1_2.pdf
#   (linked from https://www.sei.cmu.edu/library/cert-resilience-management-model-cert-rmm-version-12/)
#   sha256 7dafea8f4fb777bbf03078b91fd810a658df9e228c418bcf1f101073daadc17b (stable across two downloads), 858 pages,
#   PDF modified 2024-07-11, retrieved 2026-10-14.
# STATUS (checked 2026-10-14): CURRENT. v1.2 (February 2016) is the latest release in the SEI CERT-RMM collection;
#   no successor is listed.
#
# LICENCE — NOT FREELY REUSABLE. Copyright 2016 Carnegie Mellon University. The notice permits internal use, and
#   external reproduction only "in its entirety, without modification"; any other external or commercial use
#   needs SEI permission (permission@sei.cmu.edu); U.S. government entities are exempt. This module therefore
#   carries ONLY the practice/goal identifiers, the SEI practice, goal and process-area titles, and a one-line
#   `summary` per practice that is an AAC paraphrase (written for this library, not SEI text). No practice
#   statement, subpractice, typical work product or goal statement is reproduced. CERT and CERT-RMM are
#   registered marks of Carnegie Mellon University.
#
# Extraction (generator over `pdftotext -layout`):
#   248 specific practices = the body headings "XX:SGn.SPm Title"; the same 248 ids appear in the 26
#   "Summary of Specific Goals and Practices" tables (0 differences). Two titles wrap onto a second line and were
#   joined: RRM:SG1.SP5, RTSE:SG2.SP2 (checked against the summary tables).
#   93 specific goals (XX:SGn) and the generic goals/practices (GG1-GG3, 13 GPs: GG1.GP1, GG2.GP1-GP10,
#   GG3.GP1-GP2, from the "Generic Goals and Practices" appendix; elaborated in every process area as XX:GGn.GPm)
#   are carried as data only: they are capability/institutionalisation levels, not attested rows.
#   Process-area categories (Engineering / Enterprise / Operations / Process) are the label under each PA title.
# Source irregularities (not rows): three cross-references in prose cite ids that have no heading —
#   AM:SG2.SP3 (Access Management has one goal), IMC:SG5.SP3 (IMC:SG5 has two practices), IMG:SG1.SP1 (no IMG
#   process area; Incident Management and Control is IMC). FRM:SG1.SP1 and EF:SG3.SP1 share the same title.
#
# Process areas (practices / specific goals):
#   ADM   Asset Definition and Management              Engineering    7 / 3
#   AM    Access Management                            Operations     4 / 1
#   COMM  Communications                               Enterprise     8 / 3
#   COMP  Compliance                                   Enterprise    10 / 4
#   CTRL  Controls Management                          Engineering    4 / 4
#   EC    Environmental Control                        Operations    11 / 4
#   EF    Enterprise Focus                             Enterprise    11 / 4
#   EXD   External Dependencies Management             Operations    10 / 4
#   FRM   Financial Resource Management                Enterprise    11 / 5
#   HRM   Human Resource Management                    Enterprise    12 / 4
#   ID    Identity Management                          Operations     7 / 2
#   IMC   Incident Management and Control              Operations    14 / 5
#   KIM   Knowledge and Information Management         Operations    14 / 6
#   MA    Measurement and Analysis                     Process        8 / 2
#   MON   Monitoring                                   Process        8 / 2
#   OPD   Organizational Process Definition            Process        6 / 1
#   OPF   Organizational Process Focus                 Process        9 / 3
#   OTA   Organizational Training and Awareness        Enterprise    12 / 4
#   PM    People Management                            Operations     8 / 3
#   RISK  Risk Management                              Enterprise    13 / 6
#   RRD   Resilience Requirements Development          Engineering    6 / 3
#   RRM   Resilience Requirements Management           Engineering    5 / 1
#   RTSE  Resilient Technical Solution Engineering     Engineering    9 / 3
#   SC    Service Continuity                           Engineering   20 / 7
#   TM    Technology Management                        Operations    14 / 5
#   VAR   Vulnerability Analysis and Resolution        Operations     7 / 4
#
# Input: input.cert_rmm.practices["ADM:SG1.SP1"] == true means the organisation attests that specific practice is
# performed. Fail-closed: a missing or non-object practices container is a FAIL-CLOSED violation; a missing, false
# or non-true value is a violation; an unknown id is a violation. A specific goal is achieved only when every one
# of its practices is attested; a process area achieves GG1 (Achieve Specific Goals) only when all its goals are.
#
# Query: POST /v1/data/cert_rmm/main/compliance_report

# METADATA
# title: "CERT Resilience Management Model v1.2 — 248 specific practices across 26 process areas, attested"
# custom:
#   class: compliance
#   framework: cert_rmm
#   source: dod
#   domains: [assurance, it-governance]
#   coverage:
#     checks: 251
#     cited: 249
#     expected: 248
#     found: 249
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cert_rmm.main

import rego.v1

source := {
	"publication": "CERT Resilience Management Model (CERT-RMM), Version 1.2",
	"publisher": "Software Engineering Institute, Carnegie Mellon University",
	"date": "2016-02",
	"url": "https://www.sei.cmu.edu/documents/1629/CERT_Resilience_Management_Model_Version_1_2.pdf",
	"sha256": "7dafea8f4fb777bbf03078b91fd810a658df9e228c418bcf1f101073daadc17b",
	"retrieved": "2026-10-14",
	"status": "current",
	"licence": "Copyright Carnegie Mellon University; ids and titles only, summaries are AAC paraphrases",
}

process_areas := {
	"ADM": "Asset Definition and Management",
	"AM": "Access Management",
	"COMM": "Communications",
	"COMP": "Compliance",
	"CTRL": "Controls Management",
	"EC": "Environmental Control",
	"EF": "Enterprise Focus",
	"EXD": "External Dependencies Management",
	"FRM": "Financial Resource Management",
	"HRM": "Human Resource Management",
	"ID": "Identity Management",
	"IMC": "Incident Management and Control",
	"KIM": "Knowledge and Information Management",
	"MA": "Measurement and Analysis",
	"MON": "Monitoring",
	"OPD": "Organizational Process Definition",
	"OPF": "Organizational Process Focus",
	"OTA": "Organizational Training and Awareness",
	"PM": "People Management",
	"RISK": "Risk Management",
	"RRD": "Resilience Requirements Development",
	"RRM": "Resilience Requirements Management",
	"RTSE": "Resilient Technical Solution Engineering",
	"SC": "Service Continuity",
	"TM": "Technology Management",
	"VAR": "Vulnerability Analysis and Resolution",
}

process_area_categories := {
	"ADM": "Engineering",
	"AM": "Operations",
	"COMM": "Enterprise",
	"COMP": "Enterprise",
	"CTRL": "Engineering",
	"EC": "Operations",
	"EF": "Enterprise",
	"EXD": "Operations",
	"FRM": "Enterprise",
	"HRM": "Enterprise",
	"ID": "Operations",
	"IMC": "Operations",
	"KIM": "Operations",
	"MA": "Process",
	"MON": "Process",
	"OPD": "Process",
	"OPF": "Process",
	"OTA": "Enterprise",
	"PM": "Operations",
	"RISK": "Enterprise",
	"RRD": "Engineering",
	"RRM": "Engineering",
	"RTSE": "Engineering",
	"SC": "Engineering",
	"TM": "Operations",
	"VAR": "Operations",
}

# specific goal titles (SEI), keyed by goal id
goals := {
	"ADM:SG1": "Establish Organizational Assets",
	"ADM:SG2": "Establish the Relationship Between Assets and Services",
	"ADM:SG3": "Manage Assets",
	"AM:SG1": "Manage and Control Access",
	"COMM:SG1": "Prepare for Resilience Communications",
	"COMM:SG2": "Deliver Resilience Communications",
	"COMM:SG3": "Improve Communications",
	"COMP:SG1": "Prepare for Compliance Management",
	"COMP:SG2": "Establish Compliance Obligations",
	"COMP:SG3": "Demonstrate Satisfaction of Compliance Obligations",
	"COMP:SG4": "Monitor Compliance Activities",
	"CTRL:SG1": "Establish Control Objectives",
	"CTRL:SG2": "Establish Controls",
	"CTRL:SG3": "Analyze Controls",
	"CTRL:SG4": "Assess Control Effectiveness",
	"EC:SG1": "Establish and Prioritize Facility Assets",
	"EC:SG2": "Protect Facility Assets",
	"EC:SG3": "Manage Facility Asset Risk",
	"EC:SG4": "Control Operational Environment",
	"EF:SG1": "Establish Strategic Objectives",
	"EF:SG2": "Plan for Operational Resilience",
	"EF:SG3": "Establish Sponsorship",
	"EF:SG4": "Provide Resilience Oversight",
	"EXD:SG1": "Identify and Prioritize External Dependencies",
	"EXD:SG2": "Manage Risks Due to External Dependencies",
	"EXD:SG3": "Establish Formal Relationships",
	"EXD:SG4": "Manage External Entity Performance",
	"FRM:SG1": "Establish Financial Commitment",
	"FRM:SG2": "Perform Financial Planning",
	"FRM:SG3": "Fund Resilience Activities",
	"FRM:SG4": "Account for Resilience Activities",
	"FRM:SG5": "Optimize Resilience Expenditures and Investments",
	"HRM:SG1": "Establish Resource Needs",
	"HRM:SG2": "Manage Staff Acquisition",
	"HRM:SG3": "Manage Staff Performance",
	"HRM:SG4": "Manage Changes to Employment Status",
	"ID:SG1": "Establish Identities",
	"ID:SG2": "Manage Identities",
	"IMC:SG1": "Establish the Incident Management and Control Process",
	"IMC:SG2": "Detect Events",
	"IMC:SG3": "Declare and Analyze Incidents",
	"IMC:SG4": "Respond to and Recover from Incidents",
	"IMC:SG5": "Establish Incident Learning",
	"KIM:SG1": "Establish and Prioritize Information Assets",
	"KIM:SG2": "Protect Information Assets",
	"KIM:SG3": "Manage Information Asset Risks",
	"KIM:SG4": "Manage Information Asset Confidentiality and Privacy",
	"KIM:SG5": "Manage Information Asset Integrity",
	"KIM:SG6": "Manage Information Asset Availability",
	"MA:SG1": "Align Measurement and Analysis Activities",
	"MA:SG2": "Provide Measurement Results",
	"MON:SG1": "Establish and Maintain a Monitoring Program",
	"MON:SG2": "Perform Monitoring",
	"OPD:SG1": "Establish Organizational Process Assets",
	"OPF:SG1": "Determine Process Improvement Opportunities",
	"OPF:SG2": "Plan and Implement Process Actions",
	"OPF:SG3": "Deploy Organizational Process Assets and Incorporate Experiences",
	"OTA:SG1": "Establish Awareness Program",
	"OTA:SG2": "Conduct Awareness Activities",
	"OTA:SG3": "Establish Training Capability",
	"OTA:SG4": "Conduct Training",
	"PM:SG1": "Establish Vital Staff",
	"PM:SG2": "Manage Risks Associated with Staff Availability",
	"PM:SG3": "Manage the Availability of Staff",
	"RISK:SG1": "Prepare for Risk Management",
	"RISK:SG2": "Establish Risk Parameters and Focus",
	"RISK:SG3": "Identify Risks",
	"RISK:SG4": "Analyze Risks",
	"RISK:SG5": "Address Risks",
	"RISK:SG6": "Use Risk Information to Manage Resilience",
	"RRD:SG1": "Identify Enterprise Requirements",
	"RRD:SG2": "Develop Service Requirements",
	"RRD:SG3": "Analyze and Validate Requirements",
	"RRM:SG1": "Manage Requirements",
	"RTSE:SG1": "Establish Guidelines for Resilient Technical Solution Development",
	"RTSE:SG2": "Develop Resilient Technical Solution Development Plans",
	"RTSE:SG3": "Execute the Plan",
	"SC:SG1": "Prepare for Service Continuity",
	"SC:SG2": "Identify and Prioritize High-Value Services",
	"SC:SG3": "Develop Service Continuity Plans",
	"SC:SG4": "Validate Service Continuity Plans",
	"SC:SG5": "Exercise Service Continuity Plans",
	"SC:SG6": "Execute Service Continuity Plans",
	"SC:SG7": "Maintain Service Continuity Plans",
	"TM:SG1": "Establish and Prioritize Technology Assets",
	"TM:SG2": "Protect Technology Assets",
	"TM:SG3": "Manage Technology Asset Risks",
	"TM:SG4": "Manage Technology Asset Integrity",
	"TM:SG5": "Manage Technology Asset Availability",
	"VAR:SG1": "Prepare for Vulnerability Analysis and Resolution",
	"VAR:SG2": "Identify and Analyze Vulnerabilities",
	"VAR:SG3": "Manage Exposure to Vulnerabilities",
	"VAR:SG4": "Identify Root Causes",
}

# generic goals and practices: capability levels, data only (not attested)
generic_goals := {
	"GG1": "Achieve Specific Goals",
	"GG2": "Institutionalize a Managed Process",
	"GG3": "Institutionalize a Defined Process",
}

generic_practices := {
	"GG1.GP1": "Perform Specific Practices",
	"GG2.GP1": "Establish Process Governance",
	"GG2.GP2": "Plan the Process",
	"GG2.GP3": "Provide Resources",
	"GG2.GP4": "Assign Responsibility",
	"GG2.GP5": "Train People",
	"GG2.GP6": "Control Work Products",
	"GG2.GP7": "Identify and Involve Relevant Stakeholders",
	"GG2.GP8": "Measure and Control the Process",
	"GG2.GP9": "Objectively Evaluate Adherence",
	"GG2.GP10": "Review Status with Higher Level Managers",
	"GG3.GP1": "Establish a Defined Process",
	"GG3.GP2": "Collect Improvement Information",
}

# ids carry a colon ("ADM:SG1.SP1"), so the rows are an array; practice_by_id is the keyed view.
# title: SEI practice title; summary: AAC paraphrase (not SEI text)
practice_rows := [
	{"id": "ADM:SG1.SP1", "process_area": "ADM", "goal": "ADM:SG1", "title": "Inventory Assets", "summary": "Identify the organisation's assets and keep an inventory of them"},
	{"id": "ADM:SG1.SP2", "process_area": "ADM", "goal": "ADM:SG1", "title": "Establish a Common Understanding", "summary": "Define assets consistently and share that definition across the organisation"},
	{"id": "ADM:SG1.SP3", "process_area": "ADM", "goal": "ADM:SG1", "title": "Establish Ownership and Custodianship", "summary": "Assign an owner and a custodian with authority and responsibility for each asset"},
	{"id": "ADM:SG2.SP1", "process_area": "ADM", "goal": "ADM:SG2", "title": "Associate Assets with Services", "summary": "Link each asset to the service or services it supports"},
	{"id": "ADM:SG2.SP2", "process_area": "ADM", "goal": "ADM:SG2", "title": "Analyze Asset-Service Dependencies", "summary": "Find and analyse assets shared by more than one service"},
	{"id": "ADM:SG3.SP1", "process_area": "ADM", "goal": "ADM:SG3", "title": "Identify Change Criteria", "summary": "Set and maintain criteria that signal a change to an asset or to its service association"},
	{"id": "ADM:SG3.SP2", "process_area": "ADM", "goal": "ADM:SG3", "title": "Maintain Changes to Assets and Inventory", "summary": "Manage changes to assets and to the asset inventory as conditions change"},
	{"id": "AM:SG1.SP1", "process_area": "AM", "goal": "AM:SG1", "title": "Enable Access", "summary": "Grant access to assets on the basis of resilience requirements and approvals"},
	{"id": "AM:SG1.SP2", "process_area": "AM", "goal": "AM:SG1", "title": "Manage Changes to Access Privileges", "summary": "Manage changes to access privileges as assets, roles and requirements change"},
	{"id": "AM:SG1.SP3", "process_area": "AM", "goal": "AM:SG1", "title": "Periodically Review and Maintain Access Privileges", "summary": "Review access privileges periodically for excessive or inappropriate access"},
	{"id": "AM:SG1.SP4", "process_area": "AM", "goal": "AM:SG1", "title": "Correct Inconsistencies", "summary": "Correct excessive or inappropriate access privileges that reviews find"},
	{"id": "COMM:SG1.SP1", "process_area": "COMM", "goal": "COMM:SG1", "title": "Establish a Resilience Communications Plan", "summary": "Plan the resilience communications process"},
	{"id": "COMM:SG1.SP2", "process_area": "COMM", "goal": "COMM:SG1", "title": "Identify Communications Requirements", "summary": "Identify what communications stakeholders and the organisation need, and how much"},
	{"id": "COMM:SG1.SP3", "process_area": "COMM", "goal": "COMM:SG1", "title": "Establish Communications Guidelines and Standards", "summary": "Set and maintain guidelines and standards for meeting communications needs"},
	{"id": "COMM:SG2.SP1", "process_area": "COMM", "goal": "COMM:SG2", "title": "Identify Communications Methods and Channels", "summary": "Set and maintain the methods and channels used to communicate with stakeholders"},
	{"id": "COMM:SG2.SP2", "process_area": "COMM", "goal": "COMM:SG2", "title": "Establish and Maintain Communications Infrastructure", "summary": "Build and maintain an infrastructure that meets resilience communications needs"},
	{"id": "COMM:SG2.SP3", "process_area": "COMM", "goal": "COMM:SG2", "title": "Provide Resilience Communications", "summary": "Deliver resilience communications as the communications plan sets out"},
	{"id": "COMM:SG3.SP1", "process_area": "COMM", "goal": "COMM:SG3", "title": "Assess Communications Effectiveness", "summary": "Assess how effective resilience communications are and identify corrective actions"},
	{"id": "COMM:SG3.SP2", "process_area": "COMM", "goal": "COMM:SG3", "title": "Improve Communications", "summary": "Feed lessons learned back into the communications plans"},
	{"id": "COMP:SG1.SP1", "process_area": "COMP", "goal": "COMP:SG1", "title": "Establish a Compliance Plan", "summary": "Set a strategic plan for managing compliance with obligations"},
	{"id": "COMP:SG1.SP2", "process_area": "COMP", "goal": "COMP:SG1", "title": "Establish a Compliance Program", "summary": "Run a programme that carries out the compliance plan"},
	{"id": "COMP:SG1.SP3", "process_area": "COMP", "goal": "COMP:SG1", "title": "Establish Compliance Guidelines and Standards", "summary": "Set and communicate guidelines and standards for meeting compliance obligations"},
	{"id": "COMP:SG2.SP1", "process_area": "COMP", "goal": "COMP:SG2", "title": "Identify Compliance Obligations", "summary": "Identify and document the organisation's compliance obligations"},
	{"id": "COMP:SG2.SP2", "process_area": "COMP", "goal": "COMP:SG2", "title": "Analyze Obligations", "summary": "Analyse and organise compliance obligations so they can be met"},
	{"id": "COMP:SG2.SP3", "process_area": "COMP", "goal": "COMP:SG2", "title": "Establish Ownership for Meeting Obligations", "summary": "Assign responsibility for meeting each compliance obligation"},
	{"id": "COMP:SG3.SP1", "process_area": "COMP", "goal": "COMP:SG3", "title": "Collect and Validate Compliance Data", "summary": "Collect and validate the data needed to meet compliance obligations"},
	{"id": "COMP:SG3.SP2", "process_area": "COMP", "goal": "COMP:SG3", "title": "Demonstrate the Extent of Compliance Obligation Satisfaction", "summary": "Show through compliance activities how far obligations are being met"},
	{"id": "COMP:SG3.SP3", "process_area": "COMP", "goal": "COMP:SG3", "title": "Remediate Areas of Non-Compliance", "summary": "Remediate areas of non-compliance"},
	{"id": "COMP:SG4.SP1", "process_area": "COMP", "goal": "COMP:SG4", "title": "Evaluate Compliance Activities", "summary": "Monitor compliance independently and improve it"},
	{"id": "CTRL:SG1.SP1", "process_area": "CTRL", "goal": "CTRL:SG1", "title": "Define Control Objectives", "summary": "Set control objectives as the basis for the internal control system"},
	{"id": "CTRL:SG2.SP1", "process_area": "CTRL", "goal": "CTRL:SG2", "title": "Define Controls", "summary": "Identify and establish controls that protect services and assets from disruption"},
	{"id": "CTRL:SG3.SP1", "process_area": "CTRL", "goal": "CTRL:SG3", "title": "Analyze Controls", "summary": "Analyse whether controls can achieve the control objectives"},
	{"id": "CTRL:SG4.SP1", "process_area": "CTRL", "goal": "CTRL:SG4", "title": "Assess Controls", "summary": "Assess control effectiveness against control objectives and resilience requirements"},
	{"id": "EC:SG1.SP1", "process_area": "EC", "goal": "EC:SG1", "title": "Prioritize Facility Assets", "summary": "Prioritise facility assets by their importance to delivering high-value services"},
	{"id": "EC:SG1.SP2", "process_area": "EC", "goal": "EC:SG1", "title": "Establish Resilience-Focused Facility Assets", "summary": "Identify and establish the facility assets that support service continuity plans"},
	{"id": "EC:SG2.SP1", "process_area": "EC", "goal": "EC:SG2", "title": "Assign Resilience Requirements to Facility Assets", "summary": "Assign defined resilience requirements to facility assets"},
	{"id": "EC:SG2.SP2", "process_area": "EC", "goal": "EC:SG2", "title": "Establish and Implement Controls", "summary": "Identify and implement the administrative, technical and physical controls facility assets need"},
	{"id": "EC:SG3.SP1", "process_area": "EC", "goal": "EC:SG3", "title": "Identify and Assess Facility Asset Risks", "summary": "Identify and assess risks to facility assets periodically"},
	{"id": "EC:SG3.SP2", "process_area": "EC", "goal": "EC:SG3", "title": "Address Facility Risks", "summary": "Develop and carry out risk response plans for facility asset risks"},
	{"id": "EC:SG4.SP1", "process_area": "EC", "goal": "EC:SG4", "title": "Perform Facility Sustainability Planning", "summary": "Plan for the sustained availability of high-value facilities"},
	{"id": "EC:SG4.SP2", "process_area": "EC", "goal": "EC:SG4", "title": "Maintain Environmental Conditions", "summary": "Maintain the environmental conditions of facility assets"},
	{"id": "EC:SG4.SP3", "process_area": "EC", "goal": "EC:SG4", "title": "Manage Dependencies on Public Services", "summary": "Identify and manage facility dependencies on public services"},
	{"id": "EC:SG4.SP4", "process_area": "EC", "goal": "EC:SG4", "title": "Manage Dependencies on Public Infrastructure", "summary": "Identify and manage facility dependencies on public infrastructure"},
	{"id": "EC:SG4.SP5", "process_area": "EC", "goal": "EC:SG4", "title": "Plan for Facility Retirement", "summary": "Plan facility retirements to keep operational impact low"},
	{"id": "EF:SG1.SP1", "process_area": "EF", "goal": "EF:SG1", "title": "Establish Strategic Objectives", "summary": "Set the strategic objectives that resilience activities are based on"},
	{"id": "EF:SG1.SP2", "process_area": "EF", "goal": "EF:SG1", "title": "Establish Critical Success Factors", "summary": "Identify and establish the organisation's critical success factors"},
	{"id": "EF:SG1.SP3", "process_area": "EF", "goal": "EF:SG1", "title": "Establish Organizational Services", "summary": "Establish the high-value services that support the strategic objectives"},
	{"id": "EF:SG2.SP1", "process_area": "EF", "goal": "EF:SG2", "title": "Establish an Operational Resilience Management Plan", "summary": "Set a plan for managing operational resilience as the basis of the programme"},
	{"id": "EF:SG2.SP2", "process_area": "EF", "goal": "EF:SG2", "title": "Establish an Operational Resilience Management Program", "summary": "Run a programme that carries out the operational resilience management plan"},
	{"id": "EF:SG3.SP1", "process_area": "EF", "goal": "EF:SG3", "title": "Commit Funding for Operational Resilience Management", "summary": "Obtain higher-level managers' commitment to fund resilience activities"},
	{"id": "EF:SG3.SP2", "process_area": "EF", "goal": "EF:SG3", "title": "Promote a Resilience-Aware Culture", "summary": "Promote a resilience-aware culture through goals and their achievement"},
	{"id": "EF:SG3.SP3", "process_area": "EF", "goal": "EF:SG3", "title": "Sponsor Resilience Standards and Policies", "summary": "Sponsor the development, implementation, enforcement and management of resilience standards and policies"},
	{"id": "EF:SG4.SP1", "process_area": "EF", "goal": "EF:SG4", "title": "Establish Resilience as a Governance Focus Area", "summary": "Extend governance to the operational resilience management system and its process goals"},
	{"id": "EF:SG4.SP2", "process_area": "EF", "goal": "EF:SG4", "title": "Perform Resilience Oversight", "summary": "Oversee the resilience management system for adherence to procedures, policies, standards, guidelines and regulations"},
	{"id": "EF:SG4.SP3", "process_area": "EF", "goal": "EF:SG4", "title": "Establish Corrective Actions", "summary": "Identify corrective actions for resilience performance issues"},
	{"id": "EXD:SG1.SP1", "process_area": "EXD", "goal": "EXD:SG1", "title": "Identify External Dependencies", "summary": "Set and maintain a list of external dependencies"},
	{"id": "EXD:SG1.SP2", "process_area": "EXD", "goal": "EXD:SG1", "title": "Prioritize External Dependencies", "summary": "Prioritise external dependencies by their importance to high-value services"},
	{"id": "EXD:SG2.SP1", "process_area": "EXD", "goal": "EXD:SG2", "title": "Identify and Assess Risks Due to External Dependencies", "summary": "Identify and assess risks from external dependencies periodically"},
	{"id": "EXD:SG2.SP2", "process_area": "EXD", "goal": "EXD:SG2", "title": "Mitigate Risks Due to External Dependencies", "summary": "Develop and carry out mitigation plans for risks from external dependencies"},
	{"id": "EXD:SG3.SP1", "process_area": "EXD", "goal": "EXD:SG3", "title": "Establish Enterprise Specifications for External Dependencies", "summary": "Set and maintain enterprise specifications that apply to external entities in general"},
	{"id": "EXD:SG3.SP2", "process_area": "EXD", "goal": "EXD:SG3", "title": "Establish Resilience Specifications for External Dependencies", "summary": "Set and maintain resilience specifications for particular external dependencies and entities"},
	{"id": "EXD:SG3.SP3", "process_area": "EXD", "goal": "EXD:SG3", "title": "Evaluate and Select External Entities", "summary": "Select external entities after evaluating their ability to meet the specifications"},
	{"id": "EXD:SG3.SP4", "process_area": "EXD", "goal": "EXD:SG3", "title": "Formalize Relationships", "summary": "Put formal agreements with external entities in place and maintain them"},
	{"id": "EXD:SG4.SP1", "process_area": "EXD", "goal": "EXD:SG4", "title": "Monitor External Entity Performance", "summary": "Monitor external entity performance against the specifications"},
	{"id": "EXD:SG4.SP2", "process_area": "EXD", "goal": "EXD:SG4", "title": "Correct External Entity Performance", "summary": "Take corrective action on external entity performance where needed"},
	{"id": "FRM:SG1.SP1", "process_area": "FRM", "goal": "FRM:SG1", "title": "Commit Funding for Operational Resilience Management", "summary": "Obtain higher-level managers' commitment to fund resilience activities"},
	{"id": "FRM:SG1.SP2", "process_area": "FRM", "goal": "FRM:SG1", "title": "Establish Structure to Support Financial Management", "summary": "Set up the structure for assigning and managing financial resources for resilience"},
	{"id": "FRM:SG2.SP1", "process_area": "FRM", "goal": "FRM:SG2", "title": "Define Funding Needs", "summary": "Determine the financial obligations of managing operational resilience"},
	{"id": "FRM:SG2.SP2", "process_area": "FRM", "goal": "FRM:SG2", "title": "Establish Resilience Budgets", "summary": "Set capital and expense budgets for resilience management"},
	{"id": "FRM:SG2.SP3", "process_area": "FRM", "goal": "FRM:SG2", "title": "Resolve Funding Gaps", "summary": "Find and close resilience funding gaps and address the risks they create"},
	{"id": "FRM:SG3.SP1", "process_area": "FRM", "goal": "FRM:SG3", "title": "Fund Resilience Activities", "summary": "Provide access to funds for resilience management activities"},
	{"id": "FRM:SG4.SP1", "process_area": "FRM", "goal": "FRM:SG4", "title": "Track and Document Costs", "summary": "Track and document the costs of resilience management"},
	{"id": "FRM:SG4.SP2", "process_area": "FRM", "goal": "FRM:SG4", "title": "Perform Cost and Performance Analysis", "summary": "Analyse cost and performance of funded resilience activities"},
	{"id": "FRM:SG5.SP1", "process_area": "FRM", "goal": "FRM:SG5", "title": "Optimize Resilience Expenditures", "summary": "Optimise the cost of protecting and sustaining services and assets against the benefit"},
	{"id": "FRM:SG5.SP2", "process_area": "FRM", "goal": "FRM:SG5", "title": "Determine Return on Resilience Investments", "summary": "Calculate the return on resilience investments where possible"},
	{"id": "FRM:SG5.SP3", "process_area": "FRM", "goal": "FRM:SG5", "title": "Identify Cost Recovery Opportunities", "summary": "Identify opportunities to recover resilience costs and investments"},
	{"id": "HRM:SG1.SP1", "process_area": "HRM", "goal": "HRM:SG1", "title": "Establish Baseline Competencies", "summary": "Determine the staffing and skills the resilience management system needs"},
	{"id": "HRM:SG1.SP2", "process_area": "HRM", "goal": "HRM:SG1", "title": "Inventory Skills and Identify Gaps", "summary": "Inventory current resilience skills and identify gaps"},
	{"id": "HRM:SG1.SP3", "process_area": "HRM", "goal": "HRM:SG1", "title": "Address Skill Deficiencies", "summary": "Close the skill gaps that resilience management needs"},
	{"id": "HRM:SG2.SP1", "process_area": "HRM", "goal": "HRM:SG2", "title": "Verify Suitability of Candidate Staff", "summary": "Evaluate candidate staff for suitability against position requirements and risks"},
	{"id": "HRM:SG2.SP2", "process_area": "HRM", "goal": "HRM:SG2", "title": "Establish Terms and Conditions of Employment", "summary": "Develop and execute employment agreements suited to the position and role"},
	{"id": "HRM:SG3.SP1", "process_area": "HRM", "goal": "HRM:SG3", "title": "Establish Resilience as a Job Responsibility", "summary": "Make resilience obligations a documented, agreed condition of employment"},
	{"id": "HRM:SG3.SP2", "process_area": "HRM", "goal": "HRM:SG3", "title": "Establish Resilience Performance Goals and Objectives", "summary": "Include resilience goals and objectives in performance management"},
	{"id": "HRM:SG3.SP3", "process_area": "HRM", "goal": "HRM:SG3", "title": "Measure and Assess Performance", "summary": "Measure performance against resilience goals, acknowledge achievement and communicate corrective actions"},
	{"id": "HRM:SG3.SP4", "process_area": "HRM", "goal": "HRM:SG3", "title": "Establish Disciplinary Process", "summary": "Set a disciplinary process for staff who violate resilience policies"},
	{"id": "HRM:SG4.SP1", "process_area": "HRM", "goal": "HRM:SG4", "title": "Manage Impact of Position Changes", "summary": "Use administrative controls to keep functions and vital roles going through position changes and terminations"},
	{"id": "HRM:SG4.SP2", "process_area": "HRM", "goal": "HRM:SG4", "title": "Manage Access to Assets", "summary": "Manage access to and possession of assets when positions change"},
	{"id": "HRM:SG4.SP3", "process_area": "HRM", "goal": "HRM:SG4", "title": "Manage Involuntary Terminations", "summary": "Use administrative controls and procedures to manage the effects of involuntary terminations"},
	{"id": "ID:SG1.SP1", "process_area": "ID", "goal": "ID:SG1", "title": "Create Identities", "summary": "Register and profile the persons, objects and entities that need access to assets"},
	{"id": "ID:SG1.SP2", "process_area": "ID", "goal": "ID:SG1", "title": "Establish Identity Community", "summary": "Establish and document the identity community"},
	{"id": "ID:SG1.SP3", "process_area": "ID", "goal": "ID:SG1", "title": "Assign Roles to Identities", "summary": "Define organisational roles and associate them with identities"},
	{"id": "ID:SG2.SP1", "process_area": "ID", "goal": "ID:SG2", "title": "Monitor and Manage Identity Changes", "summary": "Monitor and manage changes to identities"},
	{"id": "ID:SG2.SP2", "process_area": "ID", "goal": "ID:SG2", "title": "Periodically Review and Maintain Identities", "summary": "Review identities periodically to find invalid ones"},
	{"id": "ID:SG2.SP3", "process_area": "ID", "goal": "ID:SG2", "title": "Correct Inconsistencies", "summary": "Correct inconsistencies between identities and what they represent"},
	{"id": "ID:SG2.SP4", "process_area": "ID", "goal": "ID:SG2", "title": "Deprovision Identities", "summary": "Deprovision identities that are no longer needed"},
	{"id": "IMC:SG1.SP1", "process_area": "IMC", "goal": "IMC:SG1", "title": "Plan for Incident Management", "summary": "Plan the incident management and control process"},
	{"id": "IMC:SG1.SP2", "process_area": "IMC", "goal": "IMC:SG1", "title": "Assign Staff to the Incident Management Plan", "summary": "Identify staff and assign them to the incident management plan"},
	{"id": "IMC:SG2.SP1", "process_area": "IMC", "goal": "IMC:SG2", "title": "Detect and Report Events", "summary": "Detect and report events"},
	{"id": "IMC:SG2.SP2", "process_area": "IMC", "goal": "IMC:SG2", "title": "Log and Track Events", "summary": "Log events and track them from inception to disposition"},
	{"id": "IMC:SG2.SP3", "process_area": "IMC", "goal": "IMC:SG2", "title": "Collect, Document, and Preserve Event Evidence", "summary": "Set and manage a process for collecting, documenting and preserving event evidence"},
	{"id": "IMC:SG2.SP4", "process_area": "IMC", "goal": "IMC:SG2", "title": "Analyze and Triage Events", "summary": "Analyse and triage events to resolve them and to decide on incident declaration"},
	{"id": "IMC:SG3.SP1", "process_area": "IMC", "goal": "IMC:SG3", "title": "Declare Incidents", "summary": "Declare incidents using established and maintained criteria"},
	{"id": "IMC:SG3.SP2", "process_area": "IMC", "goal": "IMC:SG3", "title": "Analyze Incidents", "summary": "Analyse incidents to shape an appropriate response"},
	{"id": "IMC:SG4.SP1", "process_area": "IMC", "goal": "IMC:SG4", "title": "Escalate Incidents", "summary": "Escalate incidents to the right stakeholders for input and resolution"},
	{"id": "IMC:SG4.SP2", "process_area": "IMC", "goal": "IMC:SG4", "title": "Develop Incident Response", "summary": "Develop and carry out a response that prevents or limits the impact of a declared incident"},
	{"id": "IMC:SG4.SP3", "process_area": "IMC", "goal": "IMC:SG4", "title": "Communicate Incidents", "summary": "Plan incident communications to stakeholders and manage them while the incident is open"},
	{"id": "IMC:SG4.SP4", "process_area": "IMC", "goal": "IMC:SG4", "title": "Close Incidents", "summary": "Close incidents once the relevant actions are complete"},
	{"id": "IMC:SG5.SP1", "process_area": "IMC", "goal": "IMC:SG5", "title": "Perform Post-Incident Review", "summary": "Review incidents afterwards to find underlying causes"},
	{"id": "IMC:SG5.SP2", "process_area": "IMC", "goal": "IMC:SG5", "title": "Translate Experience to Strategy", "summary": "Turn incident lessons learned into improvements"},
	{"id": "KIM:SG1.SP1", "process_area": "KIM", "goal": "KIM:SG1", "title": "Prioritize Information Assets", "summary": "Prioritise information assets by their importance to high-value services"},
	{"id": "KIM:SG1.SP2", "process_area": "KIM", "goal": "KIM:SG1", "title": "Categorize Information Assets", "summary": "Categorise information assets that support high-value services by sensitivity"},
	{"id": "KIM:SG2.SP1", "process_area": "KIM", "goal": "KIM:SG2", "title": "Assign Resilience Requirements to Information Assets", "summary": "Assign defined resilience requirements to information assets"},
	{"id": "KIM:SG2.SP2", "process_area": "KIM", "goal": "KIM:SG2", "title": "Establish and Implement Controls", "summary": "Identify and implement the administrative, technical and physical controls information assets need"},
	{"id": "KIM:SG3.SP1", "process_area": "KIM", "goal": "KIM:SG3", "title": "Identify and Assess Information Asset Risks", "summary": "Identify and assess risks to information assets periodically"},
	{"id": "KIM:SG3.SP2", "process_area": "KIM", "goal": "KIM:SG3", "title": "Address Information Asset Risks", "summary": "Develop and carry out risk response plans for information asset risks"},
	{"id": "KIM:SG4.SP1", "process_area": "KIM", "goal": "KIM:SG4", "title": "Encrypt High-Value Information", "summary": "Apply cryptographic controls to information assets for confidentiality"},
	{"id": "KIM:SG4.SP2", "process_area": "KIM", "goal": "KIM:SG4", "title": "Control Access to Information Assets", "summary": "Develop and implement access controls that limit access to information assets"},
	{"id": "KIM:SG4.SP3", "process_area": "KIM", "goal": "KIM:SG4", "title": "Control Information Asset Disposition", "summary": "Control how information assets are disposed of"},
	{"id": "KIM:SG5.SP1", "process_area": "KIM", "goal": "KIM:SG5", "title": "Control Modification of Information Assets", "summary": "Control modification of information assets"},
	{"id": "KIM:SG5.SP2", "process_area": "KIM", "goal": "KIM:SG5", "title": "Manage Information Asset Configuration", "summary": "Baseline information assets and manage changes to them"},
	{"id": "KIM:SG5.SP3", "process_area": "KIM", "goal": "KIM:SG5", "title": "Verify Validity of Information", "summary": "Implement controls that keep information valid and reliable"},
	{"id": "KIM:SG6.SP1", "process_area": "KIM", "goal": "KIM:SG6", "title": "Perform Information Duplication and Retention", "summary": "Back up and retain high-value information assets so services can use them when needed"},
	{"id": "KIM:SG6.SP2", "process_area": "KIM", "goal": "KIM:SG6", "title": "Manage Organizational Knowledge", "summary": "Identify and document the organisational and intellectual knowledge of staff"},
	{"id": "MA:SG1.SP1", "process_area": "MA", "goal": "MA:SG1", "title": "Establish Measurement Objectives", "summary": "Set and maintain measurement objectives from information needs and objectives"},
	{"id": "MA:SG1.SP2", "process_area": "MA", "goal": "MA:SG1", "title": "Specify Measures", "summary": "Define the measures needed to meet measurement objectives"},
	{"id": "MA:SG1.SP3", "process_area": "MA", "goal": "MA:SG1", "title": "Specify Data Collection and Storage Procedures", "summary": "Specify how measurement data is collected and stored"},
	{"id": "MA:SG1.SP4", "process_area": "MA", "goal": "MA:SG1", "title": "Specify Analysis Procedures", "summary": "Specify how measurement data is analysed and reported"},
	{"id": "MA:SG2.SP1", "process_area": "MA", "goal": "MA:SG2", "title": "Collect Measurement Data", "summary": "Collect measurement data in line with measurement objectives"},
	{"id": "MA:SG2.SP2", "process_area": "MA", "goal": "MA:SG2", "title": "Analyze Measurement Data", "summary": "Analyse measurement data against measurement objectives"},
	{"id": "MA:SG2.SP3", "process_area": "MA", "goal": "MA:SG2", "title": "Store Data and Results", "summary": "Store measurement data, analyses and results"},
	{"id": "MA:SG2.SP4", "process_area": "MA", "goal": "MA:SG2", "title": "Communicate Results", "summary": "Communicate measurement and analysis results to relevant stakeholders"},
	{"id": "MON:SG1.SP1", "process_area": "MON", "goal": "MON:SG1", "title": "Establish a Monitoring Program", "summary": "Set and maintain a programme for identifying, collecting and distributing monitoring information"},
	{"id": "MON:SG1.SP2", "process_area": "MON", "goal": "MON:SG1", "title": "Identify Stakeholders", "summary": "Identify the internal and external parties that rely on monitoring information"},
	{"id": "MON:SG1.SP3", "process_area": "MON", "goal": "MON:SG1", "title": "Establish Monitoring Requirements", "summary": "Set the requirements for monitoring resilience management processes"},
	{"id": "MON:SG1.SP4", "process_area": "MON", "goal": "MON:SG1", "title": "Analyze and Prioritize Monitoring Requirements", "summary": "Analyse and prioritise monitoring requirements so they can be met"},
	{"id": "MON:SG2.SP1", "process_area": "MON", "goal": "MON:SG2", "title": "Establish and Maintain Monitoring Infrastructure", "summary": "Build and maintain monitoring infrastructure that meets monitoring requirements"},
	{"id": "MON:SG2.SP2", "process_area": "MON", "goal": "MON:SG2", "title": "Establish Collection Standards and Guidelines", "summary": "Set standards and parameters for collecting information and managing data"},
	{"id": "MON:SG2.SP3", "process_area": "MON", "goal": "MON:SG2", "title": "Collect and Record Information", "summary": "Collect and record information relevant to resilience management"},
	{"id": "MON:SG2.SP4", "process_area": "MON", "goal": "MON:SG2", "title": "Distribute Information", "summary": "Distribute collected information to appropriate stakeholders"},
	{"id": "OPD:SG1.SP1", "process_area": "OPD", "goal": "OPD:SG1", "title": "Establish Standard Processes", "summary": "Set and maintain the organisation's set of standard processes"},
	{"id": "OPD:SG1.SP2", "process_area": "OPD", "goal": "OPD:SG1", "title": "Establish Tailoring Criteria and Guidelines", "summary": "Set and maintain criteria and guidelines for tailoring the standard processes"},
	{"id": "OPD:SG1.SP3", "process_area": "OPD", "goal": "OPD:SG1", "title": "Establish the Organization’s Measurement Repository", "summary": "Set up and maintain the organisation's measurement repository"},
	{"id": "OPD:SG1.SP4", "process_area": "OPD", "goal": "OPD:SG1", "title": "Establish the Organization’s Process Asset Library", "summary": "Set up and maintain the organisation's process asset library"},
	{"id": "OPD:SG1.SP5", "process_area": "OPD", "goal": "OPD:SG1", "title": "Establish Work Environment Standards", "summary": "Set and maintain work environment standards"},
	{"id": "OPD:SG1.SP6", "process_area": "OPD", "goal": "OPD:SG1", "title": "Establish Rules and Guidelines for Integrated Teams", "summary": "Set and maintain rules and guidelines for forming and running integrated teams"},
	{"id": "OPF:SG1.SP1", "process_area": "OPF", "goal": "OPF:SG1", "title": "Establish Organizational Process Needs", "summary": "Describe and maintain the organisation's process needs and objectives"},
	{"id": "OPF:SG1.SP2", "process_area": "OPF", "goal": "OPF:SG1", "title": "Appraise the Organization’s Processes", "summary": "Appraise the organisation's processes periodically to know their strengths and weaknesses"},
	{"id": "OPF:SG1.SP3", "process_area": "OPF", "goal": "OPF:SG1", "title": "Identify the Organization’s Process Improvements", "summary": "Identify improvements to processes and process assets"},
	{"id": "OPF:SG2.SP1", "process_area": "OPF", "goal": "OPF:SG2", "title": "Establish Process Action Plans", "summary": "Set and maintain process action plans for those improvements"},
	{"id": "OPF:SG2.SP2", "process_area": "OPF", "goal": "OPF:SG2", "title": "Implement Process Action Plans", "summary": "Carry out the process action plans"},
	{"id": "OPF:SG3.SP1", "process_area": "OPF", "goal": "OPF:SG3", "title": "Deploy Organizational Process Assets", "summary": "Deploy organisational process assets across the organisation"},
	{"id": "OPF:SG3.SP2", "process_area": "OPF", "goal": "OPF:SG3", "title": "Deploy Standard Processes", "summary": "Deploy the standard processes, and changes to them, to organisational units and new projects"},
	{"id": "OPF:SG3.SP3", "process_area": "OPF", "goal": "OPF:SG3", "title": "Monitor the Implementation", "summary": "Monitor use of the standard processes and process assets"},
	{"id": "OPF:SG3.SP4", "process_area": "OPF", "goal": "OPF:SG3", "title": "Incorporate Experiences into Organizational Process Assets", "summary": "Feed process work products, measures and improvement information back into the process assets"},
	{"id": "OTA:SG1.SP1", "process_area": "OTA", "goal": "OTA:SG1", "title": "Establish Awareness Needs", "summary": "Set and maintain the organisation's awareness needs"},
	{"id": "OTA:SG1.SP2", "process_area": "OTA", "goal": "OTA:SG1", "title": "Establish Awareness Plan", "summary": "Set and maintain a plan for the awareness programme"},
	{"id": "OTA:SG1.SP3", "process_area": "OTA", "goal": "OTA:SG1", "title": "Establish Awareness Delivery Capability", "summary": "Set up and maintain a repeatable way to deliver awareness material"},
	{"id": "OTA:SG2.SP1", "process_area": "OTA", "goal": "OTA:SG2", "title": "Perform Awareness Activities", "summary": "Carry out awareness activities according to the awareness plan"},
	{"id": "OTA:SG2.SP2", "process_area": "OTA", "goal": "OTA:SG2", "title": "Establish Awareness Records", "summary": "Keep records of awareness activities"},
	{"id": "OTA:SG2.SP3", "process_area": "OTA", "goal": "OTA:SG2", "title": "Assess Awareness Program Effectiveness", "summary": "Assess awareness programme effectiveness and identify corrective actions"},
	{"id": "OTA:SG3.SP1", "process_area": "OTA", "goal": "OTA:SG3", "title": "Establish Training Needs", "summary": "Set and maintain the organisation's training needs"},
	{"id": "OTA:SG3.SP2", "process_area": "OTA", "goal": "OTA:SG3", "title": "Establish Training Plan", "summary": "Set and maintain a plan for the resilience training programme"},
	{"id": "OTA:SG3.SP3", "process_area": "OTA", "goal": "OTA:SG3", "title": "Establish Training Capability", "summary": "Set up and maintain the capability to train resilience staff"},
	{"id": "OTA:SG4.SP1", "process_area": "OTA", "goal": "OTA:SG4", "title": "Deliver Resilience Training", "summary": "Deliver resilience training according to the training plan"},
	{"id": "OTA:SG4.SP2", "process_area": "OTA", "goal": "OTA:SG4", "title": "Establish Training Records", "summary": "Keep records of training delivered"},
	{"id": "OTA:SG4.SP3", "process_area": "OTA", "goal": "OTA:SG4", "title": "Assess Training Effectiveness", "summary": "Assess training programme effectiveness and identify corrective actions"},
	{"id": "PM:SG1.SP1", "process_area": "PM", "goal": "PM:SG1", "title": "Identify Vital Staff", "summary": "Identify and characterise the staff who are vital from a resilience perspective"},
	{"id": "PM:SG2.SP1", "process_area": "PM", "goal": "PM:SG2", "title": "Identify and Assess Staff Risks", "summary": "Identify and assess risks to staff availability periodically"},
	{"id": "PM:SG2.SP2", "process_area": "PM", "goal": "PM:SG2", "title": "Address Staff Risks", "summary": "Develop and carry out risk response plans for staff availability risks"},
	{"id": "PM:SG3.SP1", "process_area": "PM", "goal": "PM:SG3", "title": "Establish Redundancy for Vital Staff", "summary": "Provide redundancy for vital staff so services continue"},
	{"id": "PM:SG3.SP2", "process_area": "PM", "goal": "PM:SG3", "title": "Perform Succession Planning", "summary": "Support vital management roles through succession planning"},
	{"id": "PM:SG3.SP3", "process_area": "PM", "goal": "PM:SG3", "title": "Prepare for Redeployment", "summary": "Plan and prepare staff to redeploy to other roles during disruption or continuity plan execution"},
	{"id": "PM:SG3.SP4", "process_area": "PM", "goal": "PM:SG3", "title": "Plan to Support Staff During Disruptive Events", "summary": "Plan and provide support for staff deployed during a disruptive event"},
	{"id": "PM:SG3.SP5", "process_area": "PM", "goal": "PM:SG3", "title": "Plan for Return-to-Work Considerations", "summary": "Plan and address staff return-to-work issues after a disruptive event"},
	{"id": "RISK:SG1.SP1", "process_area": "RISK", "goal": "RISK:SG1", "title": "Determine Risk Sources and Categories", "summary": "Identify sources of risk to assets and services and decide the relevant risk categories"},
	{"id": "RISK:SG1.SP2", "process_area": "RISK", "goal": "RISK:SG1", "title": "Establish an Operational Risk Management Strategy", "summary": "Set and maintain an operational risk management strategy tied to strategic objectives"},
	{"id": "RISK:SG2.SP1", "process_area": "RISK", "goal": "RISK:SG2", "title": "Define Risk Parameters", "summary": "Define the organisation's risk parameters"},
	{"id": "RISK:SG2.SP2", "process_area": "RISK", "goal": "RISK:SG2", "title": "Establish Risk Measurement Criteria", "summary": "Set criteria for measuring the impact of realised risk"},
	{"id": "RISK:SG3.SP1", "process_area": "RISK", "goal": "RISK:SG3", "title": "Identify Asset-Level Risks", "summary": "Identify operational risks to assets that support services"},
	{"id": "RISK:SG3.SP2", "process_area": "RISK", "goal": "RISK:SG3", "title": "Identify Service-Level Risks", "summary": "Identify operational risks that could affect services"},
	{"id": "RISK:SG4.SP1", "process_area": "RISK", "goal": "RISK:SG4", "title": "Evaluate Risks", "summary": "Evaluate risks against tolerances and criteria and characterise their potential impact"},
	{"id": "RISK:SG4.SP2", "process_area": "RISK", "goal": "RISK:SG4", "title": "Categorize and Prioritize Risks", "summary": "Categorise and prioritise risks against the risk parameters"},
	{"id": "RISK:SG4.SP3", "process_area": "RISK", "goal": "RISK:SG4", "title": "Develop Risk Disposition Strategy", "summary": "Set and maintain a disposition strategy for each identified risk"},
	{"id": "RISK:SG5.SP1", "process_area": "RISK", "goal": "RISK:SG5", "title": "Develop Risk Response Plans", "summary": "Develop risk response plans"},
	{"id": "RISK:SG5.SP2", "process_area": "RISK", "goal": "RISK:SG5", "title": "Implement Risk Strategies and Plans", "summary": "Carry out and monitor risk strategies and response plans"},
	{"id": "RISK:SG6.SP1", "process_area": "RISK", "goal": "RISK:SG6", "title": "Review and Adjust Strategies to Protect Assets and Services", "summary": "Evaluate and update protection strategies for assets and services using risk information"},
	{"id": "RISK:SG6.SP2", "process_area": "RISK", "goal": "RISK:SG6", "title": "Review and Adjust Strategies to Sustain Services", "summary": "Develop sustainment strategies and update plans using risk information"},
	{"id": "RRD:SG1.SP1", "process_area": "RRD", "goal": "RRD:SG1", "title": "Establish Enterprise Resilience Requirements", "summary": "Set the enterprise's resilience requirements"},
	{"id": "RRD:SG2.SP1", "process_area": "RRD", "goal": "RRD:SG2", "title": "Establish Asset Resilience Requirements", "summary": "Set resilience requirements for assets in the context of the services they support"},
	{"id": "RRD:SG2.SP2", "process_area": "RRD", "goal": "RRD:SG2", "title": "Assign Enterprise Resilience Requirements to Services", "summary": "Assign enterprise requirements to the services they affect"},
	{"id": "RRD:SG3.SP1", "process_area": "RRD", "goal": "RRD:SG3", "title": "Establish a Definition of Required Functionality", "summary": "Define and maintain the functionality assets must provide to the services they support"},
	{"id": "RRD:SG3.SP2", "process_area": "RRD", "goal": "RRD:SG3", "title": "Analyze Resilience Requirements", "summary": "Analyse asset requirements for conflicts, interdependencies and shared requirements"},
	{"id": "RRD:SG3.SP3", "process_area": "RRD", "goal": "RRD:SG3", "title": "Validate Resilience Requirements", "summary": "Validate that asset resilience requirements are adequate for the asset's value"},
	{"id": "RRM:SG1.SP1", "process_area": "RRM", "goal": "RRM:SG1", "title": "Obtain an Understanding of Resilience Requirements", "summary": "Obtain a consistent and accurate understanding of resilience requirements from their providers"},
	{"id": "RRM:SG1.SP2", "process_area": "RRM", "goal": "RRM:SG1", "title": "Obtain Commitment to Resilience Requirements", "summary": "Obtain commitment to resilience requirements from those responsible for meeting them"},
	{"id": "RRM:SG1.SP3", "process_area": "RRM", "goal": "RRM:SG1", "title": "Manage Resilience Requirements Changes", "summary": "Manage changes to resilience requirements as conditions change"},
	{"id": "RRM:SG1.SP4", "process_area": "RRM", "goal": "RRM:SG1", "title": "Maintain Traceability of Resilience Requirements", "summary": "Trace resilience requirements to the activities that satisfy them"},
	{"id": "RRM:SG1.SP5", "process_area": "RRM", "goal": "RRM:SG1", "title": "Identify Inconsistencies Between Resilience Requirements and Activities Performed to Meet the Requirements", "summary": "Identify and manage gaps between resilience requirements and the activities meant to satisfy them"},
	{"id": "RTSE:SG1.SP1", "process_area": "RTSE", "goal": "RTSE:SG1", "title": "Identify General Guidelines", "summary": "Identify general guidelines for building resilience into software and systems"},
	{"id": "RTSE:SG1.SP2", "process_area": "RTSE", "goal": "RTSE:SG1", "title": "Identify Requirements Guidelines", "summary": "Identify guidelines for setting software and system resilience requirements"},
	{"id": "RTSE:SG1.SP3", "process_area": "RTSE", "goal": "RTSE:SG1", "title": "Identify Architecture and Design Guidelines", "summary": "Identify guidelines for designing resilience into software and systems"},
	{"id": "RTSE:SG1.SP4", "process_area": "RTSE", "goal": "RTSE:SG1", "title": "Identify Implementation Guidelines", "summary": "Identify guidelines for implementing resilient software and systems"},
	{"id": "RTSE:SG1.SP5", "process_area": "RTSE", "goal": "RTSE:SG1", "title": "Identify Assembly and Integration Guidelines", "summary": "Identify guidelines for assembling and integrating resilient software into resilient systems"},
	{"id": "RTSE:SG2.SP1", "process_area": "RTSE", "goal": "RTSE:SG2", "title": "Select and Tailor Guidelines", "summary": "Select and tailor guidelines for a specific development project using selection criteria"},
	{"id": "RTSE:SG2.SP2", "process_area": "RTSE", "goal": "RTSE:SG2", "title": "Integrate Selected Guidelines with a Defined Software and System Development Process", "summary": "Integrate the selected resilience guidelines into a defined development process and a documented plan"},
	{"id": "RTSE:SG3.SP1", "process_area": "RTSE", "goal": "RTSE:SG3", "title": "Monitor Execution of the Development Plan", "summary": "Monitor the development plan to confirm resilience requirements are met"},
	{"id": "RTSE:SG3.SP2", "process_area": "RTSE", "goal": "RTSE:SG3", "title": "Release Resilient Technical Solutions into Production", "summary": "Release into production the software and systems shown to meet resilience requirements"},
	{"id": "SC:SG1.SP1", "process_area": "SC", "goal": "SC:SG1", "title": "Plan for Service Continuity", "summary": "Plan the service continuity process"},
	{"id": "SC:SG1.SP2", "process_area": "SC", "goal": "SC:SG1", "title": "Establish Standards and Guidelines for Service Continuity", "summary": "Set and communicate standards and guidelines for service continuity"},
	{"id": "SC:SG2.SP1", "process_area": "SC", "goal": "SC:SG2", "title": "Identify the Organization’s High-Value Services", "summary": "Identify the organisation's high-value services and their assets"},
	{"id": "SC:SG2.SP2", "process_area": "SC", "goal": "SC:SG2", "title": "Identify Internal and External Dependencies and Interdependencies", "summary": "Identify and analyse the internal and external relationships service continuity depends on"},
	{"id": "SC:SG2.SP3", "process_area": "SC", "goal": "SC:SG2", "title": "Identify Vital Organizational Records and Databases", "summary": "Identify the vital records and information needed for service continuity"},
	{"id": "SC:SG3.SP1", "process_area": "SC", "goal": "SC:SG3", "title": "Identify Plans to Be Developed", "summary": "Identify the service continuity plans that are needed"},
	{"id": "SC:SG3.SP2", "process_area": "SC", "goal": "SC:SG3", "title": "Develop and Document Service Continuity Plans", "summary": "Develop and document the required service continuity plans"},
	{"id": "SC:SG3.SP3", "process_area": "SC", "goal": "SC:SG3", "title": "Assign Staff to Service Continuity Plans", "summary": "Assign staff to the service continuity plans"},
	{"id": "SC:SG3.SP4", "process_area": "SC", "goal": "SC:SG3", "title": "Store and Secure Service Continuity Plans", "summary": "Store service continuity plans securely and make them available on a need-to-know basis"},
	{"id": "SC:SG3.SP5", "process_area": "SC", "goal": "SC:SG3", "title": "Develop Service Continuity Plan Training", "summary": "Develop and run training on the service continuity plans"},
	{"id": "SC:SG4.SP1", "process_area": "SC", "goal": "SC:SG4", "title": "Validate Plans to Standards and Guidelines", "summary": "Check service continuity plans against the standards and guidelines"},
	{"id": "SC:SG4.SP2", "process_area": "SC", "goal": "SC:SG4", "title": "Identify and Resolve Plan Conflicts", "summary": "Find and resolve conflicts between service continuity plans"},
	{"id": "SC:SG5.SP1", "process_area": "SC", "goal": "SC:SG5", "title": "Develop Testing Program and Standards", "summary": "Set up and run a testing programme and standards for service continuity plans"},
	{"id": "SC:SG5.SP2", "process_area": "SC", "goal": "SC:SG5", "title": "Develop and Document Test Plans", "summary": "Develop and document service continuity test plans"},
	{"id": "SC:SG5.SP3", "process_area": "SC", "goal": "SC:SG5", "title": "Exercise Plans", "summary": "Exercise service continuity plans regularly and document the results"},
	{"id": "SC:SG5.SP4", "process_area": "SC", "goal": "SC:SG5", "title": "Evaluate Plan Test Results", "summary": "Identify and implement improvements found by exercising the plans"},
	{"id": "SC:SG6.SP1", "process_area": "SC", "goal": "SC:SG6", "title": "Execute Plans", "summary": "Execute service continuity plans when required"},
	{"id": "SC:SG6.SP2", "process_area": "SC", "goal": "SC:SG6", "title": "Measure the Effectiveness of the Plans in Operation", "summary": "Review plan execution afterwards to identify corrective actions"},
	{"id": "SC:SG7.SP1", "process_area": "SC", "goal": "SC:SG7", "title": "Establish Change Criteria", "summary": "Set change criteria for service continuity plans"},
	{"id": "SC:SG7.SP2", "process_area": "SC", "goal": "SC:SG7", "title": "Maintain Changes to Plans", "summary": "Update service continuity plans as conditions change"},
	{"id": "TM:SG1.SP1", "process_area": "TM", "goal": "TM:SG1", "title": "Prioritize Technology Assets", "summary": "Prioritise technology assets by their importance to high-value services"},
	{"id": "TM:SG1.SP2", "process_area": "TM", "goal": "TM:SG1", "title": "Establish Resilience-Focused Technology Assets", "summary": "Identify and establish the technology assets that support service continuity plans"},
	{"id": "TM:SG2.SP1", "process_area": "TM", "goal": "TM:SG2", "title": "Assign Resilience Requirements to Technology Assets", "summary": "Assign defined resilience requirements to technology assets"},
	{"id": "TM:SG2.SP2", "process_area": "TM", "goal": "TM:SG2", "title": "Establish and Implement Controls", "summary": "Identify and implement the administrative, technical and physical controls technology assets need"},
	{"id": "TM:SG3.SP1", "process_area": "TM", "goal": "TM:SG3", "title": "Identify and Assess Technology Asset Risks", "summary": "Identify and assess risks to technology assets"},
	{"id": "TM:SG3.SP2", "process_area": "TM", "goal": "TM:SG3", "title": "Address Technology Asset Risks", "summary": "Develop and carry out risk response plans for technology asset risks"},
	{"id": "TM:SG4.SP1", "process_area": "TM", "goal": "TM:SG4", "title": "Control Access to Technology Assets", "summary": "Control access to technology assets"},
	{"id": "TM:SG4.SP2", "process_area": "TM", "goal": "TM:SG4", "title": "Perform Configuration Management", "summary": "Manage the configuration of technology assets"},
	{"id": "TM:SG4.SP3", "process_area": "TM", "goal": "TM:SG4", "title": "Perform Change Control and Management", "summary": "Manage changes to technology assets"},
	{"id": "TM:SG4.SP4", "process_area": "TM", "goal": "TM:SG4", "title": "Perform Release Management", "summary": "Manage releases of technology assets into production"},
	{"id": "TM:SG5.SP1", "process_area": "TM", "goal": "TM:SG5", "title": "Perform Planning to Sustain Technology Assets", "summary": "Plan to keep high-value technology assets available and functional"},
	{"id": "TM:SG5.SP2", "process_area": "TM", "goal": "TM:SG5", "title": "Manage Technology Asset Maintenance", "summary": "Perform operational maintenance on technology assets"},
	{"id": "TM:SG5.SP3", "process_area": "TM", "goal": "TM:SG5", "title": "Manage Technology Capacity", "summary": "Manage the operating capacity of technology assets"},
	{"id": "TM:SG5.SP4", "process_area": "TM", "goal": "TM:SG5", "title": "Manage Technology Interoperability", "summary": "Manage the interoperability of technology assets"},
	{"id": "VAR:SG1.SP1", "process_area": "VAR", "goal": "VAR:SG1", "title": "Establish Scope", "summary": "Identify the assets and environments to examine for vulnerabilities"},
	{"id": "VAR:SG1.SP2", "process_area": "VAR", "goal": "VAR:SG1", "title": "Establish a Vulnerability Analysis and Resolution Strategy", "summary": "Set and maintain a vulnerability analysis and resolution strategy"},
	{"id": "VAR:SG2.SP1", "process_area": "VAR", "goal": "VAR:SG2", "title": "Identify Sources of Vulnerability Information", "summary": "Identify sources of vulnerability information"},
	{"id": "VAR:SG2.SP2", "process_area": "VAR", "goal": "VAR:SG2", "title": "Discover Vulnerabilities", "summary": "Establish a process that actively discovers vulnerabilities"},
	{"id": "VAR:SG2.SP3", "process_area": "VAR", "goal": "VAR:SG2", "title": "Analyze Vulnerabilities", "summary": "Analyse vulnerabilities to decide whether to reduce or eliminate them"},
	{"id": "VAR:SG3.SP1", "process_area": "VAR", "goal": "VAR:SG3", "title": "Manage Exposure to Vulnerabilities", "summary": "Develop and carry out strategies to manage exposure to identified vulnerabilities"},
	{"id": "VAR:SG4.SP1", "process_area": "VAR", "goal": "VAR:SG4", "title": "Perform Root-Cause Analysis", "summary": "Review identified vulnerabilities to find and address their root causes"},
]

practice_by_id := {r.id: r | some r in practice_rows}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "cert_rmm", {})

_given := p if {
	p := _in.practices
	is_object(p)
}

_supplied if _given

_true(id) if _given[id] == true

violations contains "CERT-RMM v1.2: FAIL-CLOSED - attestations 'input.cert_rmm.practices' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some r in practice_rows
	not _true(r.id)
	msg := sprintf("CERT-RMM %v (%v %v): not attested — %v", [r.id, r.process_area, process_areas[r.process_area], r.title])
}

violations contains msg if {
	some id, _ in _given
	not practice_by_id[id]
	msg := sprintf("CERT-RMM Input Contract: unknown practice id %v — ids are specific practices such as ADM:SG1.SP1", [id])
}

_goal_ids(g) := {r.id | some r in practice_rows; r.goal == g}

# a goal with no practices can never be achieved (no vacuous pass)
_goal_achieved(g) if {
	ids := _goal_ids(g)
	count(ids) > 0
	every id in ids { _true(id) }
}

process_area_reports[a] := s if {
	some a, name in process_areas
	ids := {r.id | some r in practice_rows; r.process_area == a}
	gs := {g | some g; _ = goals[g]; startswith(g, concat("", [a, ":"]))}
	achieved := {g | some g in gs; _goal_achieved(g)}
	s := {
		"name": name,
		"category": process_area_categories[a],
		"practices_total": count(ids),
		"practices_attested": count({id | some id in ids; _true(id)}),
		"not_attested": sort([id | some id in ids; not _true(id)]),
		"specific_goals_total": count(gs),
		"specific_goals_achieved": sort([g | some g in achieved]),
		"gg1_achieve_specific_goals": count(achieved) == count(gs),
	}
}

compliance_report := {
	"framework": "CERT Resilience Management Model",
	"standard": "CERT-RMM Version 1.2 (SEI, February 2016) — specific practices of the 26 process areas",
	"source": source,
	"compliant": compliant,
	"standard_total": 248, # specific practices (XX:SGn.SPm) in the 26 process areas
	"total_controls": count(practice_rows),
	"practices_attested": count({r.id | some r in practice_rows; _true(r.id)}),
	"specific_goals_total": count(goals),
	"specific_goals_achieved": count({g | some g; _ = goals[g]; _goal_achieved(g)}),
	"process_areas": process_area_reports,
	"generic_goals": generic_goals,
	"violation_count": count(violations),
	"violations": violations,
}
