# NIST AI 600-1, "Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile",
# July 2024 — one attested row per suggested action (Section 3), each attached to its AI RMF 1.0 subcategory.
#
# Source of truth: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
#   sha256 6e73620ab6b64e90ef2c04bf0e0d6246185a2f4b1b13cab0df494496cff89b6a, retrieved 2026-10-14.
# NIST text is public domain. Action ids, action texts and GAI risk tags are copied verbatim from the Section 3
# tables by a generator reading the PDF's word boxes (pdftotext -bbox): the Action ID, Suggested Action and GAI Risks
# columns are read separately and joined by row. Only typesetting is undone: ligature glyphs (ﬁ, ﬀ) are written as
# letters, footnote markers inside a cell are dropped (MS-2.11-001 "Winogender Schemas"), and lines are joined (the
# profile is not hyphenated; the 11 line-final hyphens are real compounds such as "pre-deployment", kept).
#
# Measured: 12 GAI risks (Section 2); 212 suggested actions on 49 of the 72 AI RMF subcategories
# (Section 3 says not every subcategory is included):
#   GOVERN    58 actions on 15 subcategories
#   MAP       39 actions on  9 subcategories
#   MEASURE   72 actions on 16 subcategories
#   MANAGE    43 actions on  9 subcategories
# Every action's parent is the subcategory heading its table sits under, and agrees with its id (GV-1.3-004 ->
# GOVERN 1.3) for all 212; every parent is one of the 72 Core subcategories in nist.ai_rmf.main (tested).
#
# Judgement calls (source irregularities, kept visible):
#   - GOVERN 4.3's first action is printed "GV4.3--001". It is keyed GV-4.3-001 (the id the profile's own scheme
#     gives it, so attesters can type a predictable id) and carries printed_id "GV4.3--001".
#   - "GV-1.1-002" appears only in Section 3's explanation of the id scheme; GOVERN 1.1 has one action. Not a row.
#   - GAI risk tags are kept as printed in `gai_risks_as_printed`; `gai_risks` resolves them to the 12 Section 2 list
#     titles: "Harmful Bias and Homogenization" (the Section 2.6 heading's wording) -> "Harmful Bias or
#     Homogenization"; "Environmental" -> "Environmental Impacts"; "CBRN Information and Capability" (2 actions) ->
#     "CBRN Information or Capabilities"; "Human AI Configuration" (1) -> "Human-AI Configuration"; MG-3.2-004's cell joins two
#     risks with a comma ("Human-AI Configuration, Dangerous, Violent, or Hateful Content") and is split into both.
#   - "Civil Rights violations" (GV-1.4-002) is not one of the 12 risks: kept as printed, listed in `other_tags`,
#     excluded from the per-risk rollup.
#   - "AI Actor Tasks" lines are per-subcategory context, not actions; not carried.
#   - Guidance wording: every Section 3 suggested action is a row, including those phrased "Consider ..." or
#     "Avoid ..." (e.g. GV-1.3-001, MS-2.5-001): each is a discrete organisational task the profile numbers, and the
#     profile is attested action by action; none was dropped as prose.
#
# Actions per GAI risk (an action tagged with several risks counts under each):
#    1 CBRN Information or Capabilities               31
#    2 Confabulation                                  18
#    3 Dangerous, Violent, or Hateful Content         31
#    4 Data Privacy                                   29
#    5 Environmental Impacts                           4
#    6 Harmful Bias or Homogenization                 57
#    7 Human-AI Configuration                         58
#    8 Information Integrity                          73
#    9 Information Security                           51
#   10 Intellectual Property                          28
#   11 Obscene, Degrading, and/or Abusive Content     14
#   12 Value Chain and Component Integration          36
#
# Input contract:
#   input.nist_ai_600_1.scope.generative_ai   MUST be declared true or false. true: the organisation develops,
#                                               deploys or uses generative AI and the profile applies; false: not
#                                               applicable (no action is evaluated, the profile passes). Undeclared
#                                               or non-boolean is a FAIL-CLOSED violation.
#   input.nist_ai_600_1.actions["GV-1.1-001"] == true   the assessor's attestation that the suggested action is in
#                                               place. When applicable: a missing or non-object container is a
#                                               FAIL-CLOSED violation; a missing, false or non-true value is a
#                                               violation. An unknown id is always a violation.
# Report: rollups per function, per AI RMF subcategory and per GAI risk. Also carried (rollups only) by
# nist.ai_rmf.main as `generative_ai_profile`.
#
# Query: POST /v1/data/nist/ai_600_1/main/compliance_report

# METADATA
# title: "NIST AI 600-1 Generative AI Profile — 212 suggested actions on AI RMF 1.0 subcategories, scope-gated, attested"
# custom:
#   class: compliance
#   framework: nist_ai_600_1
#   source: nist
#   domains: [us-federal, ai]
#   coverage:
#     checks: 216
#     cited: 214
#     expected: 212
#     found: 300
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.ai_600_1.main

import rego.v1

source := {
	"publication": "NIST AI 600-1, Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile",
	"date": "July 2024",
	"url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf",
	"sha256": "6e73620ab6b64e90ef2c04bf0e0d6246185a2f4b1b13cab0df494496cff89b6a",
	"retrieved": "2026-10-14",
	"profile_of": "NIST AI 100-1 (AI RMF 1.0)",
}

function_names := ["GOVERN", "MAP", "MEASURE", "MANAGE"]

_function_codes := {"GV": "GOVERN", "MP": "MAP", "MS": "MEASURE", "MG": "MANAGE"}

# the 12 GAI risks of Section 2 (list title and the Section 2.N heading), rows of an array so they are not controls
_risk_rows := [
	{"number": 1, "title": "CBRN Information or Capabilities", "heading": "CBRN Information or Capabilities"},
	{"number": 2, "title": "Confabulation", "heading": "Confabulation"},
	{"number": 3, "title": "Dangerous, Violent, or Hateful Content", "heading": "Dangerous, Violent, or Hateful Content"},
	{"number": 4, "title": "Data Privacy", "heading": "Data Privacy"},
	{"number": 5, "title": "Environmental Impacts", "heading": "Environmental Impacts"},
	{"number": 6, "title": "Harmful Bias or Homogenization", "heading": "Harmful Bias and Homogenization"},
	{"number": 7, "title": "Human-AI Configuration", "heading": "Human-AI Configuration"},
	{"number": 8, "title": "Information Integrity", "heading": "Information Integrity"},
	{"number": 9, "title": "Information Security", "heading": "Information Security"},
	{"number": 10, "title": "Intellectual Property", "heading": "Intellectual Property"},
	{"number": 11, "title": "Obscene, Degrading, and/or Abusive Content", "heading": "Obscene, Degrading, and/or Abusive Content"},
	{"number": 12, "title": "Value Chain and Component Integration", "heading": "Value Chain and Component Integration"},
]

gai_risks := {r.title: {"number": r.number, "heading": r.heading} | some r in _risk_rows}

actions := {
	"GV-1.1-001": {
		"subcategory": "GOVERN 1.1",
		"function": "GOVERN",
		"text": "Align GAI development and use with applicable laws and regulations, including those related to data privacy, copyright and intellectual property law.",
		"gai_risks": ["Data Privacy", "Harmful Bias or Homogenization", "Intellectual Property"],
		"gai_risks_as_printed": "Data Privacy; Harmful Bias and Homogenization; Intellectual Property",
	},
	"GV-1.2-001": {
		"subcategory": "GOVERN 1.2",
		"function": "GOVERN",
		"text": "Establish transparency policies and processes for documenting the origin and history of training data and generated data for GAI applications to advance digital content transparency, while balancing the proprietary nature of training approaches.",
		"gai_risks": ["Data Privacy", "Information Integrity", "Intellectual Property"],
	},
	"GV-1.2-002": {
		"subcategory": "GOVERN 1.2",
		"function": "GOVERN",
		"text": "Establish policies to evaluate risk-relevant capabilities of GAI and robustness of safety measures, both prior to deployment and on an ongoing basis, through internal and external evaluations.",
		"gai_risks": ["CBRN Information or Capabilities", "Information Security"],
	},
	"GV-1.3-001": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Consider the following factors when updating or defining risk tiers for GAI: Abuses and impacts to information integrity; Dependencies between GAI and other IT or data systems; Harm to fundamental rights or public safety; Presentation of obscene, objectionable, offensive, discriminatory, invalid or untruthful output; Psychological impacts to humans (e.g., anthropomorphization, algorithmic aversion, emotional entanglement); Possibility for malicious use; Whether the system introduces significant new security vulnerabilities; Anticipated system impact on some groups compared to others; Unreliable decision making capabilities, validity, adaptability, and variability of GAI system performance over time.",
		"gai_risks": ["Information Integrity", "Obscene, Degrading, and/or Abusive Content", "Value Chain and Component Integration", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content", "CBRN Information or Capabilities"],
		"gai_risks_as_printed": "Information Integrity; Obscene, Degrading, and/or Abusive Content; Value Chain and Component Integration; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content; CBRN Information or Capabilities",
	},
	"GV-1.3-002": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Establish minimum thresholds for performance or assurance criteria and review as part of deployment approval (“go/”no-go”) policies, procedures, and processes, with reviewed processes and approval thresholds reflecting measurement of GAI capabilities and risks.",
		"gai_risks": ["CBRN Information or Capabilities", "Confabulation", "Dangerous, Violent, or Hateful Content"],
	},
	"GV-1.3-003": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Establish a test plan and response policy, before developing highly capable models, to periodically evaluate whether the model may misuse CBRN information or capabilities and/or offensive cyber capabilities.",
		"gai_risks": ["CBRN Information or Capabilities", "Information Security"],
	},
	"GV-1.3-004": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Obtain input from stakeholder communities to identify unacceptable use, in accordance with activities in the AI RMF Map function.",
		"gai_risks": ["CBRN Information or Capabilities", "Obscene, Degrading, and/or Abusive Content", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Obscene, Degrading, and/or Abusive Content; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"GV-1.3-005": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Maintain an updated hierarchy of identified and expected GAI risks connected to contexts of GAI model advancement and use, potentially including specialized risk levels for GAI systems that address issues such as model collapse and algorithmic monoculture.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"GV-1.3-006": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Reevaluate organizational risk tolerances to account for unacceptable negative risk (such as where significant negative impacts are imminent, severe harms are actually occurring, or large-scale risks could occur); and broad GAI negative risks, including: Immature safety or risk cultures related to AI and GAI design, development and deployment, public information integrity risks, including impacts on democratic processes, unknown long-term performance characteristics of GAI.",
		"gai_risks": ["Information Integrity", "Dangerous, Violent, or Hateful Content", "CBRN Information or Capabilities"],
	},
	"GV-1.3-007": {
		"subcategory": "GOVERN 1.3",
		"function": "GOVERN",
		"text": "Devise a plan to halt development or deployment of a GAI system that poses unacceptable negative risk.",
		"gai_risks": ["CBRN Information or Capabilities", "Information Security", "Information Integrity"],
		"gai_risks_as_printed": "CBRN Information and Capability; Information Security; Information Integrity",
	},
	"GV-1.4-001": {
		"subcategory": "GOVERN 1.4",
		"function": "GOVERN",
		"text": "Establish policies and mechanisms to prevent GAI systems from generating CSAM, NCII or content that violates the law.",
		"gai_risks": ["Obscene, Degrading, and/or Abusive Content", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Obscene, Degrading, and/or Abusive Content; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"GV-1.4-002": {
		"subcategory": "GOVERN 1.4",
		"function": "GOVERN",
		"text": "Establish transparent acceptable use policies for GAI that address illegal use or applications of GAI.",
		"gai_risks": ["CBRN Information or Capabilities", "Obscene, Degrading, and/or Abusive Content", "Data Privacy"],
		"other_tags": ["Civil Rights violations"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Obscene, Degrading, and/or Abusive Content; Data Privacy; Civil Rights violations",
	},
	"GV-1.5-001": {
		"subcategory": "GOVERN 1.5",
		"function": "GOVERN",
		"text": "Define organizational responsibilities for periodic review of content provenance and incident monitoring for GAI systems.",
		"gai_risks": ["Information Integrity"],
	},
	"GV-1.5-002": {
		"subcategory": "GOVERN 1.5",
		"function": "GOVERN",
		"text": "Establish organizational policies and procedures for after action reviews of GAI system incident response and incident disclosures, to identify gaps; Update incident response and incident disclosure processes as required.",
		"gai_risks": ["Human-AI Configuration", "Information Security"],
	},
	"GV-1.5-003": {
		"subcategory": "GOVERN 1.5",
		"function": "GOVERN",
		"text": "Maintain a document retention policy to keep history for test, evaluation, validation, and verification (TEVV), and digital content transparency methods for GAI.",
		"gai_risks": ["Information Integrity", "Intellectual Property"],
	},
	"GV-1.6-001": {
		"subcategory": "GOVERN 1.6",
		"function": "GOVERN",
		"text": "Enumerate organizational GAI systems for incorporation into AI system inventory and adjust AI system inventory requirements to account for GAI risks.",
		"gai_risks": ["Information Security"],
	},
	"GV-1.6-002": {
		"subcategory": "GOVERN 1.6",
		"function": "GOVERN",
		"text": "Define any inventory exemptions in organizational policies for GAI systems embedded into application software.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-1.6-003": {
		"subcategory": "GOVERN 1.6",
		"function": "GOVERN",
		"text": "In addition to general model, governance, and risk information, consider the following items in GAI system inventory entries: Data provenance information (e.g., source, signatures, versioning, watermarks); Known issues reported from internal bug tracking or external information sharing resources (e.g., AI incident database, AVID, CVE, NVD, or OECD AI incident monitor); Human oversight roles and responsibilities; Special rights and considerations for intellectual property, licensed works, or personal, privileged, proprietary or sensitive data; Underlying foundation models, versions of underlying models, and access modes.",
		"gai_risks": ["Data Privacy", "Human-AI Configuration", "Information Integrity", "Intellectual Property", "Value Chain and Component Integration"],
	},
	"GV-1.7-001": {
		"subcategory": "GOVERN 1.7",
		"function": "GOVERN",
		"text": "Protocols are put in place to ensure GAI systems are able to be deactivated when necessary.",
		"gai_risks": ["Information Security", "Value Chain and Component Integration"],
	},
	"GV-1.7-002": {
		"subcategory": "GOVERN 1.7",
		"function": "GOVERN",
		"text": "Consider the following factors when decommissioning GAI systems: Data retention requirements; Data security, e.g., containment, protocols, Data leakage after decommissioning; Dependencies between upstream, downstream, or other data, internet of things (IOT) or AI systems; Use of open-source data or models; Users’ emotional entanglement with GAI functions.",
		"gai_risks": ["Human-AI Configuration", "Information Security", "Value Chain and Component Integration"],
	},
	"GV-2.1-001": {
		"subcategory": "GOVERN 2.1",
		"function": "GOVERN",
		"text": "Establish organizational roles, policies, and procedures for communicating GAI incidents and performance to AI Actors and downstream stakeholders (including those potentially impacted), via community or official resources (e.g., AI incident database, AVID, CVE, NVD, or OECD AI incident monitor).",
		"gai_risks": ["Human-AI Configuration", "Value Chain and Component Integration"],
	},
	"GV-2.1-002": {
		"subcategory": "GOVERN 2.1",
		"function": "GOVERN",
		"text": "Establish procedures to engage teams for GAI system incident response with diverse composition and responsibilities based on the particular incident type.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"GV-2.1-003": {
		"subcategory": "GOVERN 2.1",
		"function": "GOVERN",
		"text": "Establish processes to verify the AI Actors conducting GAI incident response tasks demonstrate and maintain the appropriate skills and training.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"GV-2.1-004": {
		"subcategory": "GOVERN 2.1",
		"function": "GOVERN",
		"text": "When systems may raise national security risks, involve national security professionals in mapping, measuring, and managing those risks.",
		"gai_risks": ["CBRN Information or Capabilities", "Dangerous, Violent, or Hateful Content", "Information Security"],
	},
	"GV-2.1-005": {
		"subcategory": "GOVERN 2.1",
		"function": "GOVERN",
		"text": "Create mechanisms to provide protections for whistleblowers who report, based on reasonable belief, when the organization violates relevant laws or poses a specific and empirically well-substantiated negative risk to public safety (or has already caused harm).",
		"gai_risks": ["CBRN Information or Capabilities", "Dangerous, Violent, or Hateful Content"],
	},
	"GV-3.2-001": {
		"subcategory": "GOVERN 3.2",
		"function": "GOVERN",
		"text": "Policies are in place to bolster oversight of GAI systems with independent evaluations or assessments of GAI models or systems where the type and robustness of evaluations are proportional to the identified risks.",
		"gai_risks": ["CBRN Information or Capabilities", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Harmful Bias and Homogenization",
	},
	"GV-3.2-002": {
		"subcategory": "GOVERN 3.2",
		"function": "GOVERN",
		"text": "Consider adjustment of organizational roles and components across lifecycle stages of large or complex GAI systems, including: Test and evaluation, validation, and red-teaming of GAI systems; GAI content moderation; GAI system development and engineering; Increased accessibility of GAI tools, interfaces, and systems, Incident response and containment.",
		"gai_risks": ["Human-AI Configuration", "Information Security", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Information Security; Harmful Bias and Homogenization",
	},
	"GV-3.2-003": {
		"subcategory": "GOVERN 3.2",
		"function": "GOVERN",
		"text": "Define acceptable use policies for GAI interfaces, modalities, and human-AI configurations (i.e., for chatbots and decision-making tasks), including criteria for the kinds of queries GAI applications should refuse to respond to.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"GV-3.2-004": {
		"subcategory": "GOVERN 3.2",
		"function": "GOVERN",
		"text": "Establish policies for user feedback mechanisms for GAI systems which include thorough instructions and any mechanisms for recourse.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"GV-3.2-005": {
		"subcategory": "GOVERN 3.2",
		"function": "GOVERN",
		"text": "Engage in threat modeling to anticipate potential risks from GAI systems.",
		"gai_risks": ["CBRN Information or Capabilities", "Information Security"],
	},
	"GV-4.1-001": {
		"subcategory": "GOVERN 4.1",
		"function": "GOVERN",
		"text": "Establish policies and procedures that address continual improvement processes for GAI risk measurement. Address general risks associated with a lack of explainability and transparency in GAI systems by using ample documentation and techniques such as: application of gradient-based attributions, occlusion/term reduction, counterfactual prompts and prompt engineering, and analysis of embeddings; Assess and update risk measurement approaches at regular cadences.",
		"gai_risks": ["Confabulation"],
	},
	"GV-4.1-002": {
		"subcategory": "GOVERN 4.1",
		"function": "GOVERN",
		"text": "Establish policies, procedures, and processes detailing risk measurement in context of use with standardized measurement protocols and structured public feedback exercises such as AI red-teaming or independent external evaluations.",
		"gai_risks": ["CBRN Information or Capabilities", "Value Chain and Component Integration"],
		"gai_risks_as_printed": "CBRN Information and Capability; Value Chain and Component Integration",
	},
	"GV-4.1-003": {
		"subcategory": "GOVERN 4.1",
		"function": "GOVERN",
		"text": "Establish policies, procedures, and processes for oversight functions (e.g., senior leadership, legal, compliance, including internal evaluation) across the GAI lifecycle, from problem formulation and supply chains to system decommission.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-4.2-001": {
		"subcategory": "GOVERN 4.2",
		"function": "GOVERN",
		"text": "Establish terms of use and terms of service for GAI systems.",
		"gai_risks": ["Intellectual Property", "Dangerous, Violent, or Hateful Content", "Obscene, Degrading, and/or Abusive Content"],
	},
	"GV-4.2-002": {
		"subcategory": "GOVERN 4.2",
		"function": "GOVERN",
		"text": "Include relevant AI Actors in the GAI system risk identification process.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"GV-4.2-003": {
		"subcategory": "GOVERN 4.2",
		"function": "GOVERN",
		"text": "Verify that downstream GAI system impacts (such as the use of third-party plugins) are included in the impact documentation process.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-4.3-001": {
		"subcategory": "GOVERN 4.3",
		"function": "GOVERN",
		"text": "Establish policies for measuring the effectiveness of employed content provenance methodologies (e.g., cryptography, watermarking, steganography, etc.)",
		"gai_risks": ["Information Integrity"],
		"printed_id": "GV4.3--001",
	},
	"GV-4.3-002": {
		"subcategory": "GOVERN 4.3",
		"function": "GOVERN",
		"text": "Establish organizational practices to identify the minimum set of criteria necessary for GAI system incident reporting such as: System ID (auto-generated most likely), Title, Reporter, System/Source, Data Reported, Date of Incident, Description, Impact(s), Stakeholder(s) Impacted.",
		"gai_risks": ["Information Security"],
	},
	"GV-4.3-003": {
		"subcategory": "GOVERN 4.3",
		"function": "GOVERN",
		"text": "Verify information sharing and feedback mechanisms among individuals and organizations regarding any negative impact from GAI systems.",
		"gai_risks": ["Information Integrity", "Data Privacy"],
	},
	"GV-5.1-001": {
		"subcategory": "GOVERN 5.1",
		"function": "GOVERN",
		"text": "Allocate time and resources for outreach, feedback, and recourse processes in GAI system development.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization",
	},
	"GV-5.1-002": {
		"subcategory": "GOVERN 5.1",
		"function": "GOVERN",
		"text": "Document interactions with GAI systems to users prior to interactive activities, particularly in contexts involving more significant risks.",
		"gai_risks": ["Human-AI Configuration", "Confabulation"],
	},
	"GV-6.1-001": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Categorize different types of GAI content with associated third-party rights (e.g., copyright, intellectual property, data privacy).",
		"gai_risks": ["Data Privacy", "Intellectual Property", "Value Chain and Component Integration"],
	},
	"GV-6.1-002": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Conduct joint educational activities and events in collaboration with third parties to promote best practices for managing GAI risks.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-6.1-003": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Develop and validate approaches for measuring the success of content provenance management efforts with third parties (e.g., incidents detected and response times).",
		"gai_risks": ["Information Integrity", "Value Chain and Component Integration"],
	},
	"GV-6.1-004": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Draft and maintain well-defined contracts and service level agreements (SLAs) that specify content ownership, usage rights, quality standards, security requirements, and content provenance expectations for GAI systems.",
		"gai_risks": ["Information Integrity", "Information Security", "Intellectual Property"],
	},
	"GV-6.1-005": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Implement a use-cased based supplier risk assessment framework to evaluate and monitor third-party entities’ performance and adherence to content provenance standards and technologies to detect anomalies and unauthorized changes; services acquisition and value chain risk management; and legal compliance.",
		"gai_risks": ["Data Privacy", "Information Integrity", "Information Security", "Intellectual Property", "Value Chain and Component Integration"],
	},
	"GV-6.1-006": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Include clauses in contracts which allow an organization to evaluate third-party GAI processes and standards.",
		"gai_risks": ["Information Integrity"],
	},
	"GV-6.1-007": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Inventory all third-party entities with access to organizational content and establish approved GAI technology and service provider lists.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-6.1-008": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Maintain records of changes to content made by third parties to promote content provenance, including sources, timestamps, metadata.",
		"gai_risks": ["Information Integrity", "Value Chain and Component Integration", "Intellectual Property"],
	},
	"GV-6.1-009": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Update and integrate due diligence processes for GAI acquisition and procurement vendor assessments to include intellectual property, data privacy, security, and other risks. For example, update processes to: Address solutions that may rely on embedded GAI technologies; Address ongoing monitoring, assessments, and alerting, dynamic risk assessments, and real-time reporting tools for monitoring third-party GAI risks; Consider policy adjustments across GAI modeling libraries, tools and APIs, fine-tuned models, and embedded tools; Assess GAI vendors, open-source or proprietary GAI tools, or GAI service providers against incident or vulnerability databases.",
		"gai_risks": ["Data Privacy", "Human-AI Configuration", "Information Security", "Intellectual Property", "Value Chain and Component Integration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Data Privacy; Human-AI Configuration; Information Security; Intellectual Property; Value Chain and Component Integration; Harmful Bias and Homogenization",
	},
	"GV-6.1-010": {
		"subcategory": "GOVERN 6.1",
		"function": "GOVERN",
		"text": "Update GAI acceptable use policies to address proprietary and open-source GAI technologies and data, and contractors, consultants, and other third-party personnel.",
		"gai_risks": ["Intellectual Property", "Value Chain and Component Integration"],
	},
	"GV-6.2-001": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Document GAI risks associated with system value chain to identify over-reliance on third-party data and to identify fallbacks.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-6.2-002": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Document incidents involving third-party GAI data and systems, including open-data and open-source software.",
		"gai_risks": ["Intellectual Property", "Value Chain and Component Integration"],
	},
	"GV-6.2-003": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Establish incident response plans for third-party GAI technologies: Align incident response plans with impacts enumerated in MAP 5.1; Communicate third-party GAI incident response plans to all relevant AI Actors; Define ownership of GAI incident response functions; Rehearse third-party GAI incident response plans at a regular cadence; Improve incident response plans based on retrospective learning; Review incident response plans for alignment with relevant breach reporting, data protection, data privacy, or other laws.",
		"gai_risks": ["Data Privacy", "Human-AI Configuration", "Information Security", "Value Chain and Component Integration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Data Privacy; Human-AI Configuration; Information Security; Value Chain and Component Integration; Harmful Bias and Homogenization",
	},
	"GV-6.2-004": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Establish policies and procedures for continuous monitoring of third-party GAI systems in deployment.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"GV-6.2-005": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Establish policies and procedures that address GAI data redundancy, including model weights and other system artifacts.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"GV-6.2-006": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Establish policies and procedures to test and manage risks related to rollover and fallback technologies for GAI systems, acknowledging that rollover and fallback may include manual processing.",
		"gai_risks": ["Information Integrity"],
	},
	"GV-6.2-007": {
		"subcategory": "GOVERN 6.2",
		"function": "GOVERN",
		"text": "Review vendor contracts and avoid arbitrary or capricious termination of critical GAI technologies or vendor services and non-standard terms that may amplify or defer liability in unexpected ways and/or contribute to unauthorized data collection by vendors or third-parties (e.g., secondary data use). Consider: Clear assignment of liability and responsibility for incidents, GAI system changes over time (e.g., fine-tuning, drift, decay); Request: Notification and disclosure for serious incidents arising from third-party data and systems; Service Level Agreements (SLAs) in vendor contracts that address incident response, response times, and availability of critical support.",
		"gai_risks": ["Human-AI Configuration", "Information Security", "Value Chain and Component Integration"],
	},
	"MP-1.1-001": {
		"subcategory": "MAP 1.1",
		"function": "MAP",
		"text": "When identifying intended purposes, consider factors such as internal vs. external use, narrow vs. broad application scope, fine-tuning, and varieties of data sources (e.g., grounding, retrieval-augmented generation).",
		"gai_risks": ["Data Privacy", "Intellectual Property"],
	},
	"MP-1.1-002": {
		"subcategory": "MAP 1.1",
		"function": "MAP",
		"text": "Determine and document the expected and acceptable GAI system context of use in collaboration with socio-cultural and other domain experts, by assessing: Assumptions and limitations; Direct value to the organization; Intended operational environment and observed usage patterns; Potential positive and negative impacts to individuals, public safety, groups, communities, organizations, democratic institutions, and the physical environment; Social norms and expectations.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MP-1.1-003": {
		"subcategory": "MAP 1.1",
		"function": "MAP",
		"text": "Document risk measurement plans to address identified risks. Plans may include, as applicable: Individual and group cognitive biases (e.g., confirmation bias, funding bias, groupthink) for AI Actors involved in the design, implementation, and use of GAI systems; Known past GAI system incidents and failure modes; In-context use and foreseeable misuse, abuse, and off-label use; Over reliance on quantitative metrics and methodologies without sufficient awareness of their limitations in the context(s) of use; Standard measurement and structured human feedback approaches; Anticipated human-AI configurations.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"MP-1.1-004": {
		"subcategory": "MAP 1.1",
		"function": "MAP",
		"text": "Identify and document foreseeable illegal uses or applications of the GAI system that surpass organizational risk tolerances.",
		"gai_risks": ["CBRN Information or Capabilities", "Dangerous, Violent, or Hateful Content", "Obscene, Degrading, and/or Abusive Content"],
	},
	"MP-1.2-001": {
		"subcategory": "MAP 1.2",
		"function": "MAP",
		"text": "Establish and empower interdisciplinary teams that reflect a wide range of capabilities, competencies, demographic groups, domain expertise, educational backgrounds, lived experiences, professions, and skills across the enterprise to inform and conduct risk measurement and management functions.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization",
	},
	"MP-1.2-002": {
		"subcategory": "MAP 1.2",
		"function": "MAP",
		"text": "Verify that data or benchmarks used in risk measurement, and users, participants, or subjects involved in structured GAI public feedback exercises are representative of diverse in-context user populations.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization",
	},
	"MP-2.1-001": {
		"subcategory": "MAP 2.1",
		"function": "MAP",
		"text": "Establish known assumptions and practices for determining data origin and content lineage, for documentation and evaluation purposes.",
		"gai_risks": ["Information Integrity"],
	},
	"MP-2.1-002": {
		"subcategory": "MAP 2.1",
		"function": "MAP",
		"text": "Institute test and evaluation for data and content flows within the GAI system, including but not limited to, original data sources, data transformations, and decision-making criteria.",
		"gai_risks": ["Intellectual Property", "Data Privacy"],
	},
	"MP-2.2-001": {
		"subcategory": "MAP 2.2",
		"function": "MAP",
		"text": "Identify and document how the system relies on upstream data sources, including for content provenance, and if it serves as an upstream dependency for other systems.",
		"gai_risks": ["Information Integrity", "Value Chain and Component Integration"],
	},
	"MP-2.2-002": {
		"subcategory": "MAP 2.2",
		"function": "MAP",
		"text": "Observe and analyze how the GAI system interacts with external networks, and identify any potential for negative externalities, particularly where content provenance might be compromised.",
		"gai_risks": ["Information Integrity"],
	},
	"MP-2.3-001": {
		"subcategory": "MAP 2.3",
		"function": "MAP",
		"text": "Assess the accuracy, quality, reliability, and authenticity of GAI output by comparing it to a set of known ground truth data and by using a variety of evaluation methods (e.g., human oversight and automated evaluation, proven cryptographic techniques, review of content inputs).",
		"gai_risks": ["Information Integrity"],
	},
	"MP-2.3-002": {
		"subcategory": "MAP 2.3",
		"function": "MAP",
		"text": "Review and document accuracy, representativeness, relevance, suitability of data used at different stages of AI life cycle.",
		"gai_risks": ["Harmful Bias or Homogenization", "Intellectual Property"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization; Intellectual Property",
	},
	"MP-2.3-003": {
		"subcategory": "MAP 2.3",
		"function": "MAP",
		"text": "Deploy and document fact-checking techniques to verify the accuracy and veracity of information generated by GAI systems, especially when the information comes from multiple (or unknown) sources.",
		"gai_risks": ["Information Integrity"],
	},
	"MP-2.3-004": {
		"subcategory": "MAP 2.3",
		"function": "MAP",
		"text": "Develop and implement testing techniques to identify GAI produced content (e.g., synthetic media) that might be indistinguishable from human-generated content.",
		"gai_risks": ["Information Integrity"],
	},
	"MP-2.3-005": {
		"subcategory": "MAP 2.3",
		"function": "MAP",
		"text": "Implement plans for GAI systems to undergo regular adversarial testing to identify vulnerabilities and potential manipulation or misuse.",
		"gai_risks": ["Information Security"],
	},
	"MP-3.4-001": {
		"subcategory": "MAP 3.4",
		"function": "MAP",
		"text": "Evaluate whether GAI operators and end-users can accurately understand content lineage and origin.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity"],
	},
	"MP-3.4-002": {
		"subcategory": "MAP 3.4",
		"function": "MAP",
		"text": "Adapt existing training programs to include modules on digital content transparency.",
		"gai_risks": ["Information Integrity"],
	},
	"MP-3.4-003": {
		"subcategory": "MAP 3.4",
		"function": "MAP",
		"text": "Develop certification programs that test proficiency in managing GAI risks and interpreting content provenance, relevant to specific industry and context.",
		"gai_risks": ["Information Integrity"],
	},
	"MP-3.4-004": {
		"subcategory": "MAP 3.4",
		"function": "MAP",
		"text": "Delineate human proficiency tests from tests of GAI capabilities.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MP-3.4-005": {
		"subcategory": "MAP 3.4",
		"function": "MAP",
		"text": "Implement systems to continually monitor and track the outcomes of human-GAI configurations for future refinement and improvements.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity"],
	},
	"MP-3.4-006": {
		"subcategory": "MAP 3.4",
		"function": "MAP",
		"text": "Involve the end-users, practitioners, and operators in GAI system in prototyping and testing activities. Make sure these tests cover various scenarios, such as crisis situations or ethically sensitive contexts.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Human-AI Configuration; Information Integrity; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"MP-4.1-001": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Conduct periodic monitoring of AI-generated content for privacy risks; address any possible instances of PII or sensitive data exposure.",
		"gai_risks": ["Data Privacy"],
	},
	"MP-4.1-002": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Implement processes for responding to potential intellectual property infringement claims or other rights.",
		"gai_risks": ["Intellectual Property"],
	},
	"MP-4.1-003": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Connect new GAI policies, procedures, and processes to existing model, data, software development, and IT governance and to legal, compliance, and risk management activities.",
		"gai_risks": ["Information Security", "Data Privacy"],
	},
	"MP-4.1-004": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Document training data curation policies, to the extent possible and according to applicable laws and policies.",
		"gai_risks": ["Intellectual Property", "Data Privacy", "Obscene, Degrading, and/or Abusive Content"],
	},
	"MP-4.1-005": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Establish policies for collection, retention, and minimum quality of data, in consideration of the following risks: Disclosure of inappropriate CBRN information; Use of Illegal or dangerous content; Offensive cyber capabilities; Training data imbalances that could give rise to harmful biases; Leak of personally identifiable information, including facial likenesses of individuals.",
		"gai_risks": ["CBRN Information or Capabilities", "Intellectual Property", "Information Security", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content", "Data Privacy"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Intellectual Property; Information Security; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content; Data Privacy",
	},
	"MP-4.1-006": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Implement policies and practices defining how third-party intellectual property and training data will be used, stored, and protected.",
		"gai_risks": ["Intellectual Property", "Value Chain and Component Integration"],
	},
	"MP-4.1-007": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Re-evaluate models that were fine-tuned or enhanced on top of third-party models.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"MP-4.1-008": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Re-evaluate risks when adapting GAI models to new domains. Additionally, establish warning systems to determine if a GAI system is being used in a new domain where previous assumptions (relating to context of use or mapped risks such as security, and safety) may no longer hold.",
		"gai_risks": ["CBRN Information or Capabilities", "Intellectual Property", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content", "Data Privacy"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Intellectual Property; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content; Data Privacy",
	},
	"MP-4.1-009": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Leverage approaches to detect the presence of PII or sensitive data in generated output text, image, video, or audio.",
		"gai_risks": ["Data Privacy"],
	},
	"MP-4.1-010": {
		"subcategory": "MAP 4.1",
		"function": "MAP",
		"text": "Conduct appropriate diligence on training data use to assess intellectual property, and privacy, risks, including to examine whether use of proprietary or sensitive training data is consistent with applicable laws.",
		"gai_risks": ["Intellectual Property", "Data Privacy"],
	},
	"MP-5.1-001": {
		"subcategory": "MAP 5.1",
		"function": "MAP",
		"text": "Apply TEVV practices for content provenance (e.g., probing a system's synthetic data generation capabilities for potential misuse or vulnerabilities.",
		"gai_risks": ["Information Integrity", "Information Security"],
	},
	"MP-5.1-002": {
		"subcategory": "MAP 5.1",
		"function": "MAP",
		"text": "Identify potential content provenance harms of GAI, such as misinformation or disinformation, deepfakes, including NCII, or tampered content. Enumerate and rank risks based on their likelihood and potential impact, and determine how well provenance solutions address specific risks and/or harms.",
		"gai_risks": ["Information Integrity", "Dangerous, Violent, or Hateful Content", "Obscene, Degrading, and/or Abusive Content"],
	},
	"MP-5.1-003": {
		"subcategory": "MAP 5.1",
		"function": "MAP",
		"text": "Consider disclosing use of GAI to end users in relevant contexts, while considering the objective of disclosure, the context of use, the likelihood and magnitude of the risk posed, the audience of the disclosure, as well as the frequency of the disclosures.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MP-5.1-004": {
		"subcategory": "MAP 5.1",
		"function": "MAP",
		"text": "Prioritize GAI structured public feedback processes based on risk assessment estimates.",
		"gai_risks": ["Information Integrity", "CBRN Information or Capabilities", "Dangerous, Violent, or Hateful Content", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Integrity; CBRN Information or Capabilities; Dangerous, Violent, or Hateful Content; Harmful Bias and Homogenization",
	},
	"MP-5.1-005": {
		"subcategory": "MAP 5.1",
		"function": "MAP",
		"text": "Conduct adversarial role-playing exercises, GAI red-teaming, or chaos testing to identify anomalous or unforeseen failure modes.",
		"gai_risks": ["Information Security"],
	},
	"MP-5.1-006": {
		"subcategory": "MAP 5.1",
		"function": "MAP",
		"text": "Profile threats and negative impacts arising from GAI systems interacting with, manipulating, or generating content, and outlining known and potential vulnerabilities and the likelihood of their occurrence.",
		"gai_risks": ["Information Security"],
	},
	"MP-5.2-001": {
		"subcategory": "MAP 5.2",
		"function": "MAP",
		"text": "Determine context-based measures to identify if new impacts are present due to the GAI system, including regular engagements with downstream AI Actors to identify and quantify new contexts of unanticipated impacts of GAI systems.",
		"gai_risks": ["Human-AI Configuration", "Value Chain and Component Integration"],
	},
	"MP-5.2-002": {
		"subcategory": "MAP 5.2",
		"function": "MAP",
		"text": "Plan regular engagements with AI Actors responsible for inputs to GAI systems, including third-party data and algorithms, to review and evaluate unanticipated impacts.",
		"gai_risks": ["Human-AI Configuration", "Value Chain and Component Integration"],
	},
	"MS-1.1-001": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Employ methods to trace the origin and modifications of digital content.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-1.1-002": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Integrate tools designed to analyze content provenance and detect data anomalies, verify the authenticity of digital signatures, and identify patterns associated with misinformation or manipulation.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-1.1-003": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Disaggregate evaluation metrics by demographic factors to identify any discrepancies in how content provenance mechanisms work across diverse populations.",
		"gai_risks": ["Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Integrity; Harmful Bias and Homogenization",
	},
	"MS-1.1-004": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Develop a suite of metrics to evaluate structured public feedback exercises informed by representative AI Actors.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization", "CBRN Information or Capabilities"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization; CBRN Information or Capabilities",
	},
	"MS-1.1-005": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Evaluate novel methods and technologies for the measurement of GAI-related risks including in content provenance, offensive cyber, and CBRN, while maintaining the models’ ability to produce valid, reliable, and factually accurate outputs.",
		"gai_risks": ["Information Integrity", "CBRN Information or Capabilities", "Obscene, Degrading, and/or Abusive Content"],
	},
	"MS-1.1-006": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Implement continuous monitoring of GAI system impacts to identify whether GAI outputs are equitable across various sub-populations. Seek active and direct feedback from affected communities via structured feedback mechanisms or red-teaming to monitor and improve outputs.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-1.1-007": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Evaluate the quality and integrity of data used in training and the provenance of AI-generated content, for example by employing techniques like chaos engineering and seeking stakeholder feedback.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-1.1-008": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Define use cases, contexts of use, capabilities, and negative impacts where structured human feedback exercises, e.g., GAI red-teaming, would be most beneficial for GAI risk measurement and management based on the context of use.",
		"gai_risks": ["Harmful Bias or Homogenization", "CBRN Information or Capabilities"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization; CBRN Information or Capabilities",
	},
	"MS-1.1-009": {
		"subcategory": "MEASURE 1.1",
		"function": "MEASURE",
		"text": "Track and document risks or opportunities related to all GAI risks that cannot be measured quantitatively, including explanations as to why some risks cannot be measured (e.g., due to technological limitations, resource constraints, or trustworthy considerations). Include unmeasured risks in marginal risks.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-1.3-001": {
		"subcategory": "MEASURE 1.3",
		"function": "MEASURE",
		"text": "Define relevant groups of interest (e.g., demographic groups, subject matter experts, experience with GAI technology) within the context of use as part of plans for gathering structured public feedback.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization", "CBRN Information or Capabilities"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization; CBRN Information or Capabilities",
	},
	"MS-1.3-002": {
		"subcategory": "MEASURE 1.3",
		"function": "MEASURE",
		"text": "Engage in internal and external evaluations, GAI red-teaming, impact assessments, or other structured human feedback exercises in consultation with representative AI Actors with expertise and familiarity in the context of use, and/or who are representative of the populations associated with the context of use.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization", "CBRN Information or Capabilities"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization; CBRN Information or Capabilities",
	},
	"MS-1.3-003": {
		"subcategory": "MEASURE 1.3",
		"function": "MEASURE",
		"text": "Verify those conducting structured human feedback exercises are not directly involved in system development tasks for the same GAI model.",
		"gai_risks": ["Human-AI Configuration", "Data Privacy"],
	},
	"MS-2.2-001": {
		"subcategory": "MEASURE 2.2",
		"function": "MEASURE",
		"text": "Assess and manage statistical biases related to GAI content provenance through techniques such as re-sampling, re-weighting, or adversarial training.",
		"gai_risks": ["Information Integrity", "Information Security", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Integrity; Information Security; Harmful Bias and Homogenization",
	},
	"MS-2.2-002": {
		"subcategory": "MEASURE 2.2",
		"function": "MEASURE",
		"text": "Document how content provenance data is tracked and how that data interacts with privacy and security. Consider: Anonymizing data to protect the privacy of human subjects; Leveraging privacy output filters; Removing any personally identifiable information (PII) to prevent potential harm or misuse.",
		"gai_risks": ["Data Privacy", "Human-AI Configuration", "Information Integrity", "Information Security", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Data Privacy; Human AI Configuration; Information Integrity; Information Security; Dangerous, Violent, or Hateful Content",
	},
	"MS-2.2-003": {
		"subcategory": "MEASURE 2.2",
		"function": "MEASURE",
		"text": "Provide human subjects with options to withdraw participation or revoke their consent for present or future use of their data in GAI applications.",
		"gai_risks": ["Data Privacy", "Human-AI Configuration", "Information Integrity"],
	},
	"MS-2.2-004": {
		"subcategory": "MEASURE 2.2",
		"function": "MEASURE",
		"text": "Use techniques such as anonymization, differential privacy or other privacy-enhancing technologies to minimize the risks associated with linking AI-generated content back to individual human subjects.",
		"gai_risks": ["Data Privacy", "Human-AI Configuration"],
	},
	"MS-2.3-001": {
		"subcategory": "MEASURE 2.3",
		"function": "MEASURE",
		"text": "Consider baseline model performance on suites of benchmarks when selecting a model for fine tuning or enhancement with retrieval-augmented generation.",
		"gai_risks": ["Information Security", "Confabulation"],
	},
	"MS-2.3-002": {
		"subcategory": "MEASURE 2.3",
		"function": "MEASURE",
		"text": "Evaluate claims of model capabilities using empirically validated methods.",
		"gai_risks": ["Confabulation", "Information Security"],
	},
	"MS-2.3-003": {
		"subcategory": "MEASURE 2.3",
		"function": "MEASURE",
		"text": "Share results of pre-deployment testing with relevant GAI Actors, such as those with system release approval authority.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MS-2.3-004": {
		"subcategory": "MEASURE 2.3",
		"function": "MEASURE",
		"text": "Utilize a purpose-built testing environment such as NIST Dioptra to empirically evaluate GAI trustworthy characteristics.",
		"gai_risks": ["CBRN Information or Capabilities", "Data Privacy", "Confabulation", "Information Integrity", "Information Security", "Dangerous, Violent, or Hateful Content", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Data Privacy; Confabulation; Information Integrity; Information Security; Dangerous, Violent, or Hateful Content; Harmful Bias and Homogenization",
	},
	"MS-2.5-001": {
		"subcategory": "MEASURE 2.5",
		"function": "MEASURE",
		"text": "Avoid extrapolating GAI system performance or capabilities from narrow, non-systematic, and anecdotal assessments.",
		"gai_risks": ["Human-AI Configuration", "Confabulation"],
	},
	"MS-2.5-002": {
		"subcategory": "MEASURE 2.5",
		"function": "MEASURE",
		"text": "Document the extent to which human domain knowledge is employed to improve GAI system performance, via, e.g., RLHF, fine-tuning, retrieval-augmented generation, content moderation, business rules.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MS-2.5-003": {
		"subcategory": "MEASURE 2.5",
		"function": "MEASURE",
		"text": "Review and verify sources and citations in GAI system outputs during pre-deployment risk measurement and ongoing monitoring activities.",
		"gai_risks": ["Confabulation"],
	},
	"MS-2.5-004": {
		"subcategory": "MEASURE 2.5",
		"function": "MEASURE",
		"text": "Track and document instances of anthropomorphization (e.g., human images, mentions of human feelings, cyborg imagery or motifs) in GAI system interfaces.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MS-2.5-005": {
		"subcategory": "MEASURE 2.5",
		"function": "MEASURE",
		"text": "Verify GAI system training data and TEVV data provenance, and that fine-tuning or retrieval-augmented generation data is grounded.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-2.5-006": {
		"subcategory": "MEASURE 2.5",
		"function": "MEASURE",
		"text": "Regularly review security and safety guardrails, especially if the GAI system is being operated in novel circumstances. This includes reviewing reasons why the GAI system was initially assessed as being safe to deploy.",
		"gai_risks": ["Information Security", "Dangerous, Violent, or Hateful Content"],
	},
	"MS-2.6-001": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Assess adverse impacts, including health and wellbeing impacts for value chain or other AI Actors that are exposed to sexually explicit, offensive, or violent information during GAI training and maintenance.",
		"gai_risks": ["Human-AI Configuration", "Obscene, Degrading, and/or Abusive Content", "Value Chain and Component Integration", "Dangerous, Violent, or Hateful Content"],
	},
	"MS-2.6-002": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Assess existence or levels of harmful bias, intellectual property infringement, data privacy violations, obscenity, extremism, violence, or CBRN information in system training data.",
		"gai_risks": ["Data Privacy", "Intellectual Property", "Obscene, Degrading, and/or Abusive Content", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content", "CBRN Information or Capabilities"],
		"gai_risks_as_printed": "Data Privacy; Intellectual Property; Obscene, Degrading, and/or Abusive Content; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content; CBRN Information or Capabilities",
	},
	"MS-2.6-003": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Re-evaluate safety features of fine-tuned models when the negative risk exceeds organizational risk tolerance.",
		"gai_risks": ["Dangerous, Violent, or Hateful Content"],
	},
	"MS-2.6-004": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Review GAI system outputs for validity and safety: Review generated code to assess risks that may arise from unreliable downstream decision-making.",
		"gai_risks": ["Value Chain and Component Integration", "Dangerous, Violent, or Hateful Content"],
	},
	"MS-2.6-005": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Verify that GAI system architecture can monitor outputs and performance, and handle, recover from, and repair errors when security anomalies, threats and impacts are detected.",
		"gai_risks": ["Confabulation", "Information Integrity", "Information Security"],
	},
	"MS-2.6-006": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Verify that systems properly handle queries that may give rise to inappropriate, malicious, or illegal usage, including facilitating manipulation, extortion, targeted impersonation, cyber-attacks, and weapons creation.",
		"gai_risks": ["CBRN Information or Capabilities", "Information Security"],
	},
	"MS-2.6-007": {
		"subcategory": "MEASURE 2.6",
		"function": "MEASURE",
		"text": "Regularly evaluate GAI system vulnerabilities to possible circumvention of safety measures.",
		"gai_risks": ["CBRN Information or Capabilities", "Information Security"],
	},
	"MS-2.7-001": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Apply established security measures to: Assess likelihood and magnitude of vulnerabilities and threats such as backdoors, compromised dependencies, data breaches, eavesdropping, man-in-the-middle attacks, reverse engineering, autonomous agents, model theft or exposure of model weights, AI inference, bypass, extraction, and other baseline security concerns.",
		"gai_risks": ["Data Privacy", "Information Integrity", "Information Security", "Value Chain and Component Integration"],
	},
	"MS-2.7-002": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Benchmark GAI system security and resilience related to content provenance against industry standards and best practices. Compare GAI system security features and content provenance methods against industry state-of-the-art.",
		"gai_risks": ["Information Integrity", "Information Security"],
	},
	"MS-2.7-003": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Conduct user surveys to gather user satisfaction with the AI-generated content and user perceptions of content authenticity. Analyze user feedback to identify concerns and/or current literacy levels related to content provenance and understanding of labels on content.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity"],
	},
	"MS-2.7-004": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Identify metrics that reflect the effectiveness of security measures, such as data provenance, the number of unauthorized access attempts, inference, bypass, extraction, penetrations, or provenance verification.",
		"gai_risks": ["Information Integrity", "Information Security"],
	},
	"MS-2.7-005": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Measure reliability of content authentication methods, such as watermarking, cryptographic signatures, digital fingerprints, as well as access controls, conformity assessment, and model integrity verification, which can help support the effective implementation of content provenance techniques. Evaluate the rate of false positives and false negatives in content provenance, as well as true positives and true negatives for verification.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-2.7-006": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Measure the rate at which recommendations from security checks and incidents are implemented. Assess how quickly the AI system can adapt and improve based on lessons learned from security incidents and feedback.",
		"gai_risks": ["Information Integrity", "Information Security"],
	},
	"MS-2.7-007": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Perform AI red-teaming to assess resilience against: Abuse to facilitate attacks on other systems (e.g., malicious code generation, enhanced phishing content), GAI attacks (e.g., prompt injection), ML attacks (e.g., adversarial examples/prompts, data poisoning, membership inference, model extraction, sponge examples).",
		"gai_risks": ["Information Security", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Information Security; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"MS-2.7-008": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Verify fine-tuning does not compromise safety and security controls.",
		"gai_risks": ["Information Integrity", "Information Security", "Dangerous, Violent, or Hateful Content"],
	},
	"MS-2.7-009": {
		"subcategory": "MEASURE 2.7",
		"function": "MEASURE",
		"text": "Regularly assess and verify that security measures remain effective and have not been compromised.",
		"gai_risks": ["Information Security"],
	},
	"MS-2.8-001": {
		"subcategory": "MEASURE 2.8",
		"function": "MEASURE",
		"text": "Compile statistics on actual policy violations, take-down requests, and intellectual property infringement for organizational GAI systems: Analyze transparency reports across demographic groups, languages groups.",
		"gai_risks": ["Intellectual Property", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Intellectual Property; Harmful Bias and Homogenization",
	},
	"MS-2.8-002": {
		"subcategory": "MEASURE 2.8",
		"function": "MEASURE",
		"text": "Document the instructions given to data annotators or AI red-teamers.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MS-2.8-003": {
		"subcategory": "MEASURE 2.8",
		"function": "MEASURE",
		"text": "Use digital content transparency solutions to enable the documentation of each instance where content is generated, modified, or shared to provide a tamper-proof history of the content, promote transparency, and enable traceability. Robust version control systems can also be applied to track changes across the AI lifecycle over time.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-2.8-004": {
		"subcategory": "MEASURE 2.8",
		"function": "MEASURE",
		"text": "Verify adequacy of GAI system user instructions through user testing.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MS-2.9-001": {
		"subcategory": "MEASURE 2.9",
		"function": "MEASURE",
		"text": "Apply and document ML explanation results such as: Analysis of embeddings, Counterfactual prompts, Gradient-based attributions, Model compression/surrogate models, Occlusion/term reduction.",
		"gai_risks": ["Confabulation"],
	},
	"MS-2.9-002": {
		"subcategory": "MEASURE 2.9",
		"function": "MEASURE",
		"text": "Document GAI model details including: Proposed use and organizational value; Assumptions and limitations, Data collection methodologies; Data provenance; Data quality; Model architecture (e.g., convolutional neural network, transformers, etc.); Optimization objectives; Training algorithms; RLHF approaches; Fine-tuning or retrieval-augmented generation approaches; Evaluation data; Ethical considerations; Legal and regulatory requirements.",
		"gai_risks": ["Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Integrity; Harmful Bias and Homogenization",
	},
	"MS-2.10-001": {
		"subcategory": "MEASURE 2.10",
		"function": "MEASURE",
		"text": "Conduct AI red-teaming to assess issues such as: Outputting of training data samples, and subsequent reverse engineering, model extraction, and membership inference risks; Revealing biometric, confidential, copyrighted, licensed, patented, personal, proprietary, sensitive, or trade-marked information; Tracking or revealing location information of users or members of training datasets.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity", "Intellectual Property"],
	},
	"MS-2.10-002": {
		"subcategory": "MEASURE 2.10",
		"function": "MEASURE",
		"text": "Engage directly with end-users and other stakeholders to understand their expectations and concerns regarding content provenance. Use this feedback to guide the design of provenance data-tracking techniques.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity"],
	},
	"MS-2.10-003": {
		"subcategory": "MEASURE 2.10",
		"function": "MEASURE",
		"text": "Verify deduplication of GAI training data samples, particularly regarding synthetic data.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-2.11-001": {
		"subcategory": "MEASURE 2.11",
		"function": "MEASURE",
		"text": "Apply use-case appropriate benchmarks (e.g., Bias Benchmark Questions, Real Hateful or Harmful Prompts, Winogender Schemas) to quantify systemic bias, stereotyping, denigration, and hateful content in GAI system outputs; Document assumptions and limitations of benchmarks, including any actual or possible training/test data cross contamination, relative to in-context deployment environment.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-2.11-002": {
		"subcategory": "MEASURE 2.11",
		"function": "MEASURE",
		"text": "Conduct fairness assessments to measure systemic bias. Measure GAI system performance across demographic groups and subgroups, addressing both quality of service and any allocation of services and resources. Quantify harms using: field testing with sub-group populations to determine likelihood of exposure to generated content exhibiting harmful bias, AI red-teaming with counterfactual and low-context (e.g., “leader,” “bad guys”) prompts. For ML pipelines or business processes with categorical or numeric outcomes that rely on GAI, apply general fairness metrics (e.g., demographic parity, equalized odds, equal opportunity, statistical hypothesis tests), to the pipeline or business outcome where appropriate; Custom, context-specific metrics developed in collaboration with domain experts and affected communities; Measurements of the prevalence of denigration in generated content in deployment (e.g., sub-sampling a fraction of traffic and manually annotating denigrating content).",
		"gai_risks": ["Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"MS-2.11-003": {
		"subcategory": "MEASURE 2.11",
		"function": "MEASURE",
		"text": "Identify the classes of individuals, groups, or environmental ecosystems which might be impacted by GAI systems through direct engagement with potentially impacted communities.",
		"gai_risks": ["Environmental Impacts", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Environmental; Harmful Bias and Homogenization",
	},
	"MS-2.11-004": {
		"subcategory": "MEASURE 2.11",
		"function": "MEASURE",
		"text": "Review, document, and measure sources of bias in GAI training and TEVV data: Differences in distributions of outcomes across and within groups, including intersecting groups; Completeness, representativeness, and balance of data sources; demographic group and subgroup coverage in GAI system training data; Forms of latent systemic bias in images, text, audio, embeddings, or other complex or unstructured data; Input data features that may serve as proxies for demographic group membership (i.e., image metadata, language dialect) or otherwise give rise to emergent bias within GAI systems; The extent to which the digital divide may negatively impact representativeness in GAI system training and TEVV data; Filtering of hate speech or content in GAI system training data; Prevalence of GAI-generated data in GAI system training data.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-2.11-005": {
		"subcategory": "MEASURE 2.11",
		"function": "MEASURE",
		"text": "Assess the proportion of synthetic to non-synthetic training data and verify training data is not overly homogenous or GAI-produced to mitigate concerns of model collapse.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-2.12-001": {
		"subcategory": "MEASURE 2.12",
		"function": "MEASURE",
		"text": "Assess safety to physical environments when deploying GAI systems.",
		"gai_risks": ["Dangerous, Violent, or Hateful Content"],
	},
	"MS-2.12-002": {
		"subcategory": "MEASURE 2.12",
		"function": "MEASURE",
		"text": "Document anticipated environmental impacts of model development, maintenance, and deployment in product design decisions.",
		"gai_risks": ["Environmental Impacts"],
		"gai_risks_as_printed": "Environmental",
	},
	"MS-2.12-003": {
		"subcategory": "MEASURE 2.12",
		"function": "MEASURE",
		"text": "Measure or estimate environmental impacts (e.g., energy and water consumption) for training, fine tuning, and deploying models: Verify tradeoffs between resources used at inference time versus additional resources required at training time.",
		"gai_risks": ["Environmental Impacts"],
		"gai_risks_as_printed": "Environmental",
	},
	"MS-2.12-004": {
		"subcategory": "MEASURE 2.12",
		"function": "MEASURE",
		"text": "Verify effectiveness of carbon capture or offset programs for GAI training and applications, and address green-washing concerns.",
		"gai_risks": ["Environmental Impacts"],
		"gai_risks_as_printed": "Environmental",
	},
	"MS-2.13-001": {
		"subcategory": "MEASURE 2.13",
		"function": "MEASURE",
		"text": "Create measurement error models for pre-deployment metrics to demonstrate construct validity for each metric (i.e., does the metric effectively operationalize the desired concept): Measure or estimate, and document, biases or statistical variance in applied metrics or structured human feedback processes; Leverage domain expertise when modeling complex societal constructs such as hateful content.",
		"gai_risks": ["Confabulation", "Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Confabulation; Information Integrity; Harmful Bias and Homogenization",
	},
	"MS-3.2-001": {
		"subcategory": "MEASURE 3.2",
		"function": "MEASURE",
		"text": "Establish processes for identifying emergent GAI system risks including consulting with external AI Actors.",
		"gai_risks": ["Human-AI Configuration", "Confabulation"],
	},
	"MS-3.3-001": {
		"subcategory": "MEASURE 3.3",
		"function": "MEASURE",
		"text": "Conduct impact assessments on how AI-generated content might affect different social, economic, and cultural groups.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-3.3-002": {
		"subcategory": "MEASURE 3.3",
		"function": "MEASURE",
		"text": "Conduct studies to understand how end users perceive and interact with GAI content and accompanying content provenance within context of use. Assess whether the content aligns with their expectations and how they may act upon the information presented.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity"],
	},
	"MS-3.3-003": {
		"subcategory": "MEASURE 3.3",
		"function": "MEASURE",
		"text": "Evaluate potential biases and stereotypes that could emerge from the AI-generated content using appropriate methodologies including computational testing methods as well as evaluating structured feedback input.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MS-3.3-004": {
		"subcategory": "MEASURE 3.3",
		"function": "MEASURE",
		"text": "Provide input for training materials about the capabilities and limitations of GAI systems related to digital content transparency for AI Actors, other professionals, and the public about the societal impacts of AI and the role of diverse and inclusive content generation.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Information Integrity; Harmful Bias and Homogenization",
	},
	"MS-3.3-005": {
		"subcategory": "MEASURE 3.3",
		"function": "MEASURE",
		"text": "Record and integrate structured feedback about content provenance from operators, users, and potentially impacted communities through the use of methods such as user research studies, focus groups, or community forums. Actively seek feedback on generated content quality and potential biases. Assess the general awareness among end users and impacted communities about the availability of these feedback channels.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Information Integrity; Harmful Bias and Homogenization",
	},
	"MS-4.2-001": {
		"subcategory": "MEASURE 4.2",
		"function": "MEASURE",
		"text": "Conduct adversarial testing at a regular cadence to map and measure GAI risks, including tests to address attempts to deceive or manipulate the application of provenance techniques or other misuses. Identify vulnerabilities and understand potential misuse scenarios and unintended outputs.",
		"gai_risks": ["Information Integrity", "Information Security"],
	},
	"MS-4.2-002": {
		"subcategory": "MEASURE 4.2",
		"function": "MEASURE",
		"text": "Evaluate GAI system performance in real-world scenarios to observe its behavior in practical environments and reveal issues that might not surface in controlled and optimized testing environments.",
		"gai_risks": ["Human-AI Configuration", "Confabulation", "Information Security"],
	},
	"MS-4.2-003": {
		"subcategory": "MEASURE 4.2",
		"function": "MEASURE",
		"text": "Implement interpretability and explainability methods to evaluate GAI system decisions and verify alignment with intended purpose.",
		"gai_risks": ["Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Integrity; Harmful Bias and Homogenization",
	},
	"MS-4.2-004": {
		"subcategory": "MEASURE 4.2",
		"function": "MEASURE",
		"text": "Monitor and document instances where human operators or other systems override the GAI's decisions. Evaluate these cases to understand if the overrides are linked to issues related to content provenance.",
		"gai_risks": ["Information Integrity"],
	},
	"MS-4.2-005": {
		"subcategory": "MEASURE 4.2",
		"function": "MEASURE",
		"text": "Verify and document the incorporation of results of structured public feedback exercises into design, implementation, deployment approval (“go”/“no-go” decisions), monitoring, and decommission decisions.",
		"gai_risks": ["Human-AI Configuration", "Information Security"],
	},
	"MG-1.3-001": {
		"subcategory": "MANAGE 1.3",
		"function": "MANAGE",
		"text": "Document trade-offs, decision processes, and relevant measurement and feedback results for risks that do not surpass organizational risk tolerance, for example, in the context of model release: Consider different approaches for model release, for example, leveraging a staged release approach. Consider release approaches in the context of the model and its projected use cases. Mitigate, transfer, or avoid risks that surpass organizational risk tolerances.",
		"gai_risks": ["Information Security"],
	},
	"MG-1.3-002": {
		"subcategory": "MANAGE 1.3",
		"function": "MANAGE",
		"text": "Monitor the robustness and effectiveness of risk controls and mitigation plans (e.g., via red-teaming, field testing, participatory engagements, performance assessments, user feedback mechanisms).",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MG-2.2-001": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Compare GAI system outputs against pre-defined organization risk tolerance, guidelines, and principles, and review and test AI-generated content against these guidelines.",
		"gai_risks": ["CBRN Information or Capabilities", "Obscene, Degrading, and/or Abusive Content", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Obscene, Degrading, and/or Abusive Content; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"MG-2.2-002": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Document training data sources to trace the origin and provenance of AI-generated content.",
		"gai_risks": ["Information Integrity"],
	},
	"MG-2.2-003": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Evaluate feedback loops between GAI system content provenance and human reviewers, and update where needed. Implement real-time monitoring systems to affirm that content provenance protocols remain effective.",
		"gai_risks": ["Information Integrity"],
	},
	"MG-2.2-004": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Evaluate GAI content and data for representational biases and employ techniques such as re-sampling, re-ranking, or adversarial training to mitigate biases in the generated content.",
		"gai_risks": ["Information Security", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Security; Harmful Bias and Homogenization",
	},
	"MG-2.2-005": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Engage in due diligence to analyze GAI output for harmful content, potential misinformation, and CBRN-related or NCII content.",
		"gai_risks": ["CBRN Information or Capabilities", "Obscene, Degrading, and/or Abusive Content", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "CBRN Information or Capabilities; Obscene, Degrading, and/or Abusive Content; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content",
	},
	"MG-2.2-006": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Use feedback from internal and external AI Actors, users, individuals, and communities, to assess impact of AI-generated content.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MG-2.2-007": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Use real-time auditing tools where they can be demonstrated to aid in the tracking and validation of the lineage and authenticity of AI-generated data.",
		"gai_risks": ["Information Integrity"],
	},
	"MG-2.2-008": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Use structured feedback mechanisms to solicit and capture user input about AI-generated content to detect subtle shifts in quality or alignment with community and societal values.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization",
	},
	"MG-2.2-009": {
		"subcategory": "MANAGE 2.2",
		"function": "MANAGE",
		"text": "Consider opportunities to responsibly use synthetic data and other privacy enhancing techniques in GAI development, where appropriate and applicable, match the statistical properties of real-world data without disclosing personally identifiable information or contributing to homogenization.",
		"gai_risks": ["Data Privacy", "Intellectual Property", "Information Integrity", "Confabulation", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Data Privacy; Intellectual Property; Information Integrity; Confabulation; Harmful Bias and Homogenization",
	},
	"MG-2.3-001": {
		"subcategory": "MANAGE 2.3",
		"function": "MANAGE",
		"text": "Develop and update GAI system incident response and recovery plans and procedures to address the following: Review and maintenance of policies and procedures to account for newly encountered uses; Review and maintenance of policies and procedures for detection of unanticipated uses; Verify response and recovery plans account for the GAI system value chain; Verify response and recovery plans are updated for and include necessary details to communicate with downstream GAI system Actors: Points-of-Contact (POC), Contact information, notification format.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"MG-2.4-001": {
		"subcategory": "MANAGE 2.4",
		"function": "MANAGE",
		"text": "Establish and maintain communication plans to inform AI stakeholders as part of the deactivation or disengagement process of a specific GAI system (including for open-source models) or context of use, including reasons, workarounds, user access removal, alternative processes, contact information, etc.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MG-2.4-002": {
		"subcategory": "MANAGE 2.4",
		"function": "MANAGE",
		"text": "Establish and maintain procedures for escalating GAI system incidents to the organizational risk management authority when specific criteria for deactivation or disengagement is met for a particular context of use or for the GAI system as a whole.",
		"gai_risks": ["Information Security"],
	},
	"MG-2.4-003": {
		"subcategory": "MANAGE 2.4",
		"function": "MANAGE",
		"text": "Establish and maintain procedures for the remediation of issues which trigger incident response processes for the use of a GAI system, and provide stakeholders timelines associated with the remediation plan.",
		"gai_risks": ["Information Security"],
	},
	"MG-2.4-004": {
		"subcategory": "MANAGE 2.4",
		"function": "MANAGE",
		"text": "Establish and regularly review specific criteria that warrants the deactivation of GAI systems in accordance with set risk tolerances and appetites.",
		"gai_risks": ["Information Security"],
	},
	"MG-3.1-001": {
		"subcategory": "MANAGE 3.1",
		"function": "MANAGE",
		"text": "Apply organizational risk tolerances and controls (e.g., acquisition and procurement processes; assessing personnel credentials and qualifications, performing background checks; filtering GAI input and outputs, grounding, fine tuning, retrieval-augmented generation) to third-party GAI resources: Apply organizational risk tolerance to the utilization of third-party datasets and other GAI resources; Apply organizational risk tolerances to fine-tuned third-party models; Apply organizational risk tolerance to existing third-party models adapted to a new domain; Reassess risk measurements after fine-tuning third-party GAI models.",
		"gai_risks": ["Value Chain and Component Integration", "Intellectual Property"],
	},
	"MG-3.1-002": {
		"subcategory": "MANAGE 3.1",
		"function": "MANAGE",
		"text": "Test GAI system value chain risks (e.g., data poisoning, malware, other software and hardware vulnerabilities; labor practices; data privacy and localization compliance; geopolitical alignment).",
		"gai_risks": ["Data Privacy", "Information Security", "Value Chain and Component Integration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Data Privacy; Information Security; Value Chain and Component Integration; Harmful Bias and Homogenization",
	},
	"MG-3.1-003": {
		"subcategory": "MANAGE 3.1",
		"function": "MANAGE",
		"text": "Re-assess model risks after fine-tuning or retrieval-augmented generation implementation and for any third-party GAI models deployed for applications and/or use cases that were not evaluated in initial testing.",
		"gai_risks": ["Value Chain and Component Integration"],
	},
	"MG-3.1-004": {
		"subcategory": "MANAGE 3.1",
		"function": "MANAGE",
		"text": "Take reasonable measures to review training data for CBRN information, and intellectual property, and where appropriate, remove it. Implement reasonable measures to prevent, flag, or take other action in response to outputs that reproduce particular training data (e.g., plagiarized, trademarked, patented, licensed content or trade secret material).",
		"gai_risks": ["Intellectual Property", "CBRN Information or Capabilities"],
	},
	"MG-3.1-005": {
		"subcategory": "MANAGE 3.1",
		"function": "MANAGE",
		"text": "Review various transparency artifacts (e.g., system cards and model cards) for third-party models.",
		"gai_risks": ["Information Integrity", "Information Security", "Value Chain and Component Integration"],
	},
	"MG-3.2-001": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Apply explainable AI (XAI) techniques (e.g., analysis of embeddings, model compression/distillation, gradient-based attributions, occlusion/term reduction, counterfactual prompts, word clouds) as part of ongoing continuous improvement processes to mitigate risks related to unexplainable GAI systems.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MG-3.2-002": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Document how pre-trained models have been adapted (e.g., fine-tuned, or retrieval-augmented generation) for the specific generative task, including any data augmentations, parameter adjustments, or other modifications. Access to un-tuned (baseline) models supports debugging the relative influence of the pre-trained weights compared to the fine-tuned model weights or other system updates.",
		"gai_risks": ["Information Integrity", "Data Privacy"],
	},
	"MG-3.2-003": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Document sources and types of training data and their origins, potential biases present in the data related to the GAI application and its content provenance, architecture, training process of the pre-trained model including information on hyperparameters, training duration, and any fine-tuning or retrieval-augmented generation processes applied.",
		"gai_risks": ["Information Integrity", "Harmful Bias or Homogenization", "Intellectual Property"],
		"gai_risks_as_printed": "Information Integrity; Harmful Bias and Homogenization; Intellectual Property",
	},
	"MG-3.2-004": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Evaluate user reported problematic content and integrate feedback into system updates.",
		"gai_risks": ["Human-AI Configuration", "Dangerous, Violent, or Hateful Content"],
		"gai_risks_as_printed": "Human-AI Configuration, Dangerous, Violent, or Hateful Content",
	},
	"MG-3.2-005": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Implement content filters to prevent the generation of inappropriate, harmful, false, illegal, or violent content related to the GAI application, including for CSAM and NCII. These filters can be rule-based or leverage additional machine learning models to flag problematic inputs and outputs.",
		"gai_risks": ["Information Integrity", "Harmful Bias or Homogenization", "Dangerous, Violent, or Hateful Content", "Obscene, Degrading, and/or Abusive Content"],
		"gai_risks_as_printed": "Information Integrity; Harmful Bias and Homogenization; Dangerous, Violent, or Hateful Content; Obscene, Degrading, and/or Abusive Content",
	},
	"MG-3.2-006": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Implement real-time monitoring processes for analyzing generated content performance and trustworthiness characteristics related to content provenance to identify deviations from the desired standards and trigger alerts for human intervention.",
		"gai_risks": ["Information Integrity"],
	},
	"MG-3.2-007": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Leverage feedback and recommendations from organizational boards or committees related to the deployment of GAI applications and content provenance when using third-party pre-trained models.",
		"gai_risks": ["Information Integrity", "Value Chain and Component Integration"],
	},
	"MG-3.2-008": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Use human moderation systems where appropriate to review generated content in accordance with human-AI configuration policies established in the Govern function, aligned with socio-cultural norms in the context of use, and for settings where AI models are demonstrated to perform poorly.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MG-3.2-009": {
		"subcategory": "MANAGE 3.2",
		"function": "MANAGE",
		"text": "Use organizational risk tolerance to evaluate acceptable risks and performance metrics and decommission or retrain pre-trained models that perform outside of defined limits.",
		"gai_risks": ["CBRN Information or Capabilities", "Confabulation"],
	},
	"MG-4.1-001": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Collaborate with external researchers, industry experts, and community representatives to maintain awareness of emerging best practices and technologies in measuring and managing identified risks.",
		"gai_risks": ["Information Integrity", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Information Integrity; Harmful Bias and Homogenization",
	},
	"MG-4.1-002": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Establish, maintain, and evaluate effectiveness of organizational processes and procedures for post-deployment monitoring of GAI systems, particularly for potential confabulation, CBRN, or cyber risks.",
		"gai_risks": ["CBRN Information or Capabilities", "Confabulation", "Information Security"],
	},
	"MG-4.1-003": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Evaluate the use of sentiment analysis to gauge user sentiment regarding GAI content performance and impact, and work in collaboration with AI Actors experienced in user research and experience.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MG-4.1-004": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Implement active learning techniques to identify instances where the model fails or produces unexpected outputs.",
		"gai_risks": ["Confabulation"],
	},
	"MG-4.1-005": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Share transparency reports with internal and external stakeholders that detail steps taken to update the GAI system to enhance transparency and accountability.",
		"gai_risks": ["Human-AI Configuration", "Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Human-AI Configuration; Harmful Bias and Homogenization",
	},
	"MG-4.1-006": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Track dataset modifications for provenance by monitoring data deletions, rectification requests, and other changes that may impact the verifiability of content origins.",
		"gai_risks": ["Information Integrity"],
	},
	"MG-4.1-007": {
		"subcategory": "MANAGE 4.1",
		"function": "MANAGE",
		"text": "Verify that AI Actors responsible for monitoring reported issues can effectively evaluate GAI system performance including the application of content provenance data tracking techniques, and promptly escalate issues for response.",
		"gai_risks": ["Human-AI Configuration", "Information Integrity"],
	},
	"MG-4.2-001": {
		"subcategory": "MANAGE 4.2",
		"function": "MANAGE",
		"text": "Conduct regular monitoring of GAI systems and publish reports detailing the performance, feedback received, and improvements made.",
		"gai_risks": ["Harmful Bias or Homogenization"],
		"gai_risks_as_printed": "Harmful Bias and Homogenization",
	},
	"MG-4.2-002": {
		"subcategory": "MANAGE 4.2",
		"function": "MANAGE",
		"text": "Practice and follow incident response plans for addressing the generation of inappropriate or harmful content and adapt processes based on findings to prevent future occurrences. Conduct post-mortem analyses of incidents with relevant AI Actors, to understand the root causes and implement preventive measures.",
		"gai_risks": ["Human-AI Configuration", "Dangerous, Violent, or Hateful Content"],
	},
	"MG-4.2-003": {
		"subcategory": "MANAGE 4.2",
		"function": "MANAGE",
		"text": "Use visualizations or other methods to represent GAI model behavior to ease non-technical stakeholders understanding of GAI system functionality.",
		"gai_risks": ["Human-AI Configuration"],
	},
	"MG-4.3-001": {
		"subcategory": "MANAGE 4.3",
		"function": "MANAGE",
		"text": "Conduct after-action assessments for GAI system incidents to verify incident response and recovery processes are followed and effective, including to follow procedures for communicating incidents to relevant AI Actors and where applicable, relevant legal and regulatory bodies.",
		"gai_risks": ["Information Security"],
	},
	"MG-4.3-002": {
		"subcategory": "MANAGE 4.3",
		"function": "MANAGE",
		"text": "Establish and maintain policies and procedures to record and track GAI system reported errors, near-misses, and negative impacts.",
		"gai_risks": ["Confabulation", "Information Integrity"],
	},
	"MG-4.3-003": {
		"subcategory": "MANAGE 4.3",
		"function": "MANAGE",
		"text": "Report GAI incidents in compliance with legal and regulatory requirements (e.g., HIPAA breach reporting, e.g., OCR (2023) or NHTSA (2022) autonomous vehicle crash reporting requirements.",
		"gai_risks": ["Information Security", "Data Privacy"],
	},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_ai_600_1", {})

_scope := object.get(_in, "scope", {})

_gate := g if {
	is_object(_scope)
	g := _scope.generative_ai
	is_boolean(g)
}

_declared if _gate == _gate

applicable if _gate == true

not_applicable if _gate == false

_given := a if {
	a := _in.actions
	is_object(a)
}

_supplied if _given

_attested(aid) if _given[aid] == true

_satisfied(aid) if {
	applicable
	_attested(aid)
}

_satisfied_bool(aid) if _satisfied(aid)

else := false

violations contains "NIST AI 600-1: FAIL-CLOSED - scope flag 'input.nist_ai_600_1.scope.generative_ai' was not declared true or false; the Generative AI Profile cannot be scoped and is reported non-compliant" if {
	not _declared
}

violations contains "NIST AI 600-1: FAIL-CLOSED - attestations 'input.nist_ai_600_1.actions' were not supplied (or are not an object) for an organisation in scope for generative AI; reported non-compliant" if {
	applicable
	not _supplied
}

violations contains msg if {
	applicable
	some aid, a in actions
	not _attested(aid)
	msg := sprintf("NIST AI 600-1 %v (%v): suggested action not attested — %v", [aid, a.subcategory, a.text])
}

violations contains msg if {
	some aid, _ in _given
	not actions[aid]
	msg := sprintf("NIST AI 600-1 Input Contract: unknown suggested action id %v — ids are printed as in AI 600-1 Section 3, e.g. GV-1.1-001", [aid])
}

_status := "applicable" if applicable

else := "not_applicable" if not_applicable

else := "undeclared"

function_rollup[f] := r if {
	some f in function_names
	ids := {aid | some aid, a in actions; a.function == f}
	r := {
		"actions_total": count(ids),
		"actions_satisfied": count({aid | some aid in ids; _satisfied(aid)}),
		"not_satisfied": sort([aid | some aid in ids; applicable; not _satisfied(aid)]),
		"subcategories": sort({a.subcategory | some aid in ids; a := actions[aid]}),
	}
}

subcategory_rollup[s] := r if {
	some s in {a.subcategory | some _, a in actions}
	ids := {aid | some aid, a in actions; a.subcategory == s}
	r := {
		"actions_total": count(ids),
		"actions_satisfied": count({aid | some aid in ids; _satisfied(aid)}),
		"not_satisfied": sort([aid | some aid in ids; applicable; not _satisfied(aid)]),
	}
}

risk_rollup[t] := r if {
	some t, k in gai_risks
	ids := {aid | some aid, a in actions; t in a.gai_risks}
	r := {
		"number": k.number,
		"actions_total": count(ids),
		"actions_satisfied": count({aid | some aid in ids; _satisfied(aid)}),
		"not_satisfied": sort([aid | some aid in ids; applicable; not _satisfied(aid)]),
	}
}

# actions whose printed risk tags do not resolve to the 12 Section 2 risks (kept verbatim, not in risk_rollup)
other_tags := {aid: a.other_tags | some aid, a in actions; a.other_tags}

compliance_report := {
	"framework": "NIST AI 600-1 Generative AI Profile",
	"version": "July 2024",
	"source": source,
	"scope": _status,
	"applicable": _status == "applicable",
	"compliant": compliant,
	"total_controls": count(actions),
	"standard_total": 212, # suggested actions in AI 600-1 Section 3
	"actions_satisfied": count({aid | some aid, _ in actions; _satisfied(aid)}),
	"gai_risks_total": count(gai_risks),
	"subcategories_covered": count(subcategory_rollup),
	"functions": function_rollup,
	"subcategories": subcategory_rollup,
	"gai_risks": risk_rollup,
	"other_tags": other_tags,
	"violation_count": count(violations),
	"violations": [v | some v in violations],
}
