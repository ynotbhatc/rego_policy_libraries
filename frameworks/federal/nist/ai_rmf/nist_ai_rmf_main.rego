# NIST AI Risk Management Framework (AI RMF 1.0) — master module: all 72 Core subcategories, decided by facts or
# attestation, plus the NIST AI 600-1 Generative AI Profile (nist.ai_600_1.main) as its own section.
#
# Source of truth: NIST AI 100-1, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)", January 2023,
#   https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
#   sha256 7576edb531d9848825814ee88e28b1795d3a84b435b4b797d3670eafdc4a89f1, retrieved 2026-10-14.
# NIST text is public domain. Ids and texts are copied verbatim from the Core (Section 5, Tables 1-4) by a
# generator reading the PDF's word boxes (pdftotext -bbox), category column and subcategory column separately.
# Typesetting is undone, nothing else: line-break hyphens of the justified table text are removed
# ("inte- grated" -> "integrated"); two line-break hyphens are kept as real compounds (judgement calls):
# "context-specific" (MAP 1.1; the AI 600-1 profile prints "context specific") and "context-relevant" (MEASURE 4.3).
# Curly quotes and apostrophes are kept as printed.
# Cross-check: the 49 subcategory headings reprinted in AI 600-1 agree with these texts except for AI 600-1's own
# edits (GOVERN 1.5 "are planned, and ... are clearly defined"; "AI Actors" capitalised in 9 subcategories; MAP 1.1
# "context specific"; MAP 2.3 no final period; MAP 4.1 "third-party’s"). AI 100-1 is canonical here.
#
# Measured in the Core: 4 functions, 19 categories, 72 subcategories (GOVERN 1.1 ... MANAGE 4.3):
#   GOVERN    6 categories, 19 subcategories (4 facts, 15 attestation)
#   MAP       5 categories, 18 subcategories (2 facts, 16 attestation)
#   MEASURE   4 categories, 22 subcategories (6 facts, 16 attestation)
#   MANAGE    4 categories, 13 subcategories (2 facts, 11 attestation)
#   total    19 categories, 72 subcategories (14 facts, 58 attestation)
# Section 5 gives the functions no one-line statement, so functions are carried by name only.
#
# Id scheme: exactly as the Core prints them, with the space: "GOVERN 1.1", "MAP 5.2", "MEASURE 2.13".
#
# Basis — how each subcategory is decided (reported per subcategory as `basis`):
#   facts         14  by the fact checks of nist.ai_rmf (nist_ai_rmf.rego), which read collector facts under
#                     input.govern, input.map, input.measure, input.manage and input.ai_system. A facts subcategory
#                     is satisfied when nist.ai_rmf emits no violation labelled with its id; every fact fails when
#                     missing or not exactly true, so absence is never a pass.
#   attestation   58  input.nist_ai_rmf.subcategories["GOVERN 1.1"] == true, the assessor's attestation.
# The fact checks predate this catalog; 15 of 37 decide a subcategory, the other 22 are lineage in nist.ai_rmf's
# `legacy` table (merged in the report as `legacy_fact_checks`).
#
# Input contract: input.nist_ai_rmf.subcategories is an object of subcategory id -> true. Fail-closed: a missing or
# non-object container is a FAIL-CLOSED violation; an attestation-basis subcategory whose value is missing, false
# or not exactly true is a violation; an unknown id is a violation. A value supplied for a facts-basis id is
# accepted and ignored: facts decide it.
#
# Generative AI Profile (NIST AI 600-1): evaluated in nist.ai_600_1.main (nist_ai_600_1_main.rego) behind its
# declared scope gate input.nist_ai_600_1.scope.generative_ai. This report carries that module's rollups as
# `generative_ai_profile` and unions its violations once into `violations`; the 212 suggested actions are defined
# there and only there; `total_controls` here is the 72 Core subcategories plus the 212 actions when the profile is
# in scope (core_controls / profile_controls split them), `standard_total` stays 72. `compliant` requires both; a
# profile declared not applicable (generative_ai false) passes.
#
# Query: POST /v1/data/nist/ai_rmf/main/compliance_report (AAC bridge: /v1/data/nist_ai_rmf/main/compliance_report)

# METADATA
# title: "NIST AI RMF 1.0 — 72 Core subcategories (AI 100-1 ids), facts or attestation, with the AI 600-1 GAI profile"
# custom:
#   class: compliance
#   framework: nist_ai_rmf
#   source: nist
#   domains: [us-federal, ai]
#   coverage:
#     checks: 78
#     cited: 72
#     expected: 72
#     found: 300
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.ai_rmf.main

import rego.v1

import data.nist.ai_600_1.main as gai
import data.nist.ai_rmf as facts

source := {
	"publication": "NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0)",
	"date": "January 2023",
	"url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
	"sha256": "7576edb531d9848825814ee88e28b1795d3a84b435b4b797d3670eafdc4a89f1",
	"retrieved": "2026-10-14",
	"tables": "Section 5, Tables 1-4",
}

function_names := ["GOVERN", "MAP", "MEASURE", "MANAGE"]

# categories are rows of an array (the keyed object is built from it below) so that only the 72 subcategories
# read as controls
_category_rows := [
	{"category": "GOVERN 1", "function": "GOVERN", "text": "Policies, processes, procedures, and practices across the organization related to the mapping, measuring, and managing of AI risks are in place, transparent, and implemented effectively."},
	{"category": "GOVERN 2", "function": "GOVERN", "text": "Accountability structures are in place so that the appropriate teams and individuals are empowered, responsible, and trained for mapping, measuring, and managing AI risks."},
	{"category": "GOVERN 3", "function": "GOVERN", "text": "Workforce diversity, equity, inclusion, and accessibility processes are prioritized in the mapping, measuring, and managing of AI risks throughout the lifecycle."},
	{"category": "GOVERN 4", "function": "GOVERN", "text": "Organizational teams are committed to a culture that considers and communicates AI risk."},
	{"category": "GOVERN 5", "function": "GOVERN", "text": "Processes are in place for robust engagement with relevant AI actors."},
	{"category": "GOVERN 6", "function": "GOVERN", "text": "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues."},
	{"category": "MAP 1", "function": "MAP", "text": "Context is established and understood."},
	{"category": "MAP 2", "function": "MAP", "text": "Categorization of the AI system is performed."},
	{"category": "MAP 3", "function": "MAP", "text": "AI capabilities, targeted usage, goals, and expected benefits and costs compared with appropriate benchmarks are understood."},
	{"category": "MAP 4", "function": "MAP", "text": "Risks and benefits are mapped for all components of the AI system including third-party software and data."},
	{"category": "MAP 5", "function": "MAP", "text": "Impacts to individuals, groups, communities, organizations, and society are characterized."},
	{"category": "MEASURE 1", "function": "MEASURE", "text": "Appropriate methods and metrics are identified and applied."},
	{"category": "MEASURE 2", "function": "MEASURE", "text": "AI systems are evaluated for trustworthy characteristics."},
	{"category": "MEASURE 3", "function": "MEASURE", "text": "Mechanisms for tracking identified AI risks over time are in place."},
	{"category": "MEASURE 4", "function": "MEASURE", "text": "Feedback about efficacy of measurement is gathered and assessed."},
	{"category": "MANAGE 1", "function": "MANAGE", "text": "AI risks based on assessments and other analytical output from the MAP and MEASURE functions are prioritized, responded to, and managed."},
	{"category": "MANAGE 2", "function": "MANAGE", "text": "Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, documented, and informed by input from relevant AI actors."},
	{"category": "MANAGE 3", "function": "MANAGE", "text": "AI risks and benefits from third-party entities are managed."},
	{"category": "MANAGE 4", "function": "MANAGE", "text": "Risk treatments, including response and recovery, and communication plans for the identified and measured AI risks are documented and monitored regularly."},
]

categories := {r.category: {"function": r.function, "text": r.text} | some r in _category_rows}

subcategories := {
	"GOVERN 1.1": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "Legal and regulatory requirements involving AI are understood, managed, and documented.",
		"basis": "attestation",
	},
	"GOVERN 1.2": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "The characteristics of trustworthy AI are integrated into organizational policies, processes, procedures, and practices.",
		"basis": "attestation",
	},
	"GOVERN 1.3": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "Processes, procedures, and practices are in place to determine the needed level of risk management activities based on the organization’s risk tolerance.",
		"basis": "attestation",
	},
	"GOVERN 1.4": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
		"basis": "attestation",
	},
	"GOVERN 1.5": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "Ongoing monitoring and periodic review of the risk management process and its outcomes are planned and organizational roles and responsibilities clearly defined, including determining the frequency of periodic review.",
		"basis": "attestation",
	},
	"GOVERN 1.6": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities.",
		"basis": "attestation",
	},
	"GOVERN 1.7": {
		"function": "GOVERN",
		"category": "GOVERN 1",
		"text": "Processes and procedures are in place for decommissioning and phasing out AI systems safely and in a manner that does not increase risks or decrease the organization’s trustworthiness.",
		"basis": "facts",
	},
	"GOVERN 2.1": {
		"function": "GOVERN",
		"category": "GOVERN 2",
		"text": "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization.",
		"basis": "facts",
	},
	"GOVERN 2.2": {
		"function": "GOVERN",
		"category": "GOVERN 2",
		"text": "The organization’s personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedures, and agreements.",
		"basis": "facts",
	},
	"GOVERN 2.3": {
		"function": "GOVERN",
		"category": "GOVERN 2",
		"text": "Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment.",
		"basis": "attestation",
	},
	"GOVERN 3.1": {
		"function": "GOVERN",
		"category": "GOVERN 3",
		"text": "Decision-making related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team (e.g., diversity of demographics, disciplines, experience, expertise, and backgrounds).",
		"basis": "facts",
	},
	"GOVERN 3.2": {
		"function": "GOVERN",
		"category": "GOVERN 3",
		"text": "Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems.",
		"basis": "attestation",
	},
	"GOVERN 4.1": {
		"function": "GOVERN",
		"category": "GOVERN 4",
		"text": "Organizational policies and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimize potential negative impacts.",
		"basis": "attestation",
	},
	"GOVERN 4.2": {
		"function": "GOVERN",
		"category": "GOVERN 4",
		"text": "Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, evaluate, and use, and they communicate about the impacts more broadly.",
		"basis": "attestation",
	},
	"GOVERN 4.3": {
		"function": "GOVERN",
		"category": "GOVERN 4",
		"text": "Organizational practices are in place to enable AI testing, identification of incidents, and information sharing.",
		"basis": "attestation",
	},
	"GOVERN 5.1": {
		"function": "GOVERN",
		"category": "GOVERN 5",
		"text": "Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system regarding the potential individual and societal impacts related to AI risks.",
		"basis": "attestation",
	},
	"GOVERN 5.2": {
		"function": "GOVERN",
		"category": "GOVERN 5",
		"text": "Mechanisms are established to enable the team that developed or deployed AI systems to regularly incorporate adjudicated feedback from relevant AI actors into system design and implementation.",
		"basis": "attestation",
	},
	"GOVERN 6.1": {
		"function": "GOVERN",
		"category": "GOVERN 6",
		"text": "Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third-party’s intellectual property or other rights.",
		"basis": "attestation",
	},
	"GOVERN 6.2": {
		"function": "GOVERN",
		"category": "GOVERN 6",
		"text": "Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk.",
		"basis": "attestation",
	},
	"MAP 1.1": {
		"function": "MAP",
		"category": "MAP 1",
		"text": "Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and documented. Considerations include: the specific set or types of users along with their expectations; potential positive and negative impacts of system uses to individuals, communities, organizations, society, and the planet; assumptions and related limitations about AI system purposes, uses, and risks across the development or product AI lifecycle; and related TEVV and system metrics.",
		"basis": "facts",
	},
	"MAP 1.2": {
		"function": "MAP",
		"category": "MAP 1",
		"text": "Interdisciplinary AI actors, competencies, skills, and capacities for establishing context reflect demographic diversity and broad domain and user experience expertise, and their participation is documented. Opportunities for interdisciplinary collaboration are prioritized.",
		"basis": "attestation",
	},
	"MAP 1.3": {
		"function": "MAP",
		"category": "MAP 1",
		"text": "The organization’s mission and relevant goals for AI technology are understood and documented.",
		"basis": "attestation",
	},
	"MAP 1.4": {
		"function": "MAP",
		"category": "MAP 1",
		"text": "The business value or context of business use has been clearly defined or – in the case of assessing existing AI systems – re-evaluated.",
		"basis": "attestation",
	},
	"MAP 1.5": {
		"function": "MAP",
		"category": "MAP 1",
		"text": "Organizational risk tolerances are determined and documented.",
		"basis": "facts",
	},
	"MAP 1.6": {
		"function": "MAP",
		"category": "MAP 1",
		"text": "System requirements (e.g., “the system shall respect the privacy of its users”) are elicited from and understood by relevant AI actors. Design decisions take socio-technical implications into account to address AI risks.",
		"basis": "attestation",
	},
	"MAP 2.1": {
		"function": "MAP",
		"category": "MAP 2",
		"text": "The specific tasks and methods used to implement the tasks that the AI system will support are defined (e.g., classifiers, generative models, recommenders).",
		"basis": "attestation",
	},
	"MAP 2.2": {
		"function": "MAP",
		"category": "MAP 2",
		"text": "Information about the AI system’s knowledge limits and how system output may be utilized and overseen by humans is documented. Documentation provides sufficient information to assist relevant AI actors when making decisions and taking subsequent actions.",
		"basis": "attestation",
	},
	"MAP 2.3": {
		"function": "MAP",
		"category": "MAP 2",
		"text": "Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection (e.g., availability, representativeness, suitability), system trustworthiness, and construct validation.",
		"basis": "attestation",
	},
	"MAP 3.1": {
		"function": "MAP",
		"category": "MAP 3",
		"text": "Potential benefits of intended AI system functionality and performance are examined and documented.",
		"basis": "attestation",
	},
	"MAP 3.2": {
		"function": "MAP",
		"category": "MAP 3",
		"text": "Potential costs, including non-monetary costs, which result from expected or realized AI errors or system functionality and trustworthiness – as connected to organizational risk tolerance – are examined and documented.",
		"basis": "attestation",
	},
	"MAP 3.3": {
		"function": "MAP",
		"category": "MAP 3",
		"text": "Targeted application scope is specified and documented based on the system’s capability, established context, and AI system categorization.",
		"basis": "attestation",
	},
	"MAP 3.4": {
		"function": "MAP",
		"category": "MAP 3",
		"text": "Processes for operator and practitioner proficiency with AI system performance and trustworthiness – and relevant technical standards and certifications – are defined, assessed, and documented.",
		"basis": "attestation",
	},
	"MAP 3.5": {
		"function": "MAP",
		"category": "MAP 3",
		"text": "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from the GOVERN function.",
		"basis": "attestation",
	},
	"MAP 4.1": {
		"function": "MAP",
		"category": "MAP 4",
		"text": "Approaches for mapping AI technology and legal risks of its components – including the use of third-party data or software – are in place, followed, and documented, as are risks of infringement of a third party’s intellectual property or other rights.",
		"basis": "attestation",
	},
	"MAP 4.2": {
		"function": "MAP",
		"category": "MAP 4",
		"text": "Internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented.",
		"basis": "attestation",
	},
	"MAP 5.1": {
		"function": "MAP",
		"category": "MAP 5",
		"text": "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident reports, feedback from those external to the team that developed or deployed the AI system, or other data are identified and documented.",
		"basis": "attestation",
	},
	"MAP 5.2": {
		"function": "MAP",
		"category": "MAP 5",
		"text": "Practices and personnel for supporting regular engagement with relevant AI actors and integrating feedback about positive, negative, and unanticipated impacts are in place and documented.",
		"basis": "attestation",
	},
	"MEASURE 1.1": {
		"function": "MEASURE",
		"category": "MEASURE 1",
		"text": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are selected for implementation starting with the most significant AI risks. The risks or trustworthiness characteristics that will not – or cannot – be measured are properly documented.",
		"basis": "facts",
	},
	"MEASURE 1.2": {
		"function": "MEASURE",
		"category": "MEASURE 1",
		"text": "Appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated, including reports of errors and potential impacts on affected communities.",
		"basis": "attestation",
	},
	"MEASURE 1.3": {
		"function": "MEASURE",
		"category": "MEASURE 1",
		"text": "Internal experts who did not serve as front-line developers for the system and/or independent assessors are involved in regular assessments and updates. Domain experts, users, AI actors external to the team that developed or deployed the AI system, and affected communities are consulted in support of assessments as necessary per organizational risk tolerance.",
		"basis": "attestation",
	},
	"MEASURE 2.1": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Test sets, metrics, and details about the tools used during TEVV are documented.",
		"basis": "attestation",
	},
	"MEASURE 2.2": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Evaluations involving human subjects meet applicable requirements (including human subject protection) and are representative of the relevant population.",
		"basis": "attestation",
	},
	"MEASURE 2.3": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment setting(s). Measures are documented.",
		"basis": "attestation",
	},
	"MEASURE 2.4": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "The functionality and behavior of the AI system and its components – as identified in the MAP function – are monitored when in production.",
		"basis": "facts",
	},
	"MEASURE 2.5": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are documented.",
		"basis": "attestation",
	},
	"MEASURE 2.6": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "The AI system is evaluated regularly for safety risks – as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not exceed the risk tolerance, and it can fail safely, particularly if made to operate beyond its knowledge limits. Safety metrics reflect system reliability and robustness, real-time monitoring, and response times for AI system failures.",
		"basis": "attestation",
	},
	"MEASURE 2.7": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "AI system security and resilience – as identified in the MAP function – are evaluated and documented.",
		"basis": "attestation",
	},
	"MEASURE 2.8": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Risks associated with transparency and accountability – as identified in the MAP function – are examined and documented.",
		"basis": "attestation",
	},
	"MEASURE 2.9": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "The AI model is explained, validated, and documented, and AI system output is interpreted within its context – as identified in the MAP function – to inform responsible use and governance.",
		"basis": "facts",
	},
	"MEASURE 2.10": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Privacy risk of the AI system – as identified in the MAP function – is examined and documented.",
		"basis": "facts",
	},
	"MEASURE 2.11": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Fairness and bias – as identified in the MAP function – are evaluated and results are documented.",
		"basis": "facts",
	},
	"MEASURE 2.12": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Environmental impact and sustainability of AI model training and management activities – as identified in the MAP function – are assessed and documented.",
		"basis": "attestation",
	},
	"MEASURE 2.13": {
		"function": "MEASURE",
		"category": "MEASURE 2",
		"text": "Effectiveness of the employed TEVV metrics and processes in the MEASURE function are evaluated and documented.",
		"basis": "attestation",
	},
	"MEASURE 3.1": {
		"function": "MEASURE",
		"category": "MEASURE 3",
		"text": "Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual performance in deployed contexts.",
		"basis": "facts",
	},
	"MEASURE 3.2": {
		"function": "MEASURE",
		"category": "MEASURE 3",
		"text": "Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement techniques or where metrics are not yet available.",
		"basis": "attestation",
	},
	"MEASURE 3.3": {
		"function": "MEASURE",
		"category": "MEASURE 3",
		"text": "Feedback processes for end users and impacted communities to report problems and appeal system outcomes are established and integrated into AI system evaluation metrics.",
		"basis": "attestation",
	},
	"MEASURE 4.1": {
		"function": "MEASURE",
		"category": "MEASURE 4",
		"text": "Measurement approaches for identifying AI risks are connected to deployment context(s) and informed through consultation with domain experts and other end users. Approaches are documented.",
		"basis": "attestation",
	},
	"MEASURE 4.2": {
		"function": "MEASURE",
		"category": "MEASURE 4",
		"text": "Measurement results regarding AI system trustworthiness in deployment context(s) and across the AI lifecycle are informed by input from domain experts and relevant AI actors to validate whether the system is performing consistently as intended. Results are documented.",
		"basis": "attestation",
	},
	"MEASURE 4.3": {
		"function": "MEASURE",
		"category": "MEASURE 4",
		"text": "Measurable performance improvements or declines based on consultations with relevant AI actors, including affected communities, and field data about context-relevant risks and trustworthiness characteristics are identified and documented.",
		"basis": "attestation",
	},
	"MANAGE 1.1": {
		"function": "MANAGE",
		"category": "MANAGE 1",
		"text": "A determination is made as to whether the AI system achieves its intended purposes and stated objectives and whether its development or deployment should proceed.",
		"basis": "attestation",
	},
	"MANAGE 1.2": {
		"function": "MANAGE",
		"category": "MANAGE 1",
		"text": "Treatment of documented AI risks is prioritized based on impact, likelihood, and available resources or methods.",
		"basis": "attestation",
	},
	"MANAGE 1.3": {
		"function": "MANAGE",
		"category": "MANAGE 1",
		"text": "Responses to the AI risks deemed high priority, as identified by the MAP function, are developed, planned, and documented. Risk response options can include mitigating, transferring, avoiding, or accepting.",
		"basis": "facts",
	},
	"MANAGE 1.4": {
		"function": "MANAGE",
		"category": "MANAGE 1",
		"text": "Negative residual risks (defined as the sum of all unmitigated risks) to both downstream acquirers of AI systems and end users are documented.",
		"basis": "attestation",
	},
	"MANAGE 2.1": {
		"function": "MANAGE",
		"category": "MANAGE 2",
		"text": "Resources required to manage AI risks are taken into account – along with viable non-AI alternative systems, approaches, or methods – to reduce the magnitude or likelihood of potential impacts.",
		"basis": "attestation",
	},
	"MANAGE 2.2": {
		"function": "MANAGE",
		"category": "MANAGE 2",
		"text": "Mechanisms are in place and applied to sustain the value of deployed AI systems.",
		"basis": "attestation",
	},
	"MANAGE 2.3": {
		"function": "MANAGE",
		"category": "MANAGE 2",
		"text": "Procedures are followed to respond to and recover from a previously unknown risk when it is identified.",
		"basis": "attestation",
	},
	"MANAGE 2.4": {
		"function": "MANAGE",
		"category": "MANAGE 2",
		"text": "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
		"basis": "facts",
	},
	"MANAGE 3.1": {
		"function": "MANAGE",
		"category": "MANAGE 3",
		"text": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented.",
		"basis": "attestation",
	},
	"MANAGE 3.2": {
		"function": "MANAGE",
		"category": "MANAGE 3",
		"text": "Pre-trained models which are used for development are monitored as part of AI system regular monitoring and maintenance.",
		"basis": "attestation",
	},
	"MANAGE 4.1": {
		"function": "MANAGE",
		"category": "MANAGE 4",
		"text": "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, decommissioning, incident response, recovery, and change management.",
		"basis": "attestation",
	},
	"MANAGE 4.2": {
		"function": "MANAGE",
		"category": "MANAGE 4",
		"text": "Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties, including relevant AI actors.",
		"basis": "attestation",
	},
	"MANAGE 4.3": {
		"function": "MANAGE",
		"category": "MANAGE 4",
		"text": "Incidents and errors are communicated to relevant AI actors, including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
		"basis": "attestation",
	},
}

default compliant := false

compliant if count(violations) == 0

default ai_system_name := "unknown"

ai_system_name := input.ai_system.name

default assessed_at := "unknown"

assessed_at := input.assessment_date

_in := object.get(input, "nist_ai_rmf", {})

_given := s if {
	s := _in.subcategories
	is_object(s)
}

_supplied if _given

_attested(sid) if _given[sid] == true

# fact violations of nist.ai_rmf; each is labelled "NIST AI RMF <subcategory id>: ..."
_msg_id(msg) := trim_prefix(split(msg, ":")[0], "NIST AI RMF ")

_fact_failed := {_msg_id(m) | some m in facts.violation}

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

violations contains "NIST AI RMF: FAIL-CLOSED - attestations 'input.nist_ai_rmf.subcategories' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some sid, s in subcategories
	s.basis == "attestation"
	not _attested(sid)
	msg := sprintf("NIST AI RMF %v (%v): not attested satisfied — %v", [sid, s.category, s.text])
}

violations contains msg if {
	some m in facts.violation
	sid := _msg_id(m)
	s := subcategories[sid]
	s.basis == "facts"
	msg := sprintf("NIST AI RMF %v (%v): facts not satisfied — %v", [sid, s.category, m])
}

# a fact violation that names no facts-basis subcategory would otherwise be dropped: report it, fail closed
violations contains msg if {
	some m in facts.violation
	not subcategories[_msg_id(m)].basis == "facts"
	msg := sprintf("NIST AI RMF Module Contract: fact violation not attributed to a facts-basis subcategory — %v", [m])
}

violations contains msg if {
	some sid, _ in _given
	not subcategories[sid]
	msg := sprintf("NIST AI RMF Input Contract: unknown subcategory id %v — ids are printed as in AI 100-1, e.g. GOVERN 1.1", [sid])
}

# the Generative AI Profile's own violations, once (already prefixed "NIST AI 600-1")
violations contains m if {
	some m in gai.violations
}

subcategory_results[sid] := r if {
	some sid, s in subcategories
	r := {
		"function": s.function,
		"category": s.category,
		"text": s.text,
		"basis": s.basis,
		"facts": object.get(facts.facts_for, sid, []),
		"satisfied": _satisfied_bool(sid),
		"fact_violations": sort([m | some m in facts.violation; _msg_id(m) == sid]),
	}
}

category_rollup[c] := r if {
	some c, cat in categories
	ids := {sid | some sid; s := subcategories[sid]; s.category == c}
	r := {
		"function": cat.function,
		"text": cat.text,
		"subcategories_total": count(ids),
		"subcategories_satisfied": count({sid | some sid in ids; _satisfied(sid)}),
		"not_satisfied": sort([sid | some sid in ids; not _satisfied(sid)]),
	}
}

function_rollup[f] := r if {
	some f in function_names
	ids := {sid | some sid; s := subcategories[sid]; s.function == f}
	r := {
		"categories": sort([c | some c; cat := categories[c]; cat.function == f]),
		"subcategories_total": count(ids),
		"subcategories_satisfied": count({sid | some sid in ids; _satisfied(sid)}),
		"not_satisfied": sort([sid | some sid in ids; not _satisfied(sid)]),
		"facts": count({sid | some sid in ids; subcategories[sid].basis == "facts"}),
		"attestation": count({sid | some sid in ids; subcategories[sid].basis == "attestation"}),
		"compliant": count({sid | some sid in ids; not _satisfied(sid)}) == 0,
	}
}

# kept for consumers of the previous report: one entry per function, by name
function_summary[f] := r if {
	some f in function_names
	fr := function_rollup[f]
	r := {
		"violations": count(fr.not_satisfied),
		"compliant": fr.compliant,
		"subcategories_total": fr.subcategories_total,
		"subcategories_satisfied": fr.subcategories_satisfied,
	}
}

# the profile section: rollups and counts only; its violations are in `violations` above, once
generative_ai_profile := object.remove(gai.compliance_report, ["violations"])

# controls evaluated: the 72 Core subcategories, plus the profile's 212 suggested actions when it is in scope (the
# AAC playbook scores passed = total_controls - violation_count, so every evaluated row must be in the total)
_profile_controls := count(gai.actions) if gai.applicable

else := 0

total_controls := count(subcategories) + _profile_controls

compliance_report := {
	"framework": "NIST AI Risk Management Framework (AI RMF)",
	"version": "1.0",
	"published": "2023-01",
	"source": source,
	"ai_system": ai_system_name,
	"assessed_at": assessed_at,
	"compliant": compliant,
	"total_controls": total_controls,
	"standard_total": 72, # subcategories in AI 100-1 Section 5, Tables 1-4
	"core_controls": count(subcategories),
	"profile_controls": _profile_controls,
	"subcategories_satisfied": count({sid | some sid; _ = subcategories[sid]; _satisfied(sid)}),
	"functions_total": count(function_names),
	"categories_total": count(categories),
	"functions": function_rollup,
	"categories": category_rollup,
	"subcategories": subcategory_results,
	"function_summary": function_summary,
	"legacy_fact_checks": facts.legacy,
	"generative_ai_profile": generative_ai_profile,
	"violation_count": count(violations),
	"violations": [v | some v in violations],
}
