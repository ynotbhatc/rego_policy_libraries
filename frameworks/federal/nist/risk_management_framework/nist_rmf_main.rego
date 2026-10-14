# NIST SP 800-37 Rev 2 — Risk Management Framework for Information Systems and Organizations:
# A System Life Cycle Approach for Security and Privacy (December 2018). Every RMF task of Chapter 3,
# all seven steps, one attested row per task.
#
# Source: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf
#   sha256 4f75e1136bb905a654f1bcd9eefefb4108f47597276ee5eec0688f6d96f6a01d, document date December 2018,
#   retrieved 2026-10-14. NIST text is public domain. Read with `pdftotext -layout`; every id, title, task
#   statement, expected output, primary-responsibility role and References line below is copied from
#   Chapter 3 (pages 28-83) by a generator; nothing is paraphrased. `outcomes` and `csf` are copied from the
#   Outcomes column of Tables 1-8 (the "[Cybersecurity Framework: ...]" brackets, CSF 1.1 constructs as
#   printed, including "Profile" and "Implementation Tiers").
#
# Tasks per step (47; the Chapter 3 ids exactly as printed):
#   Prepare — organization level (Table 1)      7 tasks  P-1..P-7
#   Prepare — system level (Table 2)           11 tasks  P-8..P-18
#   Categorize (Table 3)                        3 tasks  C-1..C-3
#   Select (Table 4)                            6 tasks  S-1..S-6
#   Implement (Table 5)                         2 tasks  I-1..I-2
#   Assess (Table 6)                            6 tasks  A-1..A-6
#   Authorize (Table 7)                         5 tasks  R-1..R-5
#   Monitor (Table 8)                           7 tasks  M-1..M-7
#
# Fields carried per task (strings and lists only): step, title (the heading printed above the task),
# text (the task statement), expected_outputs, primary_responsibility, references (the task's References
# line verbatim), outcomes and csf (Tables 1-8), sp800_53_controls, gate.
#   * SP 800-37 Rev 2 References lines cite publications only ("[SP 800-53]", "[NIST CSF] (Core [Identify
#     Function])"); no task names individual SP 800-53 controls or CSF subcategories there. sp800_53_controls
#     is therefore empty for every task (nothing inferred); CSF subcategories come from Tables 1-8 instead.
#   * Potential Inputs are not carried (most run to several lines).
#
# Folded legacy module: the CATEGORIZE checks of nist.rmf.categorize (categorize/system_categorization.rego,
# 12 fact rules over input.system_categorization) are folded into C-1..C-3; `legacy` maps each rule name to
# its task. That package keeps every rule name for its consumers and is no longer counted separately.
# Rule for C-1..C-3: attestation is always required; when input.system_categorization is supplied (an
# object), every legacy fact rule mapped to the task must also hold, else a violation names the rule.
#
# Judgement calls:
#   * P-4 and P-6 are printed "(Optional)". They are gated: input.nist_rmf.<gate> must be declared true or
#     false (uses_tailored_baselines_or_profiles for P-4, prioritizes_systems_within_impact_level for P-6);
#     false makes the task not applicable, undeclared or non-boolean is a violation. M-7 (system disposal,
#     SDLC "New – Not Applicable") is not gated.
#   * Primary responsibility follows the Chapter 3 task text. Appendix E differs in two places: C-3 adds
#     "(for systems processing PII)" to Senior Agency Official for Privacy, and R-1 omits Senior Agency
#     Official for Privacy (Chapter 3 lists it with a footnote). Supporting roles printed inline after the
#     primary role ("Supporting Role: ...", P-12 and P-18) are not carried as primary.
#   * P-6 expected output: the line break "sub-" + "categories" is rendered "sub-categories".
#   * Footnote markers printed after outputs/roles (e.g. "tool 94", "Officer. 66") are dropped.
#   * Legacy mapping: system_boundary_defined and external_dependencies_identified -> C-1 (system
#     description; the boundary itself is determined in P-11); the C/I/A, overall, high-water-mark,
#     information_types_identified and provisional_authorization_considered rules -> C-2 (no C task names
#     provisional authorization; it is part of the categorization record here); categorization documentation,
#     system owner approval and SAISO review -> C-3.
# Could not read: nothing.
#
# Input: input.nist_rmf.tasks["P-1"] == true attests the task performed. Fail-closed: a missing or non-object
# tasks container is a FAIL-CLOSED violation; a missing, false or non-true value, an unknown id and an
# undeclared gate are violations.
#
# Query: POST /v1/data/nist/rmf/main/compliance_report

# METADATA
# title: "NIST SP 800-37 Rev 2 Risk Management Framework — 47 Chapter 3 tasks, all seven steps, attested"
# custom:
#   class: compliance
#   framework: nist_risk_management_framework
#   source: nist
#   domains: [us-federal, it-governance]
#   coverage:
#     checks: 52
#     cited: 49
#     expected: 47
#     found: 49
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nist.rmf.main

import rego.v1

source := {
	"publication": "NIST SP 800-37 Rev 2",
	"date": "December 2018",
	"url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf",
	"sha256": "4f75e1136bb905a654f1bcd9eefefb4108f47597276ee5eec0688f6d96f6a01d",
	"retrieved": "2026-10-14",
}

sections := {
	"prepare-organization": "Prepare — organization level (Table 1)",
	"prepare-system": "Prepare — system level (Table 2)",
	"categorize": "Categorize (Table 3)",
	"select": "Select (Table 4)",
	"implement": "Implement (Table 5)",
	"assess": "Assess (Table 6)",
	"authorize": "Authorize (Table 7)",
	"monitor": "Monitor (Table 8)",
}

_gates := {
	"uses_tailored_baselines_or_profiles": "RMF P-4 (Optional) — whether the organization establishes organizationally-tailored control baselines and/or Cybersecurity Framework Profiles must be declared true or false",
	"prioritizes_systems_within_impact_level": "RMF P-6 (Optional) — whether the organization prioritizes organizational systems with the same impact level must be declared true or false",
}

# nist.rmf.categorize rule name -> the RMF task it is folded into
legacy := {
	"system_boundary_defined": "C-1",
	"external_dependencies_identified": "C-1",
	"confidentiality_properly_categorized": "C-2",
	"integrity_properly_categorized": "C-2",
	"availability_properly_categorized": "C-2",
	"overall_system_categorization_valid": "C-2",
	"high_water_mark_properly_applied": "C-2",
	"information_types_identified": "C-2",
	"provisional_authorization_considered": "C-2",
	"categorization_documentation_complete": "C-3",
	"system_owner_responsibilities_met": "C-3",
	"saiso_review_completed": "C-3",
}

tasks := {
	# ── Prepare — organization level (Table 1): 7 tasks ────────────────────
	"P-1": {
		"step": "prepare-organization",
		"title": "RISK MANAGEMENT ROLES",
		"text": "Identify and assign individuals to specific roles associated with security and privacy risk management.",
		"expected_outputs": "Documented Risk Management Framework role assignments.",
		"primary_responsibility": ["Head of Agency", "Chief Information Officer", "Senior Agency Official for Privacy"],
		"references": "[SP 800-160 v1] (Human Resource Management Process); [SP 800-181]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["Individuals are identified and assigned key roles for executing the Risk Management Framework."],
		"csf": ["ID.AM-6", "ID.GV-2"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-2": {
		"step": "prepare-organization",
		"title": "RISK MANAGEMENT STRATEGY",
		"text": "Establish a risk management strategy for the organization that includes a determination of risk tolerance.",
		"expected_outputs": "Risk management strategy and statement of risk tolerance inclusive of information security and privacy risk.",
		"primary_responsibility": ["Head of Agency"],
		"references": "[SP 800-30]; [SP 800-39] (Organization Level); [SP 800-160 v1] (Risk Management, Decision Management, Quality Assurance, Quality Management, Project Assessment and Control Processes); [SP 800-161]; [IR 8062]; [IR 8179] (Criticality Analysis Process B); [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["A risk management strategy for the organization that includes a determination and expression of organizational risk tolerance is established."],
		"csf": ["ID.RM", "ID.SC"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-3": {
		"step": "prepare-organization",
		"title": "RISK ASSESSMENT—ORGANIZATION",
		"text": "Assess organization-wide security and privacy risk and update the risk assessment results on an ongoing basis.",
		"expected_outputs": "Organization-level risk assessment results.",
		"primary_responsibility": ["Senior Accountable Official for Risk Management or Risk Executive (Function)", "Senior Agency Information Security Officer", "Senior Agency Official for Privacy"],
		"references": "[SP 800-30]; [SP 800-39] (Organization Level, Mission/Business Process Level); [SP 800-161]; [IR 8062].",
		"outcomes": ["An organization-wide risk assessment is completed or an existing risk assessment is updated."],
		"csf": ["ID.RA", "ID.SC-2"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-4": {
		"step": "prepare-organization",
		"title": "ORGANIZATIONALLY-TAILORED CONTROL BASELINES AND CYBERSECURITY FRAMEWORK PROFILES (Optional)",
		"text": "Establish, document, and publish organizationally-tailored control baselines and/or Cybersecurity Framework Profiles.",
		"expected_outputs": "List of approved or directed organizationally-tailored control baselines; [NIST CSF] Profiles.",
		"primary_responsibility": ["Mission or Business Owner", "Senior Accountable Official for Risk Management or Risk Executive (Function)"],
		"references": "[SP 800-53]; [SP 800-53B]; [SP 800-160 v1] (Business or Mission Analysis and Stakeholder Needs and Requirements Definition Processes); [NIST CSF] (Core, Profiles).",
		"outcomes": ["Organizationally-tailored control baselines and/or Cybersecurity Framework Profiles are established and made available."],
		"csf": ["Profile"],
		"sp800_53_controls": [],
		"gate": "uses_tailored_baselines_or_profiles",
	},
	"P-5": {
		"step": "prepare-organization",
		"title": "COMMON CONTROL IDENTIFICATION",
		"text": "Identify, document, and publish organization-wide common controls that are available for inheritance by organizational systems.",
		"expected_outputs": "List of common control providers and common controls available for inheritance; security and privacy plans (or equivalent documents) providing a description of the common control implementation (including inputs, expected behavior, and expected outputs).",
		"primary_responsibility": ["Senior Agency Information Security Officer", "Senior Agency Official for Privacy"],
		"references": "[SP 800-53].",
		"outcomes": ["Common controls that are available for inheritance by organizational systems are identified, documented, and published."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-6": {
		"step": "prepare-organization",
		"title": "IMPACT-LEVEL PRIORITIZATION (Optional)",
		"text": "Prioritize organizational systems with the same impact level.",
		"expected_outputs": "Organizational systems prioritized into low-, moderate-, and high-impact sub-categories.",
		"primary_responsibility": ["Senior Accountable Official for Risk Management or Risk Executive (Function)"],
		"references": "[FIPS 199]; [FIPS 200]; [SP 800-30]; [SP 800-39] (Organization and System Levels); [SP 800-59]; [SP 800-60 v1]; [SP 800-60 v2]; [SP 800-160 v1] (System Requirements Definition Process); [IR 8179] (Criticality Analysis Process B); [CNSSI 1253]; [NIST CSF] (Core [Identify Function]; Profiles).",
		"outcomes": ["A prioritization of organizational systems with the same impact level is conducted."],
		"csf": ["ID.AM-5"],
		"sp800_53_controls": [],
		"gate": "prioritizes_systems_within_impact_level",
	},
	"P-7": {
		"step": "prepare-organization",
		"title": "CONTINUOUS MONITORING STRATEGY—ORGANIZATION",
		"text": "Develop and implement an organization-wide strategy for continuously monitoring control effectiveness.",
		"expected_outputs": "An implemented organizational continuous monitoring strategy.",
		"primary_responsibility": ["Senior Accountable Official for Risk Management or Risk Executive (Function)"],
		"references": "[SP 800-30]; [SP 800-39] (Organization, Mission or Business Process, System Levels); [SP 800-53]; [SP 800-53A]; [SP 800-137]; [SP 800-161]; [IR 8011 v1]; [IR 8062]; [NIST CSF] (Core [Identify, Detect Functions]); [CNSSI 1253].",
		"outcomes": ["An organization-wide strategy for monitoring control effectiveness is developed and implemented."],
		"csf": ["DE.CM", "ID.SC-4"],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Prepare — system level (Table 2): 11 tasks ────────────────────
	"P-8": {
		"step": "prepare-system",
		"title": "MISSION OR BUSINESS FOCUS",
		"text": "Identify the missions, business functions, and mission/business processes that the system is intended to support.",
		"expected_outputs": "Missions, business functions, and mission/business processes that the system will support.",
		"primary_responsibility": ["Mission or Business Owner"],
		"references": "[SP 800-39] (Organization and Mission/Business Process Levels); [SP 800-64]; [SP 800-160 v1] (Business or Mission Analysis, Portfolio Management, and Project Planning Processes); [NIST CSF] (Core [Identify Function]); [IR 8179] (Criticality Analysis Process B).",
		"outcomes": ["Missions, business functions, and mission/business processes that the system is intended to support are identified."],
		"csf": ["Profile", "Implementation Tiers", "ID.BE"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-9": {
		"step": "prepare-system",
		"title": "SYSTEM STAKEHOLDERS",
		"text": "Identify stakeholders who have an interest in the design, development, implementation, assessment, operation, maintenance, or disposal of the system.",
		"expected_outputs": "List of system stakeholders.",
		"primary_responsibility": ["Mission or Business Owner", "System Owner"],
		"references": "[SP 800-39] (Organization Level); [SP 800-64]; [SP 800-160 v1] (Stakeholder Needs and Requirements Definition and Portfolio Management Processes); [SP 800-161]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["The stakeholders having an interest in the system are identified."],
		"csf": ["ID.AM", "ID.BE"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-10": {
		"step": "prepare-system",
		"title": "ASSET IDENTIFICATION",
		"text": "Identify assets that require protection.",
		"expected_outputs": "Set of assets to be protected.",
		"primary_responsibility": ["System Owner"],
		"references": "[SP 800-39] (Organization Level); [SP 800-64]; [SP 800-160 v1] (Stakeholder Needs and Requirements Definition Process); [IR 8179] (Criticality Analysis Process C); [NIST CSF] (Core [Identify Function]); [NARA CUI].",
		"outcomes": ["Stakeholder assets are identified and prioritized."],
		"csf": ["ID.AM"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-11": {
		"step": "prepare-system",
		"title": "AUTHORIZATION BOUNDARY",
		"text": "Determine the authorization boundary of the system.",
		"expected_outputs": "Documented authorization boundary.",
		"primary_responsibility": ["Authorizing Official"],
		"references": "[SP 800-18]; [SP 800-39] (System Level); [SP 800-47]; [SP 800-64]; [SP 800-160 v1] (System Requirements Definition Process); [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["The authorization boundary (i.e., system) is determined."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-12": {
		"step": "prepare-system",
		"title": "INFORMATION TYPES",
		"text": "Identify the types of information to be processed, stored, and transmitted by the system.",
		"expected_outputs": "A list of information types for the system.",
		"primary_responsibility": ["System Owner", "Information Owner or Steward"],
		"references": "[OMB A-130]; [NARA CUI]; [SP 800-39] (System Level); [SP 800-60 v1]; [SP 800-60 v2]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["The types of information processed, stored, and transmitted by the system are identified."],
		"csf": ["ID.AM-5"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-13": {
		"step": "prepare-system",
		"title": "INFORMATION LIFE CYCLE",
		"text": "Identify and understand all stages of the information life cycle for each information type processed, stored, or transmitted by the system.",
		"expected_outputs": "Documentation of the stages through which information passes in the system, such as a data map or model illustrating how information is structured or is processed by the system throughout its life cycle. Such documentation includes, for example, data flow diagrams, entity relationship diagrams, database schemas, and data dictionaries.",
		"primary_responsibility": ["Senior Agency Official for Privacy", "System Owner", "Information Owner or Steward"],
		"references": "[OMB A-130]; [OMB M-13-13]; [NARA RECM]; [NIST CSF] (Core [Identify Function]); [IR 8062].",
		"outcomes": ["All stages of the information life cycle are identified and understood for each information type processed, stored, or transmitted by the system."],
		"csf": ["ID.AM-3", "ID.AM-4"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-14": {
		"step": "prepare-system",
		"title": "RISK ASSESSMENT—SYSTEM",
		"text": "Conduct a system-level risk assessment and update the risk assessment results on an ongoing basis.",
		"expected_outputs": "Security and privacy risk assessment reports.",
		"primary_responsibility": ["System Owner", "System Security Officer", "System Privacy Officer"],
		"references": "[FIPS 199]; [FIPS 200]; [SP 800-30]; [SP 800-39] (Organization Level); [SP 800-59]; [SP 800-60 v1]; [SP 800-60 v2]; [SP 800-64]; [SP 800-160 v1] (Stakeholder Needs and Requirements Definition and Risk Management Processes); [SP 800-161] (Assess); [IR 8062]; [IR 8179]; [NIST CSF] (Core [Identify Function]); [CNSSI 1253].",
		"outcomes": ["A system-level risk assessment is completed or an existing risk assessment is updated."],
		"csf": ["ID.RA", "ID.SC-2"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-15": {
		"step": "prepare-system",
		"title": "REQUIREMENTS DEFINITION",
		"text": "Define the security and privacy requirements for the system and the environment of operation.",
		"expected_outputs": "Documented security and privacy requirements.",
		"primary_responsibility": ["Mission or Business Owner", "System Owner", "Information Owner or Steward", "System Privacy Officer"],
		"references": "[SP 800-39] (Organization Level); [SP 800-64]; [SP 800-160 v1] (Stakeholder Needs and Requirements Definition Process); [SP 800-161] (Multi-Tiered Risk Management); [IR 8179]; [NIST CSF] (Core [Protect, Detect, Respond, Recover Functions]; Profiles).",
		"outcomes": ["Security and privacy requirements are defined and prioritized."],
		"csf": ["ID.GV", "PR.IP"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-16": {
		"step": "prepare-system",
		"title": "ENTERPRISE ARCHITECTURE",
		"text": "Determine the placement of the system within the enterprise architecture.",
		"expected_outputs": "Updated enterprise architecture; updated security architecture; updated privacy architecture; plans to use cloud-based systems and shared systems, services, or applications.",
		"primary_responsibility": ["Mission or Business Owner", "Enterprise Architect", "Security Architect", "Privacy Architect"],
		"references": "[SP 800-39] (Mission/Business Process Level); [SP 800-64]; [SP 800-160 v1] (System Requirements Definition Process); [NIST CSF] (Core [Identify Function]; Profiles); [OMB FEA].",
		"outcomes": ["The placement of the system within the enterprise architecture is determined."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-17": {
		"step": "prepare-system",
		"title": "REQUIREMENTS ALLOCATION",
		"text": "Allocate security and privacy requirements to the system and to the environment of operation.",
		"expected_outputs": "List of security and privacy requirements allocated to the system, system elements, and the environment of operation.",
		"primary_responsibility": ["Security Architect", "Privacy Architect", "System Security Officer", "System Privacy Officer"],
		"references": "[SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-64]; [SP 800-160 v1] (System Requirements Definition Process); [NIST CSF] (Core [Identify Function]; Profiles); [OMB FEA].",
		"outcomes": ["Security and privacy requirements are allocated to the system and to the environment in which the system operates."],
		"csf": ["ID.GV"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"P-18": {
		"step": "prepare-system",
		"title": "SYSTEM REGISTRATION",
		"text": "Register the system with organizational program or management offices.",
		"expected_outputs": "Registered system in accordance with organizational policy.",
		"primary_responsibility": ["System Owner"],
		"references": "None.",
		"outcomes": ["The system is registered for purposes of management, accountability, coordination, and oversight."],
		"csf": ["ID.GV"],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Categorize (Table 3): 3 tasks ────────────────────
	"C-1": {
		"step": "categorize",
		"title": "SYSTEM DESCRIPTION",
		"text": "Document the characteristics of the system.",
		"expected_outputs": "Documented system description.",
		"primary_responsibility": ["System Owner"],
		"references": "[SP 800-18]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["The characteristics of the system are described and documented."],
		"csf": ["Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"C-2": {
		"step": "categorize",
		"title": "SECURITY CATEGORIZATION",
		"text": "Categorize the system and document the security categorization results.",
		"expected_outputs": "Impact levels determined for each information type and for each security objective (confidentiality, integrity, availability); security categorization based on high-water mark of information type impact levels.",
		"primary_responsibility": ["System Owner", "Information Owner or Steward"],
		"references": "[FIPS 199]; [FIPS 200]; [SP 800-30]; [SP 800-39] (System Level); [SP 800-59]; [SP 800-60 v1]; [SP 800-60 v2]; [SP 800-160 v1] (Stakeholder Needs and Requirements Definition and System Requirements Definition Processes); [IR 8179]; [CNSSI 1253]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["A security categorization of the system, including the information processed by the system represented by the organization-identified information types, is completed.", "Security categorization results are documented in the security, privacy, and SCRM plans.", "Security categorization results are consistent with the enterprise architecture and commitment to protecting organizational missions, business functions, and mission/business processes.", "Security categorization results reflect the organization’s risk management strategy."],
		"csf": ["ID.AM-1", "ID.AM-2", "ID.AM-3", "ID.AM-4", "ID.AM-5", "Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"C-3": {
		"step": "categorize",
		"title": "SECURITY CATEGORIZATION REVIEW AND APPROVAL",
		"text": "Review and approve the security categorization results and decision.",
		"expected_outputs": "Approval of security categorization for the system.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative", "Senior Agency Official for Privacy"],
		"references": "[FIPS 199]; [SP 800-30]; [SP 800-39] (Organization Level); [SP 800-160 v1] (Stakeholder Needs and Requirements Definition Process); [CNSSI 1253]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["The security categorization results are reviewed and the categorization decision is approved by senior leaders in the organization."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Select (Table 4): 6 tasks ────────────────────
	"S-1": {
		"step": "select",
		"title": "CONTROL SELECTION",
		"text": "Select the controls for the system and the environment of operation.",
		"expected_outputs": "Controls selected for the system and the environment of operation.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[FIPS 199]; [FIPS 200]; [SP 800-30]; [SP 800-53]; [SP 800-53B]; [SP 800-160 v1] (System Requirements Definition, Architecture Definition, and Design Definition Processes); [SP 800-161] (Respond and Chapter 3); [IR 8062]; [IR 8179]; [CNSSI 1253]; [NIST CSF] (Core [Identify, Protect, Detect, Respond, Recover Functions]; Profiles).",
		"outcomes": ["Control baselines necessary to protect the system commensurate with risk are selected."],
		"csf": ["Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"S-2": {
		"step": "select",
		"title": "CONTROL TAILORING",
		"text": "Tailor the controls selected for the system and the environment of operation.",
		"expected_outputs": "List of tailored controls for the system and environment of operation (i.e., tailored control baselines).",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[FIPS 199]; [FIPS 200]; [SP 800-30]; [SP 800-53]; [SP 800-53B]; [SP 800-160 v1] (System Requirements Definition, Architecture Definition, and Design Definition Processes); [SP 800-161] (Respond and Chapter 3); [IR 8179]; [CNSSI 1253]; [NIST CSF] (Core [Identify, Protect, Detect, Respond, Recover Functions]; Profiles).",
		"outcomes": ["Controls are tailored producing tailored control baselines."],
		"csf": ["Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"S-3": {
		"step": "select",
		"title": "CONTROL ALLOCATION",
		"text": "Allocate security and privacy controls to the system and to the environment of operation.",
		"expected_outputs": "List of security and privacy controls allocated to the system, system elements, and the environment of operation.",
		"primary_responsibility": ["Security Architect", "Privacy Architect", "System Security Officer", "System Privacy Officer"],
		"references": "[SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-64]; [SP 800-160 v1] (System Requirements Definition, Architecture Definition, and Design Definition Processes); [NIST CSF] (Core [Identify Function]; Profiles); [OMB FEA].",
		"outcomes": ["Controls are designated as system-specific, hybrid, or common controls.", "Controls are allocated to the specific system elements (i.e., machine, physical, or human elements)."],
		"csf": ["Profile", "PR.IP"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"S-4": {
		"step": "select",
		"title": "DOCUMENTATION OF PLANNED CONTROL IMPLEMENTATIONS",
		"text": "Document the controls for the system and environment of operation in security and privacy plans.",
		"expected_outputs": "Security and privacy plans for the system.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[FIPS 199]; [FIPS 200]; [SP 800-18]; [SP 800-30]; [SP 800-53]; [SP 800-64]; [SP 800-160 v1] (System Requirements Definition, Architecture Definition, and Design Definition Processes); [SP 800-161] (Respond and Chapter 3); [IR 8179]; [CNSSI 1253]; [NIST CSF] (Core [Identify, Protect, Detect, Respond, Recover Functions]; Profiles).",
		"outcomes": ["Controls and associated tailoring actions are documented in security and privacy plans or equivalent documents."],
		"csf": ["Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"S-5": {
		"step": "select",
		"title": "CONTINUOUS MONITORING STRATEGY—SYSTEM",
		"text": "Develop and implement a system-level strategy for monitoring control effectiveness that is consistent with and supplements the organizational continuous monitoring strategy.",
		"expected_outputs": "Continuous monitoring strategy for the system including time-based trigger for ongoing authorization.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[SP 800-30]; [SP 800-39] (Organization, Mission or Business Process, System Levels); [SP 800-53]; [SP 800-53A]; [SP 800-137]; [SP 800-161]; [IR 8011 v1]; [CNSSI 1253]; [NIST CSF] (Core [Detect Function]).",
		"outcomes": ["A continuous monitoring strategy for the system that reflects the organizational risk management strategy is developed."],
		"csf": ["ID.GV", "DE.CM"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"S-6": {
		"step": "select",
		"title": "PLAN REVIEW AND APPROVAL",
		"text": "Review and approve the security and privacy plans for the system and the environment of operation.",
		"expected_outputs": "Security and privacy plans approved by the authorizing official.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative"],
		"references": "[SP 800-30]; [SP 800-53]; [SP 800-160 v1] (System Requirements Definition, Architecture Definition, and Design Definition Processes).",
		"outcomes": ["Security and privacy plans reflecting the selection of controls necessary to protect the system and the environment of operation commensurate with risk are reviewed and approved by the authorizing official."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Implement (Table 5): 2 tasks ────────────────────
	"I-1": {
		"step": "implement",
		"title": "CONTROL IMPLEMENTATION",
		"text": "Implement the controls in the security and privacy plans.",
		"expected_outputs": "Implemented controls.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[FIPS 200]; [SP 800-30]; [SP 800-53]; [SP 800-53A]; [SP 800-160 v1] (Implementation, Integration, Verification, and Transition Processes); [SP 800-161]; [IR 8062]; [IR 8179].",
		"outcomes": ["Controls specified in the security and privacy plans are implemented.", "Systems security and privacy engineering methodologies are used to implement the controls in the system security and privacy plans."],
		"csf": ["PR.IP-1", "PR.IP-2"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"I-2": {
		"step": "implement",
		"title": "UPDATE CONTROL IMPLEMENTATION INFORMATION",
		"text": "Document changes to planned control implementations based on the “as-implemented” state of controls.",
		"expected_outputs": "Security and privacy plans updated with implementation detail sufficient for use by assessors; system configuration baseline.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[SP 800-53]; [SP 800-128]; [SP 800-160 v1] (Implementation, Integration, Verification, and Transition, Configuration Management Processes).",
		"outcomes": ["Changes to the planned implementation of controls are documented.", "The security and privacy plans are updated based on information obtained during the implementation of the controls."],
		"csf": ["PR.IP-1", "Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Assess (Table 6): 6 tasks ────────────────────
	"A-1": {
		"step": "assess",
		"title": "ASSESSOR SELECTION",
		"text": "Select the appropriate assessor or assessment team for the type of control assessment to be conducted.",
		"expected_outputs": "Selection of assessor or assessment team responsible for conducting the control assessment.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative"],
		"references": "[FIPS 199]; [SP 800-30]; [SP 800-53A]; [SP 800-55].",
		"outcomes": ["An assessor or assessment team is selected to conduct the control assessments.", "The appropriate level of independence is achieved for the assessor or assessment team selected."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"A-2": {
		"step": "assess",
		"title": "ASSESSMENT PLAN",
		"text": "Develop, review, and approve plans to assess implemented controls.",
		"expected_outputs": "Security and privacy assessment plans approved by the authorizing official.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative", "Control Assessor"],
		"references": "[SP 800-53A]; [SP 800-160 v1] (Verification and Validation Processes); [SP 800-161]; [IR 8011 v1].",
		"outcomes": ["Documentation needed to conduct the assessments is provided to the assessor or assessment team.", "Security and privacy assessment plans are developed and documented.", "Security and privacy assessment plans are reviewed and approved to establish the expectations for the control assessments and the level of effort required."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"A-3": {
		"step": "assess",
		"title": "CONTROL ASSESSMENTS",
		"text": "Assess the controls in accordance with the assessment procedures described in assessment plans.",
		"expected_outputs": "Completed control assessments and associated assessment evidence.",
		"primary_responsibility": ["Control Assessor"],
		"references": "[SP 800-53A]; [SP 800-160 v1] (Verification and Validation Processes); [IR 8011 v1].",
		"outcomes": ["Control assessments are conducted in accordance with the security and privacy assessment plans.", "Opportunities to reuse assessment results from previous assessments to make the risk management process timely and cost-effective are considered.", "Use of automation to conduct control assessments is maximized to increase speed, effectiveness, and efficiency of assessments."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"A-4": {
		"step": "assess",
		"title": "ASSESSMENT REPORTS",
		"text": "Prepare the assessment reports documenting the findings and recommendations from the control assessments.",
		"expected_outputs": "Completed security and privacy assessment reports detailing the assessor findings and recommendations.",
		"primary_responsibility": ["Control Assessor"],
		"references": "[SP 800-53A]; [SP 800-160 v1] (Verification and Validation Processes).",
		"outcomes": ["Security and privacy assessment reports that provide findings and recommendations are completed."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"A-5": {
		"step": "assess",
		"title": "REMEDIATION ACTIONS",
		"text": "Conduct initial remediation actions on the controls and reassess remediated controls.",
		"expected_outputs": "Completed initial remediation actions based on the security and privacy assessment reports; changes to implementations reassessed by the assessment team; updated security and privacy assessment reports; updated security and privacy plans including changes to the control implementations.",
		"primary_responsibility": ["System Owner", "Common Control Provider", "Control Assessor"],
		"references": "[SP 800-53A]; [SP 800-160 v1] (Verification and Validation Processes).",
		"outcomes": ["Remediation actions to address deficiencies in the controls implemented in the system and environment of operation are taken.", "Security and privacy plans are updated to reflect control implementation changes made based on the assessments and subsequent remediation actions."],
		"csf": ["Profile"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"A-6": {
		"step": "assess",
		"title": "PLAN OF ACTION AND MILESTONES",
		"text": "Prepare the plan of action and milestones based on the findings and recommendations of the assessment reports.",
		"expected_outputs": "A plan of action and milestones detailing the findings from the security and privacy assessment reports that are to be remediated.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[SP 800-30]; [SP 800-53A]; [SP 800-160 v1] (Verification and Validation Processes); [IR 8062].",
		"outcomes": ["A plan of action and milestones detailing remediation plans for unacceptable risks identified in security and privacy assessment reports is developed."],
		"csf": ["ID.RA-6"],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Authorize (Table 7): 5 tasks ────────────────────
	"R-1": {
		"step": "authorize",
		"title": "AUTHORIZATION PACKAGE",
		"text": "Assemble the authorization package and submit the package to the authorizing official for an authorization decision.",
		"expected_outputs": "Authorization package (with an executive summary), which may be generated from a security or privacy management tool for submission to the authorizing official.",
		"primary_responsibility": ["System Owner", "Common Control Provider", "Senior Agency Official for Privacy"],
		"references": "[OMB A-130]; [SP 800-18]; [SP 800-160 v1] (Risk Management Process); [SP 800-161] (SCRM Plans).",
		"outcomes": ["An authorization package is developed for submission to the authorizing official."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"R-2": {
		"step": "authorize",
		"title": "RISK ANALYSIS AND DETERMINATION",
		"text": "Analyze and determine the risk from the operation or use of the system or the provision of common controls.",
		"expected_outputs": "Risk determination.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative"],
		"references": "[OMB A-130]; [SP 800-30]; [SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-137]; [SP 800-160 v1] (Risk Management Process); [IR 8062].",
		"outcomes": ["A risk determination by the authorizing official that reflects the risk management strategy including risk tolerance, is rendered."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"R-3": {
		"step": "authorize",
		"title": "RISK RESPONSE",
		"text": "Identify and implement a preferred course of action in response to the risk determined.",
		"expected_outputs": "Risk responses for determined risks.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative"],
		"references": "[SP 800-30]; [SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-160 v1] (Risk Management Process); [IR 8062]; [IR 8179]; [NIST CSF] (Core [Identify Function]).",
		"outcomes": ["Risk responses for determined risks are provided."],
		"csf": ["ID.RA-6"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"R-4": {
		"step": "authorize",
		"title": "AUTHORIZATION DECISION",
		"text": "Determine if the risk from the operation or use of the information system or the provision or use of common controls is acceptable.",
		"expected_outputs": "Authorization to operate, authorization to use, common control authorization; denial of authorization to operate, denial of authorization to use, denial of common control authorization.",
		"primary_responsibility": ["Authorizing Official"],
		"references": "[SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-160 v1] (Risk Management Process).",
		"outcomes": ["The authorization for the system or the common controls is approved or denied."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"R-5": {
		"step": "authorize",
		"title": "AUTHORIZATION REPORTING",
		"text": "Report the authorization decision and any deficiencies in controls that represent significant security or privacy risk.",
		"expected_outputs": "A report indicating the authorization decision for a system or set of common controls; annotation of authorization status in the organizational system registry.",
		"primary_responsibility": ["Authorizing Official or Authorizing Official Designated Representative"],
		"references": "[SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-160 v1] (Decision Management and Project Assessment and Control Processes); [NIST CSF] (Core [Identify, Protect, Detect, Respond, Recover Functions]).",
		"outcomes": ["Authorization decisions, significant vulnerabilities, and risks are reported to organizational officials."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	# ── Monitor (Table 8): 7 tasks ────────────────────
	"M-1": {
		"step": "monitor",
		"title": "SYSTEM AND ENVIRONMENT CHANGES",
		"text": "Monitor the information system and its environment of operation for changes that impact the security and privacy posture of the system.",
		"expected_outputs": "Updated security and privacy plans; updated plans of action and milestones; updated security and privacy assessment reports.",
		"primary_responsibility": ["System Owner or Common Control Provider", "Senior Agency Information Security Officer", "Senior Agency Official for Privacy"],
		"references": "[SP 800-30]; [SP 800-128]; [SP 800-137]; [IR 8062].",
		"outcomes": ["The information system and environment of operation are monitored in accordance with the continuous monitoring strategy."],
		"csf": ["DE.CM", "ID.GV"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"M-2": {
		"step": "monitor",
		"title": "ONGOING ASSESSMENTS",
		"text": "Assess the controls implemented within and inherited by the system in accordance with the continuous monitoring strategy.",
		"expected_outputs": "Updated security and privacy assessment reports.",
		"primary_responsibility": ["Control Assessor"],
		"references": "[SP 800-53A]; [SP 800-137]; [SP 800-160 v1] (Verification, Validation, Operation, and Maintenance Processes); [IR 8011 v1].",
		"outcomes": ["Ongoing assessments of control effectiveness are conducted in accordance with the continuous monitoring strategy."],
		"csf": ["ID.SC-4"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"M-3": {
		"step": "monitor",
		"title": "ONGOING RISK RESPONSE",
		"text": "Respond to risk based on the results of ongoing monitoring activities, risk assessments, and outstanding items in plans of action and milestones.",
		"expected_outputs": "Mitigation actions or risk acceptance decisions; updated security and privacy assessment reports.",
		"primary_responsibility": ["Authorizing Official", "System Owner", "Common Control Provider"],
		"references": "[SP 800-30]; [SP 800-53]; [SP 800-53A]; [SP 800-137]; [SP 800-160 v1] (Risk Management Process); [IR 8011 v1]; [IR 8062]; [NIST CSF] (Core [Respond Function]).",
		"outcomes": ["The output of continuous monitoring activities is analyzed and responded to appropriately."],
		"csf": ["RS.AN"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"M-4": {
		"step": "monitor",
		"title": "AUTHORIZATION PACKAGE UPDATES",
		"text": "Update plans, assessment reports, and plans of action and milestones based on the results of the continuous monitoring process.",
		"expected_outputs": "Updated security and privacy assessment reports; updated plans of action and milestones; updated risk assessment results; updated security and privacy plans.",
		"primary_responsibility": ["System Owner", "Common Control Provider"],
		"references": "[SP 800-30]; [SP 800-53A].",
		"outcomes": ["Risk management documents are updated based on continuous monitoring activities."],
		"csf": ["RS.IM"],
		"sp800_53_controls": [],
		"gate": "",
	},
	"M-5": {
		"step": "monitor",
		"title": "SECURITY AND PRIVACY REPORTING",
		"text": "Report the security and privacy posture of the system to the authorizing official and other organizational officials on an ongoing basis in accordance with the organizational continuous monitoring strategy.",
		"expected_outputs": "Security and privacy posture reports.",
		"primary_responsibility": ["System Owner", "Common Control Provider", "Senior Agency Information Security Officer", "Senior Agency Official for Privacy"],
		"references": "[SP 800-53A]; [SP 800-137]; [NIST CSF] (Core [Identify, Protect, Detect, Respond, Recover Functions]).",
		"outcomes": ["A process is in place to report the security and privacy posture to the authorizing official and other senior leaders and executives."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"M-6": {
		"step": "monitor",
		"title": "ONGOING AUTHORIZATION",
		"text": "Review the security and privacy posture of the system on an ongoing basis to determine whether the risk remains acceptable.",
		"expected_outputs": "A determination of risk; ongoing authorization to operate, ongoing authorization to use, ongoing common control authorization; denial of ongoing authorization to operate, denial of ongoing authorization to use, denial of ongoing common control authorization.",
		"primary_responsibility": ["Authorizing Official"],
		"references": "[SP 800-30]; [SP 800-39] (Organization, Mission/Business Process, and System Levels); [SP 800-55]; [SP 800-160 v1] (Risk Management Process); [IR 8011 v1]; [IR 8062].",
		"outcomes": ["Authorizing officials conduct ongoing authorizations using the results of continuous monitoring activities and communicate changes in risk determination and acceptance decisions."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
	"M-7": {
		"step": "monitor",
		"title": "SYSTEM DISPOSAL",
		"text": "Implement a system disposal strategy and execute required actions when a system is removed from operation.",
		"expected_outputs": "Disposal strategy; updated system component inventory; updated security and privacy plans.",
		"primary_responsibility": ["System Owner"],
		"references": "[SP 800-30]; [SP 800-88]; [IR 8062].",
		"outcomes": ["A system disposal strategy is developed and implemented, as needed."],
		"csf": [],
		"sp800_53_controls": [],
		"gate": "",
	},
}

default compliant := false

compliant if count(violations) == 0

_in := object.get(input, "nist_rmf", {})

_given := t if {
	t := _in.tasks
	is_object(t)
}

_supplied if _given

_true(id) if _given[id] == true

_gate_declared(g) if is_boolean(_in[g])

# a gated task is not applicable only when its gate is declared false; undeclared counts as applicable
_applicable(id) if {
	tasks[id]
	not _gated_off(id)
}

_gated_off(id) if {
	g := tasks[id].gate
	g != ""
	_in[g] == false
}

_facts_supplied if is_object(input.system_categorization)

_legacy_ok(name) if data.nist.rmf.categorize[name] == true

_legacy_failed(id) := {name |
	_facts_supplied
	some name, tid in legacy
	tid == id
	not _legacy_ok(name)
}

_satisfied(id) if {
	_true(id)
	count(_legacy_failed(id)) == 0
}

violations contains "NIST SP 800-37 Rev 2 RMF: FAIL-CLOSED - task attestations 'input.nist_rmf.tasks' were not supplied (or are not an object); this module cannot be evaluated and is reported non-compliant" if {
	not _supplied
}

violations contains msg if {
	some id, t in tasks
	_applicable(id)
	not _true(id)
	msg := sprintf("NIST SP 800-37 Rev 2 RMF %v (%v, %v): not attested performed — %v", [id, sections[t.step], t.title, t.text])
}

violations contains msg if {
	some name, id in legacy
	name in _legacy_failed(id)
	msg := sprintf("NIST SP 800-37 Rev 2 RMF %v: input.system_categorization supplied but legacy check nist.rmf.categorize.%v does not hold", [id, name])
}

violations contains msg if {
	some g, why in _gates
	not _gate_declared(g)
	msg := sprintf("NIST SP 800-37 Rev 2 RMF Input Contract: gate input.nist_rmf.%v undeclared — %v", [g, why])
}

violations contains msg if {
	some id, _ in _given
	not tasks[id]
	msg := sprintf("NIST SP 800-37 Rev 2 RMF Input Contract: unknown task id %v — ids are printed task ids such as P-1, C-2, M-7", [id])
}

_status(id) := "not_applicable" if not _applicable(id)

else := "satisfied" if _satisfied(id)

else := "not_satisfied"

step_reports[s] := r if {
	some s, name in sections
	ids := {id | some id, t in tasks; t.step == s}
	r := {
		"name": name,
		"tasks_total": count(ids),
		"tasks_satisfied": count({id | some id in ids; _status(id) == "satisfied"}),
		"tasks_not_applicable": sort([id | some id in ids; _status(id) == "not_applicable"]),
		"tasks_not_satisfied": sort([id | some id in ids; _status(id) == "not_satisfied"]),
	}
}

compliance_report := {
	"framework": "NIST SP 800-37 Rev 2 Risk Management Framework",
	"standard": "NIST SP 800-37 Rev 2 — Risk Management Framework for Information Systems and Organizations (December 2018), Chapter 3 tasks",
	"source": source,
	"compliant": compliant,
	"total_controls": count(tasks),
	"standard_total": 47, # RMF tasks printed in Chapter 3 (P-1..P-18, C-1..C-3, S-1..S-6, I-1..I-2, A-1..A-6, R-1..R-5, M-1..M-7)
	"tasks_satisfied": count({id | some id, _ in tasks; _status(id) == "satisfied"}),
	"tasks_not_applicable": count({id | some id, _ in tasks; _status(id) == "not_applicable"}),
	"steps": step_reports,
	"categorization_facts_supplied": _facts_supplied_bool,
	"violation_count": count(violations),
	"violations": violations,
}

_facts_supplied_bool if _facts_supplied

else := false
