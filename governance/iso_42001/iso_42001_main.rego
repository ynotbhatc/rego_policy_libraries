# METADATA
# title: "ISO/IEC 42001:2023 — Artificial Intelligence Management System (AIMS)"
# custom:
#   class: governance
#   framework: iso_42001
#   source: iso
#   domains: [ai]
#   coverage:
#     checks: 38
#     cited: 38
#     expected: 38
#     found: 38
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package iso_42001.main

import rego.v1

# ISO/IEC 42001:2023 — Artificial Intelligence Management System (AIMS)
#
# The first certifiable AI management-system standard: clauses 4-10
# define the mandatory AIMS requirements (same Annex SL skeleton as
# ISO 27001), and Annex A supplies 38 AI-specific controls across nine
# groups (A.2-A.10). This module evaluates the management-system
# clauses plus the Annex A control groups at attestation granularity —
# one check per requirement theme, in the same entity-attestation
# style as iso27001 / ny_dfs / glba.
#
# Completes the library's AI-governance trio:
#   governance/eu_ai_act/   — EU AI Act (regulatory, risk-tiered)
#   nist_ai_rmf             — NIST AI RMF (voluntary risk framework)
#   governance/iso_42001/   — ISO/IEC 42001 (certifiable AIMS)
#
# Input contract: entity-level attestation + AIMS artifacts. An
# organization runs this against facts describing its AI management
# system, not against a single AI system (per-system obligations are
# the EU AI Act module's job). See tests for the expected shape.

# ── Evidence rule ────────────────────────────────────────────────────────────
# Only the boolean true passes a yes/no fact. A fact that is missing, null, or any
# other type ("true", "false", "no", 0, 1) is an evidence problem: the control fails
# and the finding names the problem. A boolean false keeps the plain finding.

default _input := {}

_input := input if is_object(input)

_fact(path) := object.get(_input, path, null)

_not_true(path) if _fact(path) != true

_finding(msg, path) := msg if _fact(path) == false

_finding(msg, path) := sprintf("%s [evidence missing — input.%s not collected]", [msg, concat(".", path)]) if {
	_fact(path) == null
}

_finding(msg, path) := sprintf("%s [evidence invalid — input.%s is not a boolean (got %s)]", [msg, concat(".", path), type_name(_fact(path))]) if {
	value := _fact(path)
	value != null
	not is_boolean(value)
}

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Clause 4 — Context of the Organization ───────────────────────────────────

violations contains msg if {
	_not_true(["context", "internal_external_issues_determined"])
	msg := _finding("ISO 42001 4.1: Internal and external issues relevant to the AIMS not determined (including the organization's role as AI provider, deployer, or user)", ["context", "internal_external_issues_determined"])
}

# The organization's AI role (provider, deployer, user, ...) scopes the whole assessment and is part of
# the 4.1 determination: a report without it has no stated subject, so it is an evidence problem on 4.1.
violations contains msg if {
	_fact(["organization_role"]) == null
	msg := "ISO 42001 4.1: [evidence missing — input.organization_role not collected]"
}

violations contains msg if {
	role := _fact(["organization_role"])
	role != null
	not _nonempty_string(role)
	msg := sprintf("ISO 42001 4.1: [evidence invalid — input.organization_role is not a non-empty string (got %s)]", [type_name(role)])
}

_nonempty_string(value) if {
	is_string(value)
	trim_space(value) != ""
}

violations contains msg if {
	_not_true(["context", "interested_parties_identified"])
	msg := _finding("ISO 42001 4.2: Interested parties and their requirements relevant to the AIMS not identified", ["context", "interested_parties_identified"])
}

violations contains msg if {
	_not_true(["context", "aims_scope_documented"])
	msg := _finding("ISO 42001 4.3: Scope of the AI management system not determined and documented", ["context", "aims_scope_documented"])
}

# ── Clause 5 — Leadership ────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["leadership", "top_management_commitment"])
	msg := _finding("ISO 42001 5.1: Top management leadership and commitment to the AIMS not demonstrated", ["leadership", "top_management_commitment"])
}

violations contains msg if {
	_not_true(["leadership", "ai_policy_established"])
	msg := _finding("ISO 42001 5.2 / A.2.2: AI policy not established, documented, and communicated", ["leadership", "ai_policy_established"])
}

violations contains msg if {
	_not_true(["leadership", "roles_responsibilities_assigned"])
	msg := _finding("ISO 42001 5.3 / A.3.2: AI roles, responsibilities, and authorities not assigned and communicated", ["leadership", "roles_responsibilities_assigned"])
}

# ── Clause 6 — Planning ──────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["planning", "ai_risk_assessment_process"])
	msg := _finding("ISO 42001 6.1.2: AI risk assessment process not established (criteria, identification, analysis, evaluation)", ["planning", "ai_risk_assessment_process"])
}

violations contains msg if {
	_not_true(["planning", "ai_impact_assessment_process"])
	msg := _finding("ISO 42001 6.1.4 / A.5: AI system impact assessment process not established — impacts on individuals, groups, and society", ["planning", "ai_impact_assessment_process"])
}

violations contains msg if {
	_not_true(["planning", "risk_treatment_plan"])
	msg := _finding("ISO 42001 6.1.3: AI risk treatment plan not produced with controls selected against Annex A", ["planning", "risk_treatment_plan"])
}

violations contains msg if {
	_not_true(["planning", "measurable_objectives"])
	msg := _finding("ISO 42001 6.2: Measurable AI objectives not established with plans to achieve them", ["planning", "measurable_objectives"])
}

# ── Clause 7 — Support ───────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["support", "resources_determined"])
	msg := _finding("ISO 42001 7.1 / A.4: Resources for the AIMS not determined (data, tooling, computing, human resources documented per A.4.2-A.4.6)", ["support", "resources_determined"])
}

violations contains msg if {
	_not_true(["support", "competence_ensured"])
	msg := _finding("ISO 42001 7.2: Competence of persons doing AIMS work not ensured or evidenced", ["support", "competence_ensured"])
}

violations contains msg if {
	_not_true(["support", "awareness_program"])
	msg := _finding("ISO 42001 7.3: Personnel not made aware of the AI policy and their AIMS contribution", ["support", "awareness_program"])
}

violations contains msg if {
	_not_true(["support", "documented_information_controlled"])
	msg := _finding("ISO 42001 7.5: Documented information required by the AIMS not created, updated, and controlled", ["support", "documented_information_controlled"])
}

# ── Clause 8 — Operation ─────────────────────────────────────────────────────

violations contains msg if {
	_not_true(["operation", "processes_planned_controlled"])
	msg := _finding("ISO 42001 8.1: Operational planning and control of AIMS processes not implemented", ["operation", "processes_planned_controlled"])
}

violations contains msg if {
	_not_true(["operation", "risk_assessments_at_intervals"])
	msg := _finding("ISO 42001 8.2: AI risk assessments not performed at planned intervals and on significant change", ["operation", "risk_assessments_at_intervals"])
}

violations contains msg if {
	_not_true(["operation", "impact_assessments_performed"])
	msg := _finding("ISO 42001 8.4: AI system impact assessments not performed per the 6.1.4 process", ["operation", "impact_assessments_performed"])
}

# ── Clause 9 — Performance Evaluation ────────────────────────────────────────

violations contains msg if {
	_not_true(["performance", "monitoring_measurement"])
	msg := _finding("ISO 42001 9.1: AIMS performance not monitored, measured, analyzed, and evaluated", ["performance", "monitoring_measurement"])
}

violations contains msg if {
	_not_true(["performance", "internal_audit_program"])
	msg := _finding("ISO 42001 9.2: Internal audit program for the AIMS not conducted at planned intervals", ["performance", "internal_audit_program"])
}

violations contains msg if {
	_not_true(["performance", "management_review"])
	msg := _finding("ISO 42001 9.3: Management review of the AIMS not performed at planned intervals", ["performance", "management_review"])
}

# ── Clause 10 — Improvement ──────────────────────────────────────────────────

violations contains msg if {
	_not_true(["improvement", "nonconformity_corrective_action"])
	msg := _finding("ISO 42001 10.2: Nonconformities not reacted to with corrective action and effectiveness review", ["improvement", "nonconformity_corrective_action"])
}

# ── Annex A.3 — Internal Organization ────────────────────────────────────────

violations contains msg if {
	_not_true(["annex_a", "concern_reporting_process"])
	msg := _finding("ISO 42001 A.3.3: Process for reporting concerns about the organization's role in AI systems not established", ["annex_a", "concern_reporting_process"])
}

# ── Annex A.4 — Resources for AI Systems ─────────────────────────────────────

violations contains msg if {
	_not_true(["annex_a", "resources_documented"])
	msg := _finding("ISO 42001 A.4.2: Resources for each AI system life-cycle stage (data, tooling, system, computing, human) not documented", ["annex_a", "resources_documented"])
}

# ── Annex A.6 — AI System Life Cycle ─────────────────────────────────────────

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "responsible_development_objectives"])
	msg := _finding("ISO 42001 A.6.1.2: Objectives for responsible development of AI systems not identified and documented", ["annex_a", "lifecycle", "responsible_development_objectives"])
}

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "requirements_specified"])
	msg := _finding("ISO 42001 A.6.2.2: AI system requirements and specifications not documented", ["annex_a", "lifecycle", "requirements_specified"])
}

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "verification_validation"])
	msg := _finding("ISO 42001 A.6.2.4: Verification and validation measures for AI systems not defined and applied", ["annex_a", "lifecycle", "verification_validation"])
}

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "deployment_plan"])
	msg := _finding("ISO 42001 A.6.2.5: AI system deployment plan (requirements met before deployment) not documented", ["annex_a", "lifecycle", "deployment_plan"])
}

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "operation_monitoring"])
	msg := _finding("ISO 42001 A.6.2.6: AI system operation and monitoring (performance, drift, failures) not implemented", ["annex_a", "lifecycle", "operation_monitoring"])
}

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "technical_documentation"])
	msg := _finding("ISO 42001 A.6.2.7: Technical documentation for each AI system not maintained for interested parties", ["annex_a", "lifecycle", "technical_documentation"])
}

violations contains msg if {
	_not_true(["annex_a", "lifecycle", "event_logging"])
	msg := _finding("ISO 42001 A.6.2.8: Event logs of AI system behavior not recorded and retained", ["annex_a", "lifecycle", "event_logging"])
}

# ── Annex A.7 — Data for AI Systems ──────────────────────────────────────────

violations contains msg if {
	_not_true(["annex_a", "data", "management_process"])
	msg := _finding("ISO 42001 A.7.2: Data management process for AI system data (privacy, security, transparency implications) not defined", ["annex_a", "data", "management_process"])
}

violations contains msg if {
	_not_true(["annex_a", "data", "provenance_recorded"])
	msg := _finding("ISO 42001 A.7.5: Provenance of data used in AI systems not recorded", ["annex_a", "data", "provenance_recorded"])
}

violations contains msg if {
	_not_true(["annex_a", "data", "quality_criteria"])
	msg := _finding("ISO 42001 A.7.4: Data quality requirements and criteria for AI system data not defined and measured", ["annex_a", "data", "quality_criteria"])
}

# ── Annex A.8 — Information for Interested Parties ───────────────────────────

violations contains msg if {
	_not_true(["annex_a", "interested_parties", "user_information"])
	msg := _finding("ISO 42001 A.8.2: Information enabling users to understand and use AI systems appropriately not provided", ["annex_a", "interested_parties", "user_information"])
}

violations contains msg if {
	_not_true(["annex_a", "interested_parties", "incident_reporting"])
	msg := _finding("ISO 42001 A.8.4: Process for reporting AI system incidents to interested parties not established", ["annex_a", "interested_parties", "incident_reporting"])
}

# ── Annex A.9 — Responsible Use ──────────────────────────────────────────────

violations contains msg if {
	_not_true(["annex_a", "responsible_use", "objectives_defined"])
	msg := _finding("ISO 42001 A.9.2/A.9.3: Objectives and processes for responsible use of AI systems (intended-use alignment) not documented", ["annex_a", "responsible_use", "objectives_defined"])
}

# ── Annex A.10 — Third-Party Relationships ───────────────────────────────────

violations contains msg if {
	_not_true(["annex_a", "third_party", "responsibilities_allocated"])
	msg := _finding("ISO 42001 A.10.2: Responsibilities between the organization and third parties (suppliers, partners, customers) in the AI life cycle not allocated", ["annex_a", "third_party", "responsibilities_allocated"])
}

violations contains msg if {
	_not_true(["annex_a", "third_party", "supplier_process"])
	msg := _finding("ISO 42001 A.10.3: Process to ensure supplier services align with the organization's responsible-AI approach not established", ["annex_a", "third_party", "supplier_process"])
}

# ── Compliance Report ────────────────────────────────────────────────────────

# Defaults — without these, an undefined input field makes the
# entire compliance_report object undefined (Rego v1 behavior).
default assessment_date := "unknown"

assessment_date := input.assessment_date

default entity_name := "unknown"

entity_name := input.entity_name

default organization_role := "unknown"

organization_role := input.organization_role

compliance_report := {
	"framework": "ISO/IEC 42001 AI Management System",
	"standard": "ISO/IEC 42001:2023",
	"entity_name": entity_name,
	"organization_role": organization_role,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"total_controls": 38,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": min([38, count(violations)]),
}
