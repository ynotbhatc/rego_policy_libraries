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

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Clause 4 — Context of the Organization ───────────────────────────────────

violations contains msg if {
	not input.context.internal_external_issues_determined
	msg := "ISO 42001 4.1: Internal and external issues relevant to the AIMS not determined (including the organization's role as AI provider, deployer, or user)"
}

violations contains msg if {
	not input.context.interested_parties_identified
	msg := "ISO 42001 4.2: Interested parties and their requirements relevant to the AIMS not identified"
}

violations contains msg if {
	not input.context.aims_scope_documented
	msg := "ISO 42001 4.3: Scope of the AI management system not determined and documented"
}

# ── Clause 5 — Leadership ────────────────────────────────────────────────────

violations contains msg if {
	not input.leadership.top_management_commitment
	msg := "ISO 42001 5.1: Top management leadership and commitment to the AIMS not demonstrated"
}

violations contains msg if {
	not input.leadership.ai_policy_established
	msg := "ISO 42001 5.2 / A.2.2: AI policy not established, documented, and communicated"
}

violations contains msg if {
	not input.leadership.roles_responsibilities_assigned
	msg := "ISO 42001 5.3 / A.3.2: AI roles, responsibilities, and authorities not assigned and communicated"
}

# ── Clause 6 — Planning ──────────────────────────────────────────────────────

violations contains msg if {
	not input.planning.ai_risk_assessment_process
	msg := "ISO 42001 6.1.2: AI risk assessment process not established (criteria, identification, analysis, evaluation)"
}

violations contains msg if {
	not input.planning.ai_impact_assessment_process
	msg := "ISO 42001 6.1.4 / A.5: AI system impact assessment process not established — impacts on individuals, groups, and society"
}

violations contains msg if {
	not input.planning.risk_treatment_plan
	msg := "ISO 42001 6.1.3: AI risk treatment plan not produced with controls selected against Annex A"
}

violations contains msg if {
	not input.planning.measurable_objectives
	msg := "ISO 42001 6.2: Measurable AI objectives not established with plans to achieve them"
}

# ── Clause 7 — Support ───────────────────────────────────────────────────────

violations contains msg if {
	not input.support.resources_determined
	msg := "ISO 42001 7.1 / A.4: Resources for the AIMS not determined (data, tooling, computing, human resources documented per A.4.2-A.4.6)"
}

violations contains msg if {
	not input.support.competence_ensured
	msg := "ISO 42001 7.2: Competence of persons doing AIMS work not ensured or evidenced"
}

violations contains msg if {
	not input.support.awareness_program
	msg := "ISO 42001 7.3: Personnel not made aware of the AI policy and their AIMS contribution"
}

violations contains msg if {
	not input.support.documented_information_controlled
	msg := "ISO 42001 7.5: Documented information required by the AIMS not created, updated, and controlled"
}

# ── Clause 8 — Operation ─────────────────────────────────────────────────────

violations contains msg if {
	not input.operation.processes_planned_controlled
	msg := "ISO 42001 8.1: Operational planning and control of AIMS processes not implemented"
}

violations contains msg if {
	not input.operation.risk_assessments_at_intervals
	msg := "ISO 42001 8.2: AI risk assessments not performed at planned intervals and on significant change"
}

violations contains msg if {
	not input.operation.impact_assessments_performed
	msg := "ISO 42001 8.4: AI system impact assessments not performed per the 6.1.4 process"
}

# ── Clause 9 — Performance Evaluation ────────────────────────────────────────

violations contains msg if {
	not input.performance.monitoring_measurement
	msg := "ISO 42001 9.1: AIMS performance not monitored, measured, analyzed, and evaluated"
}

violations contains msg if {
	not input.performance.internal_audit_program
	msg := "ISO 42001 9.2: Internal audit program for the AIMS not conducted at planned intervals"
}

violations contains msg if {
	not input.performance.management_review
	msg := "ISO 42001 9.3: Management review of the AIMS not performed at planned intervals"
}

# ── Clause 10 — Improvement ──────────────────────────────────────────────────

violations contains msg if {
	not input.improvement.nonconformity_corrective_action
	msg := "ISO 42001 10.2: Nonconformities not reacted to with corrective action and effectiveness review"
}

# ── Annex A.3 — Internal Organization ────────────────────────────────────────

violations contains msg if {
	not input.annex_a.concern_reporting_process
	msg := "ISO 42001 A.3.3: Process for reporting concerns about the organization's role in AI systems not established"
}

# ── Annex A.4 — Resources for AI Systems ─────────────────────────────────────

violations contains msg if {
	not input.annex_a.resources_documented
	msg := "ISO 42001 A.4.2: Resources for each AI system life-cycle stage (data, tooling, system, computing, human) not documented"
}

# ── Annex A.6 — AI System Life Cycle ─────────────────────────────────────────

violations contains msg if {
	not input.annex_a.lifecycle.responsible_development_objectives
	msg := "ISO 42001 A.6.1.2: Objectives for responsible development of AI systems not identified and documented"
}

violations contains msg if {
	not input.annex_a.lifecycle.requirements_specified
	msg := "ISO 42001 A.6.2.2: AI system requirements and specifications not documented"
}

violations contains msg if {
	not input.annex_a.lifecycle.verification_validation
	msg := "ISO 42001 A.6.2.4: Verification and validation measures for AI systems not defined and applied"
}

violations contains msg if {
	not input.annex_a.lifecycle.deployment_plan
	msg := "ISO 42001 A.6.2.5: AI system deployment plan (requirements met before deployment) not documented"
}

violations contains msg if {
	not input.annex_a.lifecycle.operation_monitoring
	msg := "ISO 42001 A.6.2.6: AI system operation and monitoring (performance, drift, failures) not implemented"
}

violations contains msg if {
	not input.annex_a.lifecycle.technical_documentation
	msg := "ISO 42001 A.6.2.7: Technical documentation for each AI system not maintained for interested parties"
}

violations contains msg if {
	not input.annex_a.lifecycle.event_logging
	msg := "ISO 42001 A.6.2.8: Event logs of AI system behavior not recorded and retained"
}

# ── Annex A.7 — Data for AI Systems ──────────────────────────────────────────

violations contains msg if {
	not input.annex_a.data.management_process
	msg := "ISO 42001 A.7.2: Data management process for AI system data (privacy, security, transparency implications) not defined"
}

violations contains msg if {
	not input.annex_a.data.provenance_recorded
	msg := "ISO 42001 A.7.5: Provenance of data used in AI systems not recorded"
}

violations contains msg if {
	not input.annex_a.data.quality_criteria
	msg := "ISO 42001 A.7.4: Data quality requirements and criteria for AI system data not defined and measured"
}

# ── Annex A.8 — Information for Interested Parties ───────────────────────────

violations contains msg if {
	not input.annex_a.interested_parties.user_information
	msg := "ISO 42001 A.8.2: Information enabling users to understand and use AI systems appropriately not provided"
}

violations contains msg if {
	not input.annex_a.interested_parties.incident_reporting
	msg := "ISO 42001 A.8.4: Process for reporting AI system incidents to interested parties not established"
}

# ── Annex A.9 — Responsible Use ──────────────────────────────────────────────

violations contains msg if {
	not input.annex_a.responsible_use.objectives_defined
	msg := "ISO 42001 A.9.2/A.9.3: Objectives and processes for responsible use of AI systems (intended-use alignment) not documented"
}

# ── Annex A.10 — Third-Party Relationships ───────────────────────────────────

violations contains msg if {
	not input.annex_a.third_party.responsibilities_allocated
	msg := "ISO 42001 A.10.2: Responsibilities between the organization and third parties (suppliers, partners, customers) in the AI life cycle not allocated"
}

violations contains msg if {
	not input.annex_a.third_party.supplier_process
	msg := "ISO 42001 A.10.3: Process to ensure supplier services align with the organization's responsible-AI approach not established"
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
}
