# ISO/IEC 42005:2025 — AI system impact assessment (first edition,
# published 2025-05-28).
#
# 42005 is a GUIDANCE standard ("should", not "shall") — these checks
# are attestations that the organization's documented AI impact
# assessment (AIIA) process and per-system records exhibit each element
# the standard describes. Clause 5 covers the organizational PROCESS;
# Clause 6 covers the per-system DOCUMENTATION. Violation messages cite
# at the clause-5/clause-6 granularity, which is stable across the
# published edition; finer sub-clause numbers live in comments only —
# verify against the purchased ISO text before quoting them in an
# audit deliverable.
#
# Companion to governance/iso_42001 (AIMS): 42001's 6.1.4 requires an
# AI impact assessment; 42005 is how to do it (Annex A integration).
#
# Query: POST /v1/data/iso_42005/main/compliance_report
#
# Fail-closed: every fact must be affirmatively true; empty input
# yields all violations.
#
# Input contract — input.iso_42005.* (all bool), two groups:
#   process.*   — organization-level AIIA process facts
#   records.*   — facts about the per-system AIIA records (attest for
#                 the assessed population, e.g. all production systems)

package iso_42005.main

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

# ── Clause 5 — the AIIA process ──────────────────────────────────────────────

violations contains msg if {
	not input.iso_42005.process.documented_repeatable_approach == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): no documented, repeatable AI impact assessment approach reflecting internal context (governance, risk appetite) and external context (regulation, norms, market)"
}

# 5.2
violations contains msg if {
	not input.iso_42005.process.methodology_and_roles_documented == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): AIIA methodology, roles, inputs, outputs and decision workflow not documented and version-controlled"
}

# 5.3
violations contains msg if {
	not input.iso_42005.process.integrated_with_management_processes == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): AIIA not integrated with existing management processes (risk management, compliance, privacy/DPIA) — standalone assessments drift"
}

# 5.4
violations contains msg if {
	not input.iso_42005.process.lifecycle_triggers_defined == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): assessment timing triggers not defined (design/planning, before deployment, after significant change)"
}

# 5.6
violations contains msg if {
	not input.iso_42005.process.responsibilities_allocated == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): assessor, reviewer and approver roles not allocated as distinct responsibilities with multidisciplinary input"
}

# 5.7
violations contains msg if {
	not input.iso_42005.process.sensitive_use_thresholds_defined == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): thresholds for sensitive/restricted uses and impact scales that trigger in-depth assessment and escalated approval not established"
}

# 5.9
violations contains msg if {
	not input.iso_42005.process.severity_likelihood_scales_defined == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): severity and likelihood scales for rating identified impacts not defined"
}

# 5.11
violations contains msg if {
	not input.iso_42005.process.approval_before_deployment_required == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): formal AIIA review and sign-off before deployment not required at a defined authority level"
}

# 5.12
violations contains msg if {
	not input.iso_42005.process.monitoring_and_reassessment_defined == true
	msg := "ISO/IEC 42005:2025 Clause 5 (process): review cadence and re-assessment triggers (system change, new use, context change, incident, emerging harm) not defined"
}

# Annex A
violations contains msg if {
	not input.iso_42005.process.integrated_with_aims == true
	msg := "ISO/IEC 42005:2025 Annex A: AIIA not referenced from the organization's AI management system (ISO/IEC 42001 6.1.4 requires an AI impact assessment; duplicate processes drift)"
}

# ── Clause 6 — per-system AIIA records ───────────────────────────────────────

violations contains msg if {
	not input.iso_42005.records.scope_stated == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): AIIA records do not state the assessment scope (system boundary, intended purpose, operational context)"
}

# 6.3
violations contains msg if {
	not input.iso_42005.records.unintended_uses_covered == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): AIIA records cover intended uses but not reasonably foreseeable UNintended uses and misuse"
}

# 6.4
violations contains msg if {
	not input.iso_42005.records.data_quality_documented == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): data sources, provenance and quality measures for development and operational data not documented"
}

# 6.5
violations contains msg if {
	not input.iso_42005.records.model_versioned == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): algorithm/model information (type, development approach, version identifiers, deployment details) not documented"
}

# 6.6
violations contains msg if {
	not input.iso_42005.records.deployment_environment_described == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): deployment environment (geography, languages, operational constraints) not described"
}

# 6.7
violations contains msg if {
	not input.iso_42005.records.interested_parties_identified == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): interested parties not identified, including indirectly affected and vulnerable individuals/groups"
}

# 6.8 / 5.8
violations contains msg if {
	not input.iso_42005.records.harms_and_benefits_assessed == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): impacts not assessed across both harms AND benefits, including failure modes and misuse scenarios"
}

# 5.9 applied per record
violations contains msg if {
	not input.iso_42005.records.impacts_rated == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): identified impacts not rated for severity and likelihood on the defined scales"
}

# 6.9
violations contains msg if {
	not input.iso_42005.records.mitigations_with_owners == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): high-severity impacts lack mitigation measures with named owners"
}

# 5.11 applied per record
violations contains msg if {
	not input.iso_42005.records.approval_predates_deployment == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): approval records (approver, date) do not predate deployment for production AI systems"
}

# 5.12 applied per record
violations contains msg if {
	not input.iso_42005.records.reviews_current == true
	msg := "ISO/IEC 42005:2025 Clause 6 (documentation): AIIA records not current — last review outside the defined cadence or change-triggered re-assessment missing"
}

# Annex D
violations contains msg if {
	not input.iso_42005.records.related_assessments_cross_referenced == true
	msg := "ISO/IEC 42005:2025 Annex D: related assessments (DPIA/privacy, ethics, environmental) for the same system not cross-referenced"
}

compliance_report := {
	"framework": "ISO/IEC 42005:2025 — AI system impact assessment",
	"edition": "first edition (2025-05-28); guidance standard — checks are attestations",
	"controls_evaluated": 22,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
