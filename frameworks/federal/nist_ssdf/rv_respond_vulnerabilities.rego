package nist_ssdf.rv

# NIST SSDF (SP 800-218 v1.1) — Practice Group: Respond to Vulnerabilities (RV)
#
# Identifies residual vulnerabilities in releases and responds appropriately to
# prevent similar ones in the future.
#
# Input contract (vulnerability-management posture — booleans):
#   input.vulnerability_management.monitoring_enabled
#   input.vulnerability_management.disclosure_program
#   input.vulnerability_management.response_process
#   input.vulnerability_management.triage_process
#   input.vulnerability_management.remediation_sla_defined
#   input.vulnerability_management.root_cause_analysis
#   input.vulnerability_management.systemic_review
#   input.vulnerability_management.process_improvement
#
# OPA endpoint: POST /v1/data/nist_ssdf/rv/compliance_report

import rego.v1

default compliant := false

# Discrete security checks in this group (each `violations` rule = one check).
controls_evaluated := 8

# ── RV.1  Identify and Confirm Vulnerabilities on an Ongoing Basis ─────────────

violations contains msg if {
	not input.vulnerability_management.monitoring_enabled == true
	msg := "RV.1.1: Ongoing monitoring for vulnerabilities in releases/components is not enabled"
}

violations contains msg if {
	not input.vulnerability_management.disclosure_program == true
	msg := "RV.1.2: No vulnerability disclosure program / intake channel exists"
}

violations contains msg if {
	not input.vulnerability_management.response_process == true
	msg := "RV.1.3: A documented vulnerability response process is not established"
}

# ── RV.2  Assess, Prioritize, and Remediate Vulnerabilities ───────────────────

violations contains msg if {
	not input.vulnerability_management.triage_process == true
	msg := "RV.2.1: Vulnerabilities are not analyzed and prioritized (triage/severity)"
}

violations contains msg if {
	not input.vulnerability_management.remediation_sla_defined == true
	msg := "RV.2.2: Remediation SLAs/timelines are not defined for confirmed vulnerabilities"
}

# ── RV.3  Analyze Vulnerabilities to Identify Root Causes ──────────────────────

violations contains msg if {
	not input.vulnerability_management.root_cause_analysis == true
	msg := "RV.3.1: Root-cause analysis is not performed for identified vulnerabilities"
}

violations contains msg if {
	not input.vulnerability_management.systemic_review == true
	msg := "RV.3.2: Codebase is not reviewed for other instances of the same class of vulnerability"
}

violations contains msg if {
	not input.vulnerability_management.process_improvement == true
	msg := "RV.3.3: SDLC is not reviewed/improved to prevent recurrence of root causes"
}

# ── Aggregate ─────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"practice_group": "RV — Respond to Vulnerabilities",
	"controls_evaluated": controls_evaluated,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
