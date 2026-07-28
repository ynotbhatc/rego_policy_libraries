package nist_ssdf.po

# NIST SSDF (SP 800-218 v1.1) — Practice Group: Prepare the Organization (PO)
#
# Ensures the organization's people, processes, and technology are prepared to
# perform secure software development at the organization level.
#
# Input contract (organizational + toolchain posture — booleans unless noted):
#   input.organization.security_requirements_defined
#   input.organization.third_party_requirements_communicated
#   input.organization.requirements_maintained
#   input.organization.roles_defined
#   input.organization.role_training_provided
#   input.organization.management_commitment
#   input.organization.security_criteria_defined
#   input.toolchain.specified
#   input.toolchain.security_integrated
#   input.toolchain.artifacts_collected
#   input.toolchain.security_check_data_collected
#   input.environments.separated
#   input.environments.endpoints_secured
#
# OPA endpoint: POST /v1/data/nist_ssdf/po/compliance_report

import rego.v1

default compliant := false

controls_evaluated := 13

# ── PO.1  Define Security Requirements for Software Development ────────────────

violations contains msg if {
	not input.organization.security_requirements_defined == true
	msg := "PO.1.1: Security requirements for software development are not defined and documented"
}

violations contains msg if {
	not input.organization.third_party_requirements_communicated == true
	msg := "PO.1.2: Security requirements are not communicated to third-party suppliers/developers"
}

violations contains msg if {
	not input.organization.requirements_maintained == true
	msg := "PO.1.3: Software security requirements are not maintained/reviewed over time"
}

# ── PO.2  Implement Roles and Responsibilities ────────────────────────────────

violations contains msg if {
	not input.organization.roles_defined == true
	msg := "PO.2.1: SDLC security roles and responsibilities are not defined for all personnel"
}

violations contains msg if {
	not input.organization.role_training_provided == true
	msg := "PO.2.2: Role-based secure-development training is not provided"
}

violations contains msg if {
	not input.organization.management_commitment == true
	msg := "PO.2.3: Management has not committed resources/support to secure development"
}

# ── PO.3  Implement Supporting Toolchains ─────────────────────────────────────

violations contains msg if {
	not input.toolchain.specified == true
	msg := "PO.3.1: A supporting toolchain for secure development is not specified"
}

violations contains msg if {
	not input.toolchain.security_integrated == true
	msg := "PO.3.2: Security is not integrated into the development toolchain (SAST/SCA/signing)"
}

violations contains msg if {
	not input.toolchain.artifacts_collected == true
	msg := "PO.3.3: Toolchain artifacts/evidence are not collected for auditability"
}

# ── PO.4  Define and Use Criteria for Software Security Checks ─────────────────

violations contains msg if {
	not input.organization.security_criteria_defined == true
	msg := "PO.4.1: Criteria for software security checks (gates) are not defined"
}

violations contains msg if {
	not input.toolchain.security_check_data_collected == true
	msg := "PO.4.2: Security-check data is not gathered/reviewed to inform decision-making"
}

# ── PO.5  Implement and Maintain Secure Environments ──────────────────────────

violations contains msg if {
	not input.environments.separated == true
	msg := "PO.5.1: Development, build, and production environments are not separated/isolated"
}

violations contains msg if {
	not input.environments.endpoints_secured == true
	msg := "PO.5.2: Developer endpoints and build environments are not hardened/secured"
}

# ── Aggregate ─────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"practice_group": "PO — Prepare the Organization",
	"controls_evaluated": controls_evaluated,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
