package nist_ssdf.pw

# NIST SSDF (SP 800-218 v1.1) — Practice Group: Produce Well-Secured Software (PW)
#
# Produces software with minimal security vulnerabilities in its releases.
#
# Input contract (design / build / review / test posture — booleans):
#   input.design.threat_model_performed
#   input.design.security_requirements_tracked
#   input.design.standardized_security_features
#   input.design.design_review_performed
#   input.dependencies.vetted_components
#   input.dependencies.internal_components_secured
#   input.dependencies.sca_enabled
#   input.dependencies.vulnerability_scanned
#   input.coding.secure_coding_standards
#   input.build.hardening_flags
#   input.build.integrity_verified
#   input.code_review.peer_review_required
#   input.sast.enabled
#   input.testing.security_testing_planned
#   input.testing.dast_enabled
#   input.configuration.secure_defaults
#   input.configuration.defaults_verified
#
# OPA endpoint: POST /v1/data/nist_ssdf/pw/compliance_report

import rego.v1

default compliant := false

# One check per SP 800-218 task (1:1 with the standard's task IDs).
controls_evaluated := 16

# ── PW.1  Design Software to Meet Security Requirements and Mitigate Risks ─────

violations contains msg if {
	not input.design.threat_model_performed == true
	msg := "PW.1.1: Threat modeling / design risk analysis is not performed"
}

violations contains msg if {
	not input.design.security_requirements_tracked == true
	msg := "PW.1.2: Security requirements are not tracked and maintained in the design"
}

violations contains msg if {
	not input.design.standardized_security_features == true
	msg := "PW.1.3: Standardized, well-vetted security features/services are not used where appropriate (custom implementations instead)"
}

# ── PW.2  Review the Software Design to Verify Compliance ──────────────────────

violations contains msg if {
	not input.design.design_review_performed == true
	msg := "PW.2.1: Software design is not reviewed by a qualified reviewer against security requirements"
}

# ── PW.4  Reuse Existing, Well-Secured Software ───────────────────────────────

violations contains msg if {
	not input.dependencies.vetted_components == true
	msg := "PW.4.1: Third-party/open-source components are not acquired from vetted, well-secured sources"
}

violations contains msg if {
	not input.dependencies.internal_components_secured == true
	msg := "PW.4.2: Reusable in-house components for common security needs are not created/maintained as well-secured"
}

violations contains msg if {
	not acquired_components_verified
	msg := "PW.4.4: Acquired components are not verified against requirements (require SCA enabled AND vulnerability scanning)"
}

acquired_components_verified if {
	input.dependencies.sca_enabled == true
	input.dependencies.vulnerability_scanned == true
}

# ── PW.5  Create Source Code Adhering to Secure Coding Practices ───────────────

violations contains msg if {
	not input.coding.secure_coding_standards == true
	msg := "PW.5.1: Secure coding standards are not defined and followed"
}

# ── PW.6  Configure the Build Process to Improve Executable Security ───────────

violations contains msg if {
	not input.build.hardening_flags == true
	msg := "PW.6.1: Compiler/build hardening settings (e.g. stack protection, RELRO) are not enabled"
}

violations contains msg if {
	not input.build.integrity_verified == true
	msg := "PW.6.2: Build process integrity is not verified (reproducible/attested builds)"
}

# ── PW.7  Review and/or Analyze Human-Readable Code ───────────────────────────

violations contains msg if {
	not input.code_review.peer_review_required == true
	msg := "PW.7.1: Peer code review is not required before merge"
}

violations contains msg if {
	not input.sast.enabled == true
	msg := "PW.7.2: Automated static analysis (SAST) is not enabled in the pipeline"
}

# ── PW.8  Test Executable Code to Identify Vulnerabilities ─────────────────────

violations contains msg if {
	not input.testing.security_testing_planned == true
	msg := "PW.8.1: Security test cases / test configuration are not defined"
}

violations contains msg if {
	not input.testing.dast_enabled == true
	msg := "PW.8.2: Dynamic analysis (DAST) / runtime security testing is not performed"
}

# ── PW.9  Configure Software to Have Secure Settings by Default ────────────────

violations contains msg if {
	not input.configuration.secure_defaults == true
	msg := "PW.9.1: Software is not configured with secure settings by default"
}

violations contains msg if {
	not input.configuration.defaults_verified == true
	msg := "PW.9.2: Secure default settings are not verified before release"
}

# ── Aggregate ─────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"practice_group": "PW — Produce Well-Secured Software",
	"controls_evaluated": controls_evaluated,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
