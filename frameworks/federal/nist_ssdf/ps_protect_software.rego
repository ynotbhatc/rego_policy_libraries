package nist_ssdf.ps

# NIST SSDF (SP 800-218 v1.1) — Practice Group: Protect the Software (PS)
#
# Protects all components of the software from tampering and unauthorized access.
#
# Input contract (source-control / release posture — booleans):
#   input.source_control.access_controlled
#   input.source_control.branch_protection
#   input.source_control.change_tracking
#   input.provenance.integrity_verification
#   input.provenance.artifacts_signed
#   input.release_management.releases_archived
#   input.release_management.sbom_generated
#   input.release_management.provenance_recorded
#
# OPA endpoint: POST /v1/data/nist_ssdf/ps/compliance_report

import rego.v1

default compliant := false

# One check per SP 800-218 task (1:1 with the standard's task IDs).
controls_evaluated := 4

# ── PS.1  Protect All Forms of Code from Unauthorized Access and Tampering ─────

violations contains msg if {
	not code_protected
	msg := "PS.1.1: Code is not protected from unauthorized access/tampering (require least-privilege repo access AND protected branches)"
}

code_protected if {
	input.source_control.access_controlled == true
	input.source_control.branch_protection == true
}

# ── PS.2  Provide a Mechanism for Verifying Software Release Integrity ─────────

violations contains msg if {
	not input.provenance.integrity_verification == true
	msg := "PS.2.1: No mechanism (hashes/signatures) is provided for consumers to verify release integrity"
}

# ── PS.3  Archive and Protect Each Software Release ────────────────────────────

violations contains msg if {
	not input.release_management.releases_archived == true
	msg := "PS.3.1: Software releases and their build inputs are not archived and protected"
}

violations contains msg if {
	not input.release_management.sbom_generated == true
	msg := "PS.3.2: An SBOM (provenance data) is not generated and retained for each release"
}

# ── Aggregate ─────────────────────────────────────────────────────────────────

compliant if {
	count(violations) == 0
}

compliance_report := {
	"practice_group": "PS — Protect the Software",
	"controls_evaluated": controls_evaluated,
	"violations": violations,
	"violation_count": count(violations),
	"compliant": compliant,
}
