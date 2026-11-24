# METADATA
# title: "NIST SSDF (SP 800-218 v1.1) — Practice Group: Protect the Software (PS)"
# custom:
#   class: compliance
#   framework: nist_ssdf
#   source: nist
#   domains: [us-federal, secure-development]
#   coverage:
#     checks: 7
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist_ssdf.ps

# NIST SSDF (SP 800-218 v1.1) — Practice Group: Protect the Software (PS)
#
# Protects all components of the software from tampering and unauthorized access.
#
# Input contract (source-control / release posture — booleans):
#   input.source_control.access_controlled
#   input.source_control.branch_protection
#   input.source_control.change_tracking            (supporting fact, see below)
#   input.provenance.integrity_verification
#   input.provenance.artifacts_signed               (supporting fact)
#   input.release_management.releases_archived
#   input.release_management.sbom_generated
#   input.release_management.provenance_recorded    (supporting fact)
#
# Evidence rule (bad input never passes, issue #301): a check passes only on the boolean true. The three
# supporting facts do not decide a check when they are true, false or absent, but a supporting fact sent
# with the wrong type (the string "true", null, 1) is a collection error and fails the check it supports:
# the verdict never rests on mistyped evidence.
#
# OPA endpoint: POST /v1/data/nist_ssdf/ps/compliance_report

import rego.v1

default compliant := false

# One check per SP 800-218 task (1:1 with the standard's task IDs).
controls_evaluated := 4

# ── PS.1  Protect All Forms of Code from Unauthorized Access and Tampering ─────

violations contains msg if {
	not code_protected
	not _mistyped(["source_control", "change_tracking"])
	msg := "PS.1.1: Code is not protected from unauthorized access/tampering (require least-privilege repo access AND protected branches)"
}

violations contains msg if {
	_mistyped(["source_control", "change_tracking"])
	msg := sprintf("PS.1.1: Code protection cannot be attested — %s", [_invalid(["source_control", "change_tracking"])])
}

_absent := "__absent__"

_mistyped(path) if {
	value := object.get(input, path, _absent)
	value != _absent
	not is_boolean(value)
}

_invalid(path) := sprintf("evidence invalid: input.%s is not a boolean (got %s)", [concat(".", path), type_name(object.get(input, path, null))])

code_protected if {
	input.source_control.access_controlled == true
	input.source_control.branch_protection == true
}

# ── PS.2  Provide a Mechanism for Verifying Software Release Integrity ─────────

violations contains msg if {
	not input.provenance.integrity_verification == true
	not _mistyped(["provenance", "artifacts_signed"])
	msg := "PS.2.1: No mechanism (hashes/signatures) is provided for consumers to verify release integrity"
}

violations contains msg if {
	_mistyped(["provenance", "artifacts_signed"])
	msg := sprintf("PS.2.1: Release integrity verification cannot be attested — %s", [_invalid(["provenance", "artifacts_signed"])])
}

# ── PS.3  Archive and Protect Each Software Release ────────────────────────────

violations contains msg if {
	not input.release_management.releases_archived == true
	msg := "PS.3.1: Software releases and their build inputs are not archived and protected"
}

violations contains msg if {
	not input.release_management.sbom_generated == true
	not _mistyped(["release_management", "provenance_recorded"])
	msg := "PS.3.2: An SBOM (provenance data) is not generated and retained for each release"
}

violations contains msg if {
	_mistyped(["release_management", "provenance_recorded"])
	msg := sprintf("PS.3.2: Release provenance data cannot be attested — %s", [_invalid(["release_management", "provenance_recorded"])])
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
