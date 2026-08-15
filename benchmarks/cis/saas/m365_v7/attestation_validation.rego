# CIS Microsoft 365 Foundations Benchmark v7.0.0
# Controls that no collector can establish
#
# An omitted control is indistinguishable from a passing one. These
# controls therefore still appear in the assessment -- as violations --
# until an operator attests to them with dated, attributed evidence.
#
# TWO DISTINCT CATEGORIES, deliberately not merged:
#
#   requires_attestation  Verified to have no app-only read path. Either no
#                         API exists at all (the SSPR settings), or the API
#                         is delegated-only and cannot run unattended
#                         (5.1.2.4). These will never be collectable under
#                         the current execution model.
#
#   unresolved            Not yet checked against a live tenant. These are
#                         NOT known limits -- several may well be
#                         collectable. They are parked pending a live-tenant
#                         probe during the POC. Reporting them as
#                         "requires attestation" would overstate the limit.
#
# See docs/m365/CIS_M365_V7_AUTOMATION_LIMITS.md in the compliance repo for
# how each was established.
#
# Input contract:
#   input.attestations[] - {control_id, observed, attested_by,
#                           attested_on, evidence_ref}

package cis_m365_v7.attestation

import rego.v1

default compliant := false

# Verified: no app-only read path exists.
REQUIRES_ATTESTATION := {
	"5.2.4.1": "self-service password reset enabled for all users",
	"5.2.4.2": "two methods required for password reset",
	"5.2.4.3": "SSPR registration and re-confirmation configured",
	"5.2.4.4": "users notified on password resets",
	"5.2.4.5": "admins notified when other admins reset a password",
	"5.1.2.4": "access to the Entra admin center restricted",
}

# Parked pending a live-tenant probe. Not claimed as limits.
UNRESOLVED := {
	"1.1.2": "emergency access accounts defined",
	"1.3.8": "Sways cannot be shared outside the organization",
	"2.2.1": "emergency access account activity monitored",
	"2.4.3": "Defender for Cloud Apps enabled",
	"2.4.5": "AIR remediation enabled",
	"5.1.2.5": "the option to remain signed in is hidden",
	"5.1.2.6": "LinkedIn account connections disabled",
	"5.1.3.2": "user ability to access groups features restricted",
	"5.1.3.3": "owners can manage group membership requests",
	"8.4.1": "app permission policies configured",
}

attestations := object.get(input, "attestations", [])

attested_ids := {a.control_id |
	some a in attestations
	a.attested_by
	a.attested_on
	a.evidence_ref
}

# An attestation missing any of who/when/evidence is not an attestation.
incomplete_ids := {a.control_id |
	some a in attestations
	not a.control_id in attested_ids
}

# ── Un-attested controls that genuinely cannot be collected ───────────
violation contains msg if {
	some cid, subject in REQUIRES_ATTESTATION
	not cid in attested_ids
	msg := sprintf("CIS %s: %s -- no app-only read path exists, so this control requires operator attestation and none has been recorded (this is not a pass)", [cid, subject])
}

violation contains msg if {
	some cid in incomplete_ids
	subject := object.get(REQUIRES_ATTESTATION, cid, object.get(UNRESOLVED, cid, "control"))
	msg := sprintf("CIS %s: %s -- an attestation was supplied but is missing attested_by, attested_on or evidence_ref, so it is not admissible evidence (this is not a pass)", [cid, subject])
}

# ── Controls parked pending a live-tenant probe ───────────────────────
# Reported separately so they are never mistaken for verified limits.
violation contains msg if {
	some cid, subject in UNRESOLVED
	not cid in attested_ids
	msg := sprintf("CIS %s: %s -- collectability is unresolved pending a live-tenant probe; not yet evaluated (this is not a pass)", [cid, subject])
}

compliant if {
	count(violation) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"section": "attestation",
	"name": "Controls with no collector path",
	"requires_attestation": REQUIRES_ATTESTATION,
	"requires_attestation_count": count(REQUIRES_ATTESTATION),
	"unresolved": UNRESOLVED,
	"unresolved_count": count(UNRESOLVED),
	"attested_control_ids": attested_ids,
	"attested_count": count(attested_ids),
	# Evidence provenance must survive into the report: an auditor has to
	# be able to tell a measured result from a human assertion.
	"evidence_source": "attested",
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
