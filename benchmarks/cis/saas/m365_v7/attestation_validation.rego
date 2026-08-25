# CIS Microsoft 365 Foundations Benchmark v7.0.0
# The ledger of controls this library does not evaluate
#
# An omitted control is indistinguishable from a passing one. These
# controls therefore still appear in the assessment -- as violations --
# until an operator attests to them with dated, attributed evidence.
#
# THREE DISTINCT CATEGORIES, deliberately not merged. Together with the
# section modules' evaluated ids they partition all 160 recommendations;
# scripts/check_cis_coverage.py fails CI if they ever stop doing so.
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
#   not_implemented       Known automatable -- our own analysis names the
#                         audit path -- but the collector does not make the
#                         call yet. This is OUR gap, not the platform's, and
#                         saying so is the difference between a backlog item
#                         and a limitation. Added 2026-08-25 after six
#                         controls were found in no category at all: not
#                         evaluated, not attested, not unresolved, and so
#                         absent from the report entirely.
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

# Automatable, but the collector does not make the call yet.
#
# Each entry names the audit path, so this reads as a work list rather
# than a disclaimer. Subjects are paraphrased from the shipped keyword
# digest -- CIS titles are not reproduced verbatim (see README).
NOT_IMPLEMENTED := {
	"1.2.2": {
		"subject": "sign-in to shared mailboxes is blocked",
		"collector": "Get-EXOMailbox -RecipientTypeDetails SharedMailbox, joined to the Entra accountEnabled flag; today the mailbox query selects only audit properties and /users selects only id and userPrincipalName",
	},
	"1.3.3": {
		"subject": "external sharing of calendars is not available",
		"collector": "Get-SharingPolicy via Exchange Online PowerShell; not among the nine cmdlets the collector runs",
	},
	"2.4.1": {
		"subject": "priority account protection is enabled and configured",
		"collector": "Defender priority-account configuration; the Defender collector reads only the anti-phish, anti-spam, malware, Safe Links and Safe Attachments policies",
	},
	"5.1.6.1": {
		"subject": "collaboration invitations are sent only to allowed domains",
		"collector": "the Graph B2B management policy carrying the invitation allow/block domain list; the Entra collector does not request it",
	},
	"5.3.4": {
		"subject": "approval is required to activate the Global Administrator role",
		"collector": "Graph PIM role-management policy rules; the Entra collector reads roleEligibilityScheduleInstances but not the policy rules that govern activation",
	},
	"5.3.5": {
		"subject": "approval is required to activate the Privileged Role Administrator role",
		"collector": "Graph PIM role-management policy rules, as for 5.3.4",
	},
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
	subject := object.get(REQUIRES_ATTESTATION, cid, object.get(UNRESOLVED, cid, object.get(NOT_IMPLEMENTED, [cid, "subject"], "control")))
	msg := sprintf("CIS %s: %s -- an attestation was supplied but is missing attested_by, attested_on or evidence_ref, so it is not admissible evidence (this is not a pass)", [cid, subject])
}

# ── Controls parked pending a live-tenant probe ───────────────────────
# Reported separately so they are never mistaken for verified limits.
violation contains msg if {
	some cid, subject in UNRESOLVED
	not cid in attested_ids
	msg := sprintf("CIS %s: %s -- collectability is unresolved pending a live-tenant probe; not yet evaluated (this is not a pass)", [cid, subject])
}

# ── Controls we know how to collect but have not built yet ────────────
# Stated as our own backlog, not as a platform limit. Before 2026-08-25
# these six were absent from the report altogether, which read as though
# the benchmark had 154 recommendations.
violation contains msg if {
	some cid, entry in NOT_IMPLEMENTED
	not cid in attested_ids
	msg := sprintf("CIS %s: %s -- automatable, but the collector does not make the call yet, so this control was not evaluated (this is not a pass)", [cid, entry.subject])
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
	"not_implemented": NOT_IMPLEMENTED,
	"not_implemented_count": count(NOT_IMPLEMENTED),
	"attested_control_ids": attested_ids,
	"attested_count": count(attested_ids),
	# Evidence provenance must survive into the report: an auditor has to
	# be able to tell a measured result from a human assertion.
	"evidence_source": "attested",
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
