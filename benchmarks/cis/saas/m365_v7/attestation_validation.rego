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

# METADATA
# title: "CIS Microsoft 365 Foundations Benchmark v7.0.0"
# custom:
#   class: security
#   framework: cis_saas
#   source: cis
#   domains: [saas, m365]
#   coverage:
#     checks: 7
#     cited: 0
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
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
# EMPTY as of 2026-08-25. All six original entries -- 1.2.2, 1.3.3,
# 2.4.1, 5.1.6.1, 5.3.4, 5.3.5 -- were built and moved into their section
# modules. The bucket stays because the category is real and will recur:
# the next control we know how to collect but have not built belongs
# here, not in `unresolved`, which would understate what we know.
#
# Each entry names the audit path, so this reads as a work list rather
# than a disclaimer. Subjects are paraphrased from the shipped keyword
# digest -- CIS titles are not reproduced verbatim (see README).
#
#   "<id>": {"subject": "...", "collector": "the call that would close it"}
#
# Empty today. Built with object.union rather than the literal `{}`: OPA >= 1.22 types a literal empty object as having no members and rejects every
# iteration or index over it as an undefined ref, so the module fails to compile when
# loaded on its own (scripts/check_per_file_load.py).
NOT_IMPLEMENTED := object.union({}, {})

# Input: input.attestations[] - {control_id, observed, attested_by, attested_on, evidence_ref}
#
# An attestation is ADMISSIBLE when all of these hold:
#   control_id    is one of the ledger ids above (a control the library does not
#                 evaluate from evidence). An attestation for an evaluated id or
#                 an id the benchmark does not have is reported as a finding of
#                 its own and never changes any control's status.
#   observed      is a boolean: true attests that the requirement is met, false
#                 that it was checked and is NOT met (a failure, not a pass).
#   attested_by, evidence_ref  are non-empty strings.
#   attested_on   is a date, YYYY-MM-DD or an RFC 3339 timestamp, that is not in
#                 the future. The benchmark states no period after which an
#                 attestation lapses, so none is applied here.
# Several admissible attestations for one id: any observed false makes it fail.
default attestations := []

attestations := input.attestations if is_array(input.attestations)

_ledger_ids := (object.keys(REQUIRES_ATTESTATION) | object.keys(UNRESOLVED)) | object.keys(NOT_IMPLEMENTED)

# Each field must be a non-empty string. A bare `a.evidence_ref` in a rule
# body only fails on false or undefined, so null, "" and numbers used to
# count as evidence and the control read as attested.
_given(v) if {
	is_string(v)
	trim_space(v) != ""
}

# attested_on as nanoseconds since the epoch; undefined when it is not a date
_attested_ns(v) := time.parse_ns("2006-01-02", v) if {
	is_string(v)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, v)
}

_attested_ns(v) := time.parse_rfc3339_ns(v) if {
	is_string(v)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T`, v)
}

_future(a) if _attested_ns(a.attested_on) > time.now_ns()

_for_ledger(a) if {
	is_string(a.control_id)
	a.control_id in _ledger_ids
}

_admissible(a) if {
	_for_ledger(a)
	is_boolean(a.observed)
	_given(a.attested_by)
	_given(a.evidence_ref)
	is_number(_attested_ns(a.attested_on))
	not _future(a)
}

failed_ids := {a.control_id |
	some a in attestations
	_admissible(a)
	a.observed == false
}

attested_ids := {a.control_id |
	some a in attestations
	_admissible(a)
	a.observed == true
	not a.control_id in failed_ids
}

# a ledger control an admissible attestation decided, either way
_decided_ids := attested_ids | failed_ids

# A ledger attestation missing any of who/when/evidence/observed, or with a
# date that is not a date, is not an attestation.
incomplete_ids := {a.control_id |
	some a in attestations
	_for_ledger(a)
	not _admissible(a)
	not _future(a)
	not a.control_id in _decided_ids
}

future_ids := {a.control_id |
	some a in attestations
	_for_ledger(a)
	_future(a)
	not a.control_id in _decided_ids
}

_subject(cid) := object.get(REQUIRES_ATTESTATION, cid, object.get(UNRESOLVED, cid, object.get(NOT_IMPLEMENTED, [cid, "subject"], "control")))

# ── Attested as not met ───────────────────────────────────────────────
# Not an evidence gap: the operator checked and recorded a failure.
violation contains msg if {
	some a in attestations
	_admissible(a)
	a.observed == false
	msg := sprintf("CIS %s: %s -- attested as not met (observed false) by %s on %s, evidence %s", [a.control_id, _subject(a.control_id), a.attested_by, a.attested_on, a.evidence_ref])
}

# ── Un-attested controls that genuinely cannot be collected ───────────
violation contains msg if {
	some cid, subject in REQUIRES_ATTESTATION
	not cid in _decided_ids
	msg := sprintf("CIS %s: %s -- no app-only read path exists, so this control requires operator attestation and none has been recorded (this is not a pass)", [cid, subject])
}

violation contains msg if {
	some cid in incomplete_ids
	msg := sprintf("CIS %s: %s -- an attestation was supplied but is missing observed (true or false), attested_by, evidence_ref or a valid attested_on date (YYYY-MM-DD), so it is not admissible evidence (this is not a pass)", [cid, _subject(cid)])
}

violation contains msg if {
	some cid in future_ids
	msg := sprintf("CIS %s: %s -- the attestation is dated in the future, so it is not admissible evidence (this is not a pass)", [cid, _subject(cid)])
}

# An attestation for a control the library evaluates from evidence, or for an
# id the ledger does not hold, decides nothing. It is reported without a "CIS
# <id>:" prefix (it starts "ignored attestation:") so no tool attributes it to
# that control's result.
violation contains msg if {
	some a in attestations
	not _for_ledger(a)
	msg := sprintf("ignored attestation: the attestation for control_id '%v' decides nothing -- attestations are accepted only for the %d ledger controls this library cannot evaluate from collected evidence; it does not change any control's status", [object.get(a, "control_id", null), count(_ledger_ids)])
}

# ── Controls parked pending a live-tenant probe ───────────────────────
# Reported separately so they are never mistaken for verified limits.
violation contains msg if {
	some cid, subject in UNRESOLVED
	not cid in _decided_ids
	msg := sprintf("CIS %s: %s -- collectability is unresolved pending a live-tenant probe; not yet evaluated (this is not a pass)", [cid, subject])
}

# ── Controls we know how to collect but have not built yet ────────────
# Stated as our own backlog, not as a platform limit. Before 2026-08-25
# these six were absent from the report altogether, which read as though
# the benchmark had 154 recommendations.
violation contains msg if {
	some cid, entry in NOT_IMPLEMENTED
	not cid in _decided_ids
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
	# admissible attestations that record the requirement as not met
	"attested_failed_control_ids": failed_ids,
	# Evidence provenance must survive into the report: an auditor has to
	# be able to tell a measured result from a human assertion.
	"evidence_source": "attested",
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
