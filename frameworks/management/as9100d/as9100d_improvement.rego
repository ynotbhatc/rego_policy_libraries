# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 10: Improvement"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 7
#     cited: 4
#     density: section
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package as9100d.improvement

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (9100:2016, built on ISO 9001:2015) — Clause 10: Improvement.
#
# One row per clause or sub-clause. Clause numbers and short titles are public structure; every title and
# message here is our own description of the evidence that satisfies the clause. No text of AS9100D or
# ISO 9001 is reproduced (both are licensed). Sources, the evidence contract and the roll-up live in
# as9100d_main.rego. Query this clause alone at /v1/data/as9100d/improvement/compliance_report.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported. A required field that is absent, null,
#                       blank, of the wrong type or (for dates) unparseable is evidence missing: the row fails
#                       and the violation names the field.

clause := "10"

clause_name := "Improvement"

items := {
	"10.1": {"title": "Improvement — opportunities to meet customer requirements and enhance satisfaction are determined and acted on", "kind": "attestation"},
	"10.2.1": {"title": "Nonconformity and corrective action — each corrective action record states the root cause, considers human factors and is closed on a recorded date or open with a due date that has not passed", "kind": "fact", "evidence": "corrective_actions"},
	"10.2.2": {"title": "Corrective action records — each record carries a unique identifier, references its nonconformity, and closed records show an effectiveness review", "kind": "fact", "evidence": "corrective_actions"},
	"10.3": {"title": "Continual improvement — the suitability, adequacy and effectiveness of the QMS are improved using analysis, evaluation and review outputs", "kind": "attestation"},
}

default compliant := false

compliant if {
	count(violations) == 0
}

_attested(id) if input.as9100d.attestations[id] == true

violations contains msg if {
	some id, it in items
	it.kind == "attestation"
	not _attested(id)
	msg := sprintf("AS9100D %s: %s — not attested: input.as9100d.attestations[%q] is not true", [id, it.title, id])
}

passed contains id if {
	some id, it in items
	it.kind == "attestation"
	_attested(id)
}

# ── Reference date and field tests ───────────────────────────────────────────
# input.as9100d.as_of (RFC 3339 or YYYY-MM-DD) pins the evaluation date for reproducible reports; otherwise
# the evaluation clock is used. "Within the past year" is a rolling 365-day window ending on that date, not a
# calendar or fiscal year. Repeated in every clause module that needs it because the product uploads one file
# at a time into an empty OPA server (scripts/check_per_file_load.py).

_now_ns := time.parse_rfc3339_ns(_rfc3339(input.as9100d.as_of)) if input.as9100d.as_of

_now_ns := time.now_ns() if not input.as9100d.as_of

_rfc3339(d) := concat("", [d, "T00:00:00Z"]) if {
	is_string(d)
	count(d) == 10
}

_rfc3339(d) := d if {
	is_string(d)
	count(d) != 10
}

_ns(d) := time.parse_rfc3339_ns(_rfc3339(d))

_year_ns := ((365 * 24) * 3600) * 1000000000

# A date is valid only when it is a string that parses. A parse failure leaves _ns undefined, so every date test
# is false for an absent, null, non-string or unparseable value and the row reports the gap instead of passing.
_date(d) if {
	is_string(d)
	is_number(_ns(d))
}

_within_past_year(d) if {
	_date(d)
	_ns(d) <= _now_ns
	_now_ns - _ns(d) <= _year_ns
}

_in_past(d) if {
	_date(d)
	_ns(d) < _now_ns
}

_not_future(d) if {
	_date(d)
	_ns(d) <= _now_ns
}

_label(x) := x.id if _text(x, "id")

_label(x) := "<no id>" if not _text(x, "id")

# Field tests go through object.get: `not is_string(x.k)` never fires when k is absent (the ref is undefined
# before the negation is evaluated). A required text field is a non-blank string, a required date parses and a
# required flag is a boolean; anything else is evidence missing and the row fails naming the field.
_text(x, k) if {
	v := object.get(x, k, null)
	is_string(v)
	count(trim_space(v)) > 0
}

_has_date(x, k) if _date(object.get(x, k, null))

_bool(x, k) if is_boolean(object.get(x, k, null))

_shown(x, k) := object.get(x, k, "<missing>")

# Identifiers used by more than one record of a list.
_dup_ids(xs) := {id |
	some i, a in xs
	id := object.get(a, "id", null)
	is_string(id)
	some j, b in xs
	i != j
	object.get(b, "id", null) == id
}

# ── 10.2 Nonconformity and corrective action ─────────────────────────────────
# input.as9100d.corrective_actions: {records: [{id, nonconformity_id, root_cause, human_factors_considered: bool,
#   status: open|closed, due_on: date, closed_on: date, effectiveness_reviewed: bool}], none_occurred: bool}
# At least one record is required. A period with no corrective actions is declared, never implied: records: []
# passes a row only with corrective_actions.none_occurred: true AND that row attested
# (attestations["10.2.1"] / attestations["10.2.2"] == true). none_occurred alongside records is a contradiction
# and fails both rows. Every record needs a unique non-blank id, a nonconformity_id, a root cause, human factors
# considered and a status of open or closed; an open record needs a due_on that parses and has not passed, a
# closed record a closed_on that parses and is not in the future, plus an effectiveness review.

_cas := input.as9100d.corrective_actions.records

_ca_none_declared if input.as9100d.corrective_actions.none_occurred == true

# The gap an empty or contradicted list produces for row id, if any.
_ca_list_gap(id) := r if {
	count(_cas) == 0
	not _ca_none_declared
	r := sprintf("no corrective action records are present — if none were raised in the period, set corrective_actions.none_occurred: true and attest %s", [id])
}

_ca_list_gap(id) := r if {
	count(_cas) == 0
	_ca_none_declared
	not _attested(id)
	r := sprintf("corrective_actions.none_occurred is true but the declaration is not attested (attestations[%q] must be true)", [id])
}

_ca_list_gap(id) := r if {
	count(_cas) > 0
	_ca_none_declared
	r := sprintf("corrective_actions.none_occurred is true but %d records are present — the declaration contradicts the evidence (row %s)", [count(_cas), id])
}

_present("10.2.1") if is_array(_cas)

_gaps["10.2.1"] contains r if r := _ca_list_gap("10.2.1")

_gaps["10.2.1"] contains r if {
	some c in _cas
	not _text(c, "root_cause")
	r := sprintf("corrective action %v has no root cause recorded (root_cause must be a non-blank string)", [_label(c)])
}

_gaps["10.2.1"] contains r if {
	some c in _cas
	not c.human_factors_considered == true
	r := sprintf("corrective action %v does not record whether human factors were considered (human_factors_considered must be true)", [_label(c)])
}

_gaps["10.2.1"] contains r if {
	some c in _cas
	not object.get(c, "status", null) in {"open", "closed"}
	r := sprintf("corrective action %v has status %v, not open or closed", [_label(c), _shown(c, "status")])
}

_gaps["10.2.1"] contains r if {
	some c in _cas
	c.status == "open"
	not _has_date(c, "due_on")
	r := sprintf("open corrective action %v has no due date that parses (due_on: %v)", [_label(c), _shown(c, "due_on")])
}

_gaps["10.2.1"] contains r if {
	some c in _cas
	c.status == "open"
	_in_past(c.due_on)
	r := sprintf("corrective action %v was due %v and is still open", [_label(c), c.due_on])
}

_gaps["10.2.1"] contains r if {
	some c in _cas
	c.status == "closed"
	not _has_date(c, "closed_on")
	r := sprintf("closed corrective action %v has no closure date that parses (closed_on: %v)", [_label(c), _shown(c, "closed_on")])
}

_gaps["10.2.1"] contains r if {
	some c in _cas
	c.status == "closed"
	_has_date(c, "closed_on")
	not _not_future(c.closed_on)
	r := sprintf("corrective action %v records a closure date in the future (closed_on: %v)", [_label(c), c.closed_on])
}

_present("10.2.2") if is_array(_cas)

_gaps["10.2.2"] contains r if r := _ca_list_gap("10.2.2")

_gaps["10.2.2"] contains r if {
	some c in _cas
	not _text(c, "id")
	r := sprintf("corrective action record %v has no identifier (id must be a non-blank string)", [c])
}

_gaps["10.2.2"] contains r if {
	some id in _dup_ids(_cas)
	r := sprintf("identifier %v is used by more than one corrective action record (ids must be unique)", [id])
}

_gaps["10.2.2"] contains r if {
	some c in _cas
	not _text(c, "nonconformity_id")
	r := sprintf("corrective action %v does not reference a nonconformity (nonconformity_id must be a non-blank string)", [_label(c)])
}

_gaps["10.2.2"] contains r if {
	some c in _cas
	c.status == "closed"
	not c.effectiveness_reviewed == true
	r := sprintf("closed corrective action %v has no effectiveness review (effectiveness_reviewed must be true)", [_label(c)])
}

violations contains msg if {
	some id, it in items
	it.kind == "fact"
	not _present(id)
	msg := sprintf("AS9100D %s: %s — FAIL-CLOSED: no evidence at input.as9100d.%s", [id, it.title, it.evidence])
}

violations contains msg if {
	some id, it in items
	it.kind == "fact"
	_present(id)
	some r in _gaps[id]
	msg := sprintf("AS9100D %s: %s — %s", [id, it.title, r])
}

_has_gap(id) if {
	some _ in _gaps[id]
}

passed contains id if {
	some id, it in items
	it.kind == "fact"
	_present(id)
	not _has_gap(id)
}

fact_evaluated := count({id | some id, it in items; it.kind == "fact"; _present(id)})

compliance_report := {
	"framework": "SAE AS9100D (9100:2016)",
	"clause": clause,
	"name": clause_name,
	"total": count(items),
	"attestation_items": count({id | some id, it in items; it.kind == "attestation"}),
	"fact_items": count({id | some id, it in items; it.kind == "fact"}),
	"passed": count(passed),
	"failed": count(items) - count(passed),
	"attested": count({id | some id in passed; items[id].kind == "attestation"}),
	"fact_evaluated": fact_evaluated,
	"fact_passed": count({id | some id in passed; items[id].kind == "fact"}),
	"gaps": sort([id | some id, _ in items; not id in passed]),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
