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
#                       evidence is checked and every gap is reported

clause := "10"

clause_name := "Improvement"

items := {
	"10.1": {"title": "Improvement — opportunities to meet customer requirements and enhance satisfaction are determined and acted on", "kind": "attestation"},
	"10.2.1": {"title": "Nonconformity and corrective action — each corrective action record states the root cause, considers human factors and is closed or not yet overdue", "kind": "fact", "evidence": "corrective_actions"},
	"10.2.2": {"title": "Corrective action records — each record references its nonconformity and closed records show an effectiveness review", "kind": "fact", "evidence": "corrective_actions"},
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

# ── Reference date ───────────────────────────────────────────────────────────
# input.as9100d.as_of (RFC 3339 or YYYY-MM-DD) pins the evaluation date for reproducible reports; otherwise
# the evaluation clock is used. Repeated in every clause module that needs it because the product uploads
# one file at a time into an empty OPA server (scripts/check_per_file_load.py).

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

_within_past_year(d) if {
	is_string(d)
	_ns(d) <= _now_ns
	_now_ns - _ns(d) <= _year_ns
}

_in_past(d) if {
	is_string(d)
	_ns(d) < _now_ns
}

_label(x) := object.get(x, "id", "<no id>")

# Negated type tests on a possibly-missing key must go through object.get: `not is_string(x.k)` never fires
# when k is absent (the ref is undefined before the negation is evaluated).
_str(x, k) if is_string(object.get(x, k, null))

# ── 10.2 Nonconformity and corrective action ─────────────────────────────────
# input.as9100d.corrective_actions: {records: [{id, nonconformity_id, root_cause, human_factors_considered: bool,
#   status: open|closed, due_on: date, closed_on: date, effectiveness_reviewed: bool}]}

_present("10.2.1") if is_array(input.as9100d.corrective_actions.records)

_gaps["10.2.1"] contains "no corrective action records are present" if {
	count(input.as9100d.corrective_actions.records) == 0
}

_gaps["10.2.1"] contains r if {
	some c in input.as9100d.corrective_actions.records
	not _has_root_cause(c)
	r := sprintf("corrective action %v has no root cause recorded", [_label(c)])
}

_has_root_cause(c) if {
	is_string(c.root_cause)
	count(trim_space(c.root_cause)) > 0
}

_gaps["10.2.1"] contains r if {
	some c in input.as9100d.corrective_actions.records
	not c.human_factors_considered == true
	r := sprintf("corrective action %v does not record whether human factors were considered", [_label(c)])
}

_gaps["10.2.1"] contains r if {
	some c in input.as9100d.corrective_actions.records
	not object.get(c, "status", null) in {"open", "closed"}
	r := sprintf("corrective action %v has status %v, not open or closed", [_label(c), object.get(c, "status", "<none>")])
}

_gaps["10.2.1"] contains r if {
	some c in input.as9100d.corrective_actions.records
	c.status == "open"
	_in_past(c.due_on)
	r := sprintf("corrective action %v was due %v and is still open", [_label(c), c.due_on])
}

_present("10.2.2") if is_array(input.as9100d.corrective_actions.records)

_gaps["10.2.2"] contains r if {
	some c in input.as9100d.corrective_actions.records
	not _str(c, "nonconformity_id")
	r := sprintf("corrective action %v does not reference a nonconformity", [_label(c)])
}

_gaps["10.2.2"] contains r if {
	some c in input.as9100d.corrective_actions.records
	c.status == "closed"
	not c.effectiveness_reviewed == true
	r := sprintf("closed corrective action %v has no effectiveness review", [_label(c)])
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
