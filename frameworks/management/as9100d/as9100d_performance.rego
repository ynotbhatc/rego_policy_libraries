# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 9: Performance evaluation"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 11
#     cited: 8
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package as9100d.performance

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (9100:2016, built on ISO 9001:2015) — Clause 9: Performance evaluation.
#
# One row per clause or sub-clause. Clause numbers and short titles are public structure; every title and
# message here is our own description of the evidence that satisfies the clause. No text of AS9100D or
# ISO 9001 is reproduced (both are licensed). Sources, the evidence contract and the roll-up live in
# as9100d_main.rego. Query this clause alone at /v1/data/as9100d/performance/compliance_report.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported

clause := "9"

clause_name := "Performance evaluation"

items := {
	"9.1.1": {"title": "Monitoring and measurement — what is monitored, the methods, the timing and the evaluation of results are determined and QMS performance is evaluated", "kind": "attestation"},
	"9.1.2": {"title": "Customer satisfaction — on-time delivery and product conformity are measured for the current period and compared with their targets", "kind": "fact", "evidence": "kpis"},
	"9.1.3": {"title": "Analysis and evaluation — data on conformity, satisfaction, performance, planning, risk actions, suppliers and improvement needs is analysed", "kind": "attestation"},
	"9.2.1": {"title": "Internal audit — at least one internal audit of the QMS has been completed within the past year", "kind": "fact", "evidence": "internal_audit"},
	"9.2.2": {"title": "Audit programme — audits are planned with scope and criteria, results are reported to management and corrections follow", "kind": "fact", "evidence": "internal_audit"},
	"9.3.1": {"title": "Management review — top management has reviewed the QMS within the past year", "kind": "fact", "evidence": "management_review"},
	"9.3.2": {"title": "Management review inputs — status of actions, changes, performance trends, resource adequacy, risk actions and on-time delivery are considered", "kind": "attestation"},
	"9.3.3": {"title": "Management review outputs — decisions on improvement, QMS changes and resource needs are recorded and retained", "kind": "attestation"},
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

# ── 9.1.2 On-time delivery and conformity ────────────────────────────────────
# input.as9100d.kpis: {on_time_delivery: {value: number, target: number, period_end: date},
#   conformity: {value, target, period_end}}

_kpis := {"on_time_delivery", "conformity"}

_present("9.1.2") if is_object(input.as9100d.kpis)

_gaps["9.1.2"] contains r if {
	some k in _kpis
	not is_number(object.get(input.as9100d.kpis, [k, "value"], null))
	r := sprintf("%v is not measured (kpis.%v.value is not a number)", [k, k])
}

_gaps["9.1.2"] contains r if {
	some k in _kpis
	v := input.as9100d.kpis[k].value
	is_number(v)
	t := input.as9100d.kpis[k].target
	is_number(t)
	v < t
	r := sprintf("%v is %v against a target of %v", [k, v, t])
}

_gaps["9.1.2"] contains r if {
	some k in _kpis
	is_number(input.as9100d.kpis[k].value)
	not _within_past_year(object.get(input.as9100d.kpis, [k, "period_end"], null))
	r := sprintf("%v has no measurement period ending within the past year", [k])
}

# ── 9.2 Internal audit ───────────────────────────────────────────────────────
# input.as9100d.internal_audit: {programme: {planned: [{id, scope, scheduled_on}]},
#   audits: [{id, completed_on: date, report_issued: bool}]}

_present("9.2.1") if is_array(input.as9100d.internal_audit.audits)

_recent_audits contains a.id if {
	some a in input.as9100d.internal_audit.audits
	_within_past_year(a.completed_on)
}

_gaps["9.2.1"] contains "no internal audit was completed within the past year" if {
	count(_recent_audits) == 0
}

_present("9.2.2") if is_object(input.as9100d.internal_audit)

_gaps["9.2.2"] contains "the audit programme has no planned audits (internal_audit.programme.planned)" if {
	not is_array(object.get(input.as9100d.internal_audit, ["programme", "planned"], null))
}

_gaps["9.2.2"] contains "the audit programme has no planned audits (internal_audit.programme.planned)" if {
	count(input.as9100d.internal_audit.programme.planned) == 0
}

_gaps["9.2.2"] contains r if {
	some p in input.as9100d.internal_audit.programme.planned
	not _str(p, "scope")
	r := sprintf("planned audit %v has no scope", [_label(p)])
}

_gaps["9.2.2"] contains r if {
	some a in input.as9100d.internal_audit.audits
	not a.report_issued == true
	r := sprintf("audit %v has no report issued to management", [_label(a)])
}

# ── 9.3 Management review ────────────────────────────────────────────────────
# input.as9100d.management_review: {reviews: [{held_on: date, outputs_recorded: bool}]}

_present("9.3.1") if is_array(input.as9100d.management_review.reviews)

_recent_reviews contains m if {
	some m in input.as9100d.management_review.reviews
	_within_past_year(m.held_on)
}

_gaps["9.3.1"] contains "no management review was held within the past year" if {
	count(_recent_reviews) == 0
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
