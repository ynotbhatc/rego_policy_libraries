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
# Clause 9.1.2 is one row decided two ways: the on-time delivery and conformity KPIs are evidence (kpis) and
# customer feedback, complaints and corrective-action requests, which no collector produces, are attested under
# the same clause id (attestations["9.1.2"]). The row fails without either. Every row id is a clause number.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported. A required field that is absent, null,
#                       blank, of the wrong type or (for dates) unparseable is evidence missing: the row fails
#                       and the violation names the field.

clause := "9"

clause_name := "Performance evaluation"

items := {
	"9.1.1": {"title": "Monitoring and measurement — what is monitored, the methods, the timing and the evaluation of results are determined and QMS performance is evaluated", "kind": "attestation"},
	"9.1.2": {"title": "Customer satisfaction — on-time delivery and product conformity are measured for a period ending within the past year, each against a numeric target that the measured value meets, and customer feedback, complaints and corrective-action requests are attested as collected, monitored and acted on", "kind": "fact", "evidence": "kpis"},
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

# ── Reference date and field tests ───────────────────────────────────────────
# input.as9100d.as_of (RFC 3339 or YYYY-MM-DD) pins the evaluation date for reproducible reports; otherwise
# the evaluation clock is used. "Within the past year" is the twelve months ending on that date: the same
# calendar date one year earlier is the earliest that counts (time.add_date, so a February 29 anchor falls back
# to March 1). It is not a fiscal year and not a count of days. Repeated in every clause module that needs it because the product uploads one file
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

_year_ago_ns := time.add_date(_now_ns, -1, 0, 0)

# A date is valid only when it is a string that parses. A parse failure leaves _ns undefined, so every date test
# is false for an absent, null, non-string or unparseable value and the row reports the gap instead of passing.
_date(d) if {
	is_string(d)
	is_number(_ns(d))
}

_within_past_year(d) if {
	_date(d)
	_ns(d) <= _now_ns
	_ns(d) >= _year_ago_ns
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

# ── 9.1.2 Customer satisfaction — on-time delivery and conformity KPIs ───────
# input.as9100d.kpis: {on_time_delivery: {value: number, target: number, period_end: date},
#   conformity: {value: number, target: number, period_end: date}}
# Each KPI needs a numeric value, a numeric target (a KPI without a target is unmeasured, not passing) and a
# period_end that parses and lies within the past year; the value must meet the target.

_kpis := {"on_time_delivery", "conformity"}

_kpi(k, f) := object.get(input.as9100d.kpis, [k, f], null)

_present("9.1.2") if is_object(input.as9100d.kpis)

_gaps["9.1.2"] contains r if {
	some k in _kpis
	not is_number(_kpi(k, "value"))
	r := sprintf("%v is not measured (kpis.%v.value must be a number, got %v)", [k, k, _kpi(k, "value")])
}

_gaps["9.1.2"] contains r if {
	some k in _kpis
	not is_number(_kpi(k, "target"))
	r := sprintf("%v has no target (kpis.%v.target must be a number, got %v)", [k, k, _kpi(k, "target")])
}

_gaps["9.1.2"] contains r if {
	some k in _kpis
	v := _kpi(k, "value")
	is_number(v)
	t := _kpi(k, "target")
	is_number(t)
	v < t
	r := sprintf("%v is %v against a target of %v", [k, v, t])
}

_gaps["9.1.2"] contains r if {
	some k in _kpis
	not _within_past_year(_kpi(k, "period_end"))
	r := sprintf("%v has no measurement period ending within the past year (kpis.%v.period_end: %v)", [k, k, _kpi(k, "period_end")])
}

# Customer feedback, complaints and corrective-action requests have no collector, so the organization attests
# them under the clause's own id. Without that attestation the row fails even when every KPI meets its target.
_gaps["9.1.2"] contains "customer feedback, complaints and corrective-action requests are not attested as collected, monitored and acted on (input.as9100d.attestations[\"9.1.2\"] must be true)" if {
	not _attested("9.1.2")
}

# ── 9.2 Internal audit ───────────────────────────────────────────────────────
# input.as9100d.internal_audit: {programme: {planned: [{id, scope, scheduled_on}]},
#   audits: [{id, completed_on: date, report_issued: bool}]}

_present("9.2.1") if is_array(input.as9100d.internal_audit.audits)

_recent_audits contains a if {
	some a in input.as9100d.internal_audit.audits
	_within_past_year(object.get(a, "completed_on", null))
}

_gaps["9.2.1"] contains "no internal audit was completed within the past year (internal_audit.audits[].completed_on must be a date in the twelve months ending on as_of)" if {
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
	not _text(p, "scope")
	r := sprintf("planned audit %v has no scope", [_label(p)])
}

_gaps["9.2.2"] contains r if {
	some p in input.as9100d.internal_audit.programme.planned
	not _has_date(p, "scheduled_on")
	r := sprintf("planned audit %v has no scheduled date that parses (scheduled_on: %v)", [_label(p), _shown(p, "scheduled_on")])
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
	_within_past_year(object.get(m, "held_on", null))
}

_gaps["9.3.1"] contains "no management review was held within the past year (management_review.reviews[].held_on must be a date in the twelve months ending on as_of)" if {
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
