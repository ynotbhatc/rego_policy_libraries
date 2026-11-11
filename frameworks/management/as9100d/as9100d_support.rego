# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 7: Support"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 16
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package as9100d.support

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (9100:2016, built on ISO 9001:2015) — Clause 7: Support.
#
# One row per clause or sub-clause. Clause numbers and short titles are public structure; every title and
# message here is our own description of the evidence that satisfies the clause. No text of AS9100D or
# ISO 9001 is reproduced (both are licensed). Sources, the evidence contract and the roll-up live in
# as9100d_main.rego. Query this clause alone at /v1/data/as9100d/support/compliance_report.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported

clause := "7"

clause_name := "Support"

items := {
	"7.1.1": {"title": "Resources — the resources needed to establish, maintain and improve the QMS are determined and provided, including those from external providers", "kind": "attestation"},
	"7.1.2": {"title": "People — the persons necessary for QMS operation and process control are provided", "kind": "attestation"},
	"7.1.3": {"title": "Infrastructure — buildings, equipment, transport and information technology needed for conforming output are determined, provided and maintained", "kind": "attestation"},
	"7.1.4": {"title": "Process environment — the social, psychological and physical conditions needed for conforming output are determined and maintained", "kind": "attestation"},
	"7.1.5.1": {"title": "Monitoring and measuring resources — a register of measuring equipment identifies each item, its suitability and its calibration schedule, and recall is managed", "kind": "fact", "evidence": "measuring_equipment"},
	"7.1.5.2": {"title": "Measurement traceability — in-service equipment is calibrated against traceable standards, its status is identified and no calibration is overdue", "kind": "fact", "evidence": "measuring_equipment"},
	"7.1.6": {"title": "Organizational knowledge — the knowledge needed to operate processes is maintained and additional knowledge needs are anticipated", "kind": "attestation"},
	"7.2": {"title": "Competence — competence needs are determined, met through education, training or experience, evaluated for effectiveness and evidenced in retained records", "kind": "attestation"},
	"7.3": {"title": "Awareness — persons know the policy, objectives, their contribution, the consequences of nonconformity, product safety and ethical behaviour expectations", "kind": "attestation"},
	"7.4": {"title": "Communication — internal and external communications relevant to the QMS are determined: what, when, with whom, how and by whom", "kind": "attestation"},
	"7.5.1": {"title": "Documented information — the information the standard requires and the organization needs for QMS effectiveness is maintained", "kind": "attestation"},
	"7.5.2": {"title": "Creating and updating — documents carry identification, format and media controls and are reviewed and approved for suitability", "kind": "attestation"},
	"7.5.3": {"title": "Control of documented information — availability, protection, distribution, access, change control, retention, disposition and the removal of obsolete documents are controlled, including external and customer-furnished information", "kind": "attestation"},
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

# ── 7.1.5 Monitoring and measuring resources ─────────────────────────────────
# input.as9100d.measuring_equipment: [{id, description, in_service: bool, calibration_due: date,
#   calibrated_on: date, traceable: bool}]

_present("7.1.5.1") if is_array(input.as9100d.measuring_equipment)

_gaps["7.1.5.1"] contains "the measuring-equipment register is empty" if {
	count(input.as9100d.measuring_equipment) == 0
}

_gaps["7.1.5.1"] contains r if {
	some e in input.as9100d.measuring_equipment
	not _str(e, "id")
	r := sprintf("register entry %v has no identifier", [e])
}

_gaps["7.1.5.1"] contains r if {
	some e in input.as9100d.measuring_equipment
	e.in_service == true
	not _str(e, "calibration_due")
	r := sprintf("in-service equipment %v has no calibration due date", [_label(e)])
}

_present("7.1.5.2") if is_array(input.as9100d.measuring_equipment)

_gaps["7.1.5.2"] contains r if {
	some e in input.as9100d.measuring_equipment
	e.in_service == true
	_in_past(e.calibration_due)
	r := sprintf("calibration of in-service equipment %v was due %v and is overdue", [_label(e), e.calibration_due])
}

_gaps["7.1.5.2"] contains r if {
	some e in input.as9100d.measuring_equipment
	e.in_service == true
	not e.traceable == true
	r := sprintf("in-service equipment %v has no traceability to a measurement standard recorded", [_label(e)])
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
