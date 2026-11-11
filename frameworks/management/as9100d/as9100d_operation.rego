# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 8: Operation"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 33
#     cited: 30
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package as9100d.operation

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (9100:2016, built on ISO 9001:2015) — Clause 8: Operation.
#
# One row per clause or sub-clause. Clause numbers and short titles are public structure; every title and
# message here is our own description of the evidence that satisfies the clause. No text of AS9100D or
# ISO 9001 is reproduced (both are licensed). Sources, the evidence contract and the roll-up live in
# as9100d_main.rego. Query this clause alone at /v1/data/as9100d/operation/compliance_report.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported

clause := "8"

clause_name := "Operation"

items := {
	"8.1": {"title": "Operational planning and control — criteria, resources, documented information and controls for product and service provision are planned, including work transfers and outsourced processes", "kind": "attestation"},
	"8.1.1": {"title": "Operational risk management — a process assigns responsibility, defines risk criteria, identifies, assesses and mitigates risks that exceed criteria, and accepts residual risk", "kind": "attestation"},
	"8.1.2": {"title": "Configuration management — approved baselines are recorded, changes to them are controlled and status accounting (drift) records carry a disposition", "kind": "fact", "evidence": "configuration_management"},
	"8.1.3": {"title": "Product safety — hazards are assessed and managed across the product life cycle, with safety-critical items identified and communicated", "kind": "attestation"},
	"8.1.4": {"title": "Prevention of counterfeit parts — components carry documented provenance (SBOM or certificate of conformity) and come from approved sources", "kind": "fact", "evidence": "counterfeit_prevention"},
	"8.2.1": {"title": "Customer communication — product information, enquiries, contracts, feedback, customer property and contingency actions are communicated", "kind": "attestation"},
	"8.2.2": {"title": "Determining requirements — product and service requirements including statutory, regulatory, special and operational-risk requirements are defined", "kind": "attestation"},
	"8.2.3": {"title": "Review of requirements — requirements are reviewed before commitment, special requirements and critical items are identified and differences are resolved", "kind": "attestation"},
	"8.2.4": {"title": "Changes to requirements — amended documented information and awareness of changed requirements by relevant persons", "kind": "attestation"},
	"8.3.1": {"title": "Design and development — a process suitable for ensuring subsequent provision of products and services is established", "kind": "attestation"},
	"8.3.2": {"title": "Design and development planning — stages, reviews, verification and validation, authorities, interfaces and the division into elements are planned", "kind": "attestation"},
	"8.3.3": {"title": "Design and development inputs — functional, performance, statutory, regulatory and previous-design inputs are determined and conflicts resolved", "kind": "attestation"},
	"8.3.4": {"title": "Design and development controls — reviews, verification and validation are performed, with tests planned, witnessed and recorded against acceptance criteria", "kind": "attestation"},
	"8.3.5": {"title": "Design and development outputs — outputs meet inputs, define key characteristics and critical items and specify acceptance criteria and data for production", "kind": "attestation"},
	"8.3.6": {"title": "Design and development changes — changes are identified, reviewed, controlled, authorized and assessed for impact on delivered product", "kind": "attestation"},
	"8.4.1": {"title": "Control of external providers — an approved supplier list records each provider's approval status and scope, with controls set by the provider's effect on conformity", "kind": "fact", "evidence": "external_providers"},
	"8.4.2": {"title": "Type and extent of control — supplier performance is monitored and reviewed within the past year, verification activities are defined and risk is used to set controls", "kind": "fact", "evidence": "external_providers"},
	"8.4.3": {"title": "Information for external providers — requirements including flow-down of customer and QMS requirements are communicated and acknowledged by each provider", "kind": "fact", "evidence": "external_providers"},
	"8.5.1": {"title": "Control of production and service provision — provision runs under controlled conditions with documented information, monitoring, infrastructure, competence and release criteria", "kind": "attestation"},
	"8.5.1.1": {"title": "Control of equipment, tools and software programs — production equipment, tooling and software are validated before use and maintained in a known state", "kind": "fact", "evidence": "production_equipment"},
	"8.5.1.2": {"title": "Validation and control of special processes — processes whose output cannot be verified afterwards are qualified, with criteria, approved equipment, personnel and records", "kind": "attestation"},
	"8.5.1.3": {"title": "Production process verification — first article inspection confirms the process delivers conforming product and is repeated after process or design changes", "kind": "attestation"},
	"8.5.2": {"title": "Identification and traceability — each unit or batch carries a unique identifier and its lot or serial record, so configuration and history can be reconstructed", "kind": "fact", "evidence": "traceability"},
	"8.5.3": {"title": "Property of customers and external providers — such property is identified, verified, protected and safeguarded, with loss or damage reported", "kind": "attestation"},
	"8.5.4": {"title": "Preservation — outputs are preserved during production and provision, including cleaning, FOD prevention, handling, shelf life and marking", "kind": "attestation"},
	"8.5.5": {"title": "Post-delivery activities — warranty, maintenance, recycling, disposal and the collection of in-service data and problems are controlled", "kind": "attestation"},
	"8.5.6": {"title": "Control of changes — every production or service change record is reviewed for impact, approved by an authorized person and retained", "kind": "fact", "evidence": "change_control"},
	"8.6": {"title": "Release of products and services — planned verification is completed, release is authorized and evidence of conformity with release authority is retained", "kind": "attestation"},
	"8.7.1": {"title": "Control of nonconforming outputs — each nonconformance record carries a disposition, and use-as-is or repair dispositions carry customer authorization", "kind": "fact", "evidence": "nonconformance"},
	"8.7.2": {"title": "Nonconformity records — each record describes the nonconformity, the action taken and the authority that decided the disposition", "kind": "fact", "evidence": "nonconformance"},
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

# ── 8.1.2 Configuration management ───────────────────────────────────────────
# input.as9100d.configuration_management: {baselines: [{id, approved: bool, approved_by, approved_on}],
#   drift_records: [{baseline_id, detected_on, disposition}]}

_present("8.1.2") if is_array(input.as9100d.configuration_management.baselines)

_gaps["8.1.2"] contains "no configuration baseline is recorded" if {
	count(input.as9100d.configuration_management.baselines) == 0
}

_gaps["8.1.2"] contains r if {
	some b in input.as9100d.configuration_management.baselines
	not b.approved == true
	r := sprintf("baseline %v is not approved", [_label(b)])
}

_gaps["8.1.2"] contains r if {
	some b in input.as9100d.configuration_management.baselines
	b.approved == true
	not _str(b, "approved_by")
	r := sprintf("baseline %v records no approving authority", [_label(b)])
}

_gaps["8.1.2"] contains "no status-accounting (drift) records: configuration_management.drift_records must be a list" if {
	not is_array(object.get(input.as9100d.configuration_management, "drift_records", null))
}

_gaps["8.1.2"] contains r if {
	some d in input.as9100d.configuration_management.drift_records
	not _str(d, "disposition")
	r := sprintf("drift against baseline %v has no disposition", [object.get(d, "baseline_id", "<no baseline>")])
}

# ── 8.1.4 Prevention of counterfeit parts ────────────────────────────────────
# input.as9100d.counterfeit_prevention: {approved_sources: [string], components: [{id, source,
#   provenance_documented: bool}]}

_present("8.1.4") if is_array(input.as9100d.counterfeit_prevention.components)

_gaps["8.1.4"] contains "no components are recorded for provenance review" if {
	count(input.as9100d.counterfeit_prevention.components) == 0
}

_gaps["8.1.4"] contains "no approved-source list: counterfeit_prevention.approved_sources must be a list" if {
	not is_array(object.get(input.as9100d.counterfeit_prevention, "approved_sources", null))
}

_gaps["8.1.4"] contains r if {
	some c in input.as9100d.counterfeit_prevention.components
	not c.provenance_documented == true
	r := sprintf("component %v has no documented provenance (SBOM or certificate of conformity)", [_label(c)])
}

_gaps["8.1.4"] contains r if {
	is_array(input.as9100d.counterfeit_prevention.approved_sources)
	some c in input.as9100d.counterfeit_prevention.components
	not object.get(c, "source", null) in input.as9100d.counterfeit_prevention.approved_sources
	r := sprintf("component %v was obtained from %v, which is not an approved source", [_label(c), object.get(c, "source", "<no source>")])
}

# ── 8.4 Externally provided processes, products and services ─────────────────
# input.as9100d.external_providers: {suppliers: [{id, status: approved|conditional|..., scope,
#   performance_reviewed_on: date, flow_down_acknowledged: bool}]}

_approved_status := {"approved", "conditional"}

_present("8.4.1") if is_array(input.as9100d.external_providers.suppliers)

_gaps["8.4.1"] contains "the approved supplier list is empty" if {
	count(input.as9100d.external_providers.suppliers) == 0
}

_gaps["8.4.1"] contains r if {
	some s in input.as9100d.external_providers.suppliers
	not object.get(s, "status", null) in _approved_status
	r := sprintf("supplier %v has status %v, not approved or conditional", [_label(s), object.get(s, "status", "<none>")])
}

_gaps["8.4.1"] contains r if {
	some s in input.as9100d.external_providers.suppliers
	not _str(s, "scope")
	r := sprintf("supplier %v has no approved scope recorded", [_label(s)])
}

_present("8.4.2") if is_array(input.as9100d.external_providers.suppliers)

_gaps["8.4.2"] contains r if {
	some s in input.as9100d.external_providers.suppliers
	not _within_past_year(object.get(s, "performance_reviewed_on", null))
	r := sprintf("supplier %v has no performance review within the past year", [_label(s)])
}

_present("8.4.3") if is_array(input.as9100d.external_providers.suppliers)

_gaps["8.4.3"] contains r if {
	some s in input.as9100d.external_providers.suppliers
	not s.flow_down_acknowledged == true
	r := sprintf("supplier %v has not acknowledged the flowed-down requirements", [_label(s)])
}

# ── 8.5.1.1 Equipment, tools and software programs ───────────────────────────
# input.as9100d.production_equipment: [{id, type: equipment|tool|software, validated: bool, validated_on}]

_present("8.5.1.1") if is_array(input.as9100d.production_equipment)

_gaps["8.5.1.1"] contains "no production equipment, tooling or software is registered" if {
	count(input.as9100d.production_equipment) == 0
}

_gaps["8.5.1.1"] contains r if {
	some e in input.as9100d.production_equipment
	not e.validated == true
	r := sprintf("%v %v is not validated for use", [object.get(e, "type", "item"), _label(e)])
}

# ── 8.5.2 Identification and traceability ────────────────────────────────────
# input.as9100d.traceability: {items: [{id, part_number, serial | lot}]}

_present("8.5.2") if is_array(input.as9100d.traceability.items)

_gaps["8.5.2"] contains "no traceability records are present" if {
	count(input.as9100d.traceability.items) == 0
}

_gaps["8.5.2"] contains r if {
	some t in input.as9100d.traceability.items
	not _str(t, "id")
	r := sprintf("traceability record %v has no unique identifier", [t])
}

_gaps["8.5.2"] contains r if {
	some t in input.as9100d.traceability.items
	not _str(t, "serial")
	not _str(t, "lot")
	r := sprintf("item %v carries neither a serial nor a lot number", [_label(t)])
}

# ── 8.5.6 Control of changes ─────────────────────────────────────────────────
# input.as9100d.change_control: {records: [{id, approved: bool, approved_by, impact_reviewed: bool}]}

_present("8.5.6") if is_array(input.as9100d.change_control.records)

_gaps["8.5.6"] contains "no change records are present" if {
	count(input.as9100d.change_control.records) == 0
}

_gaps["8.5.6"] contains r if {
	some c in input.as9100d.change_control.records
	not c.approved == true
	r := sprintf("change %v is not approved", [_label(c)])
}

_gaps["8.5.6"] contains r if {
	some c in input.as9100d.change_control.records
	c.approved == true
	not _str(c, "approved_by")
	r := sprintf("change %v records no approving authority", [_label(c)])
}

_gaps["8.5.6"] contains r if {
	some c in input.as9100d.change_control.records
	not c.impact_reviewed == true
	r := sprintf("change %v has no review of its consequences", [_label(c)])
}

# ── 8.7 Control of nonconforming outputs ─────────────────────────────────────
# input.as9100d.nonconformance: {records: [{id, description, disposition, disposition_authority,
#   customer_authorized: bool}]}

_dispositions := {"rework", "repair", "use_as_is", "scrap", "return_to_supplier", "regrade", "correction"}

_customer_dispositions := {"use_as_is", "repair"}

_present("8.7.1") if is_array(input.as9100d.nonconformance.records)

_gaps["8.7.1"] contains "no nonconformance records are present" if {
	count(input.as9100d.nonconformance.records) == 0
}

_gaps["8.7.1"] contains r if {
	some n in input.as9100d.nonconformance.records
	not object.get(n, "disposition", null) in _dispositions
	r := sprintf("nonconformance %v has no recognized disposition (%v)", [_label(n), object.get(n, "disposition", "<none>")])
}

_gaps["8.7.1"] contains r if {
	some n in input.as9100d.nonconformance.records
	n.disposition in _customer_dispositions
	not n.customer_authorized == true
	r := sprintf("nonconformance %v is dispositioned %v without customer authorization", [_label(n), n.disposition])
}

_present("8.7.2") if is_array(input.as9100d.nonconformance.records)

_gaps["8.7.2"] contains r if {
	some n in input.as9100d.nonconformance.records
	not _str(n, "id")
	r := sprintf("nonconformance record %v has no identifier", [n])
}

_gaps["8.7.2"] contains r if {
	some n in input.as9100d.nonconformance.records
	not _str(n, "description")
	r := sprintf("nonconformance %v has no description", [_label(n)])
}

_gaps["8.7.2"] contains r if {
	some n in input.as9100d.nonconformance.records
	not _str(n, "disposition_authority")
	r := sprintf("nonconformance %v does not name the authority that decided the disposition", [_label(n)])
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
