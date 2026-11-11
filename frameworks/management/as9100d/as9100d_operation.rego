# METADATA
# title: "SAE AS9100D (9100:2016) — Clause 8: Operation"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 34
#     cited: 31
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
# Grouping. 8.2.3.1 and 8.2.3.2 are decided under their parent row 8.2.3; 8.3.4.1 (aerospace verification and
# validation testing) is its own row because it is an aerospace addition with evidence of its own.
#
# kind: attestation  -> input.as9100d.attestations["<id>"] == true (anything else is a violation)
# kind: fact         -> evidence under input.as9100d.<evidence>; missing evidence is FAIL-CLOSED, present
#                       evidence is checked and every gap is reported. A required field that is absent, null,
#                       blank, of the wrong type or (for dates) unparseable is evidence missing: the row fails
#                       and the violation names the field.

clause := "8"

clause_name := "Operation"

items := {
	"8.1": {"title": "Operational planning and control — criteria, resources, documented information and controls for product and service provision are planned, including work transfers and outsourced processes", "kind": "attestation"},
	"8.1.1": {"title": "Operational risk management — a process assigns responsibility, defines risk criteria, identifies, assesses and mitigates risks that exceed criteria, and accepts residual risk", "kind": "attestation"},
	"8.1.2": {"title": "Configuration management — approved baselines are recorded with an identified approver and date, changes to them are controlled and status accounting (drift) records name their baseline and carry a disposition", "kind": "fact", "evidence": "configuration_management"},
	"8.1.3": {"title": "Product safety — hazards are assessed and managed across the product life cycle, with safety-critical items identified and communicated", "kind": "attestation"},
	"8.1.4": {"title": "Prevention of counterfeit parts — components carry documented provenance (SBOM or certificate of conformity) and come from approved sources", "kind": "fact", "evidence": "counterfeit_prevention"},
	"8.2.1": {"title": "Customer communication — product information, enquiries, contracts, feedback, customer property and contingency actions are communicated", "kind": "attestation"},
	"8.2.2": {"title": "Determining requirements — product and service requirements including statutory, regulatory, special and operational-risk requirements are defined", "kind": "attestation"},
	"8.2.3": {"title": "Review of requirements (8.2.3.1 and 8.2.3.2) — requirements are reviewed before commitment, special requirements and critical items are identified, differences are resolved and the review is recorded", "kind": "attestation"},
	"8.2.4": {"title": "Changes to requirements — amended documented information and awareness of changed requirements by relevant persons", "kind": "attestation"},
	"8.3.1": {"title": "Design and development — a process suitable for ensuring subsequent provision of products and services is established", "kind": "attestation"},
	"8.3.2": {"title": "Design and development planning — stages, reviews, verification and validation, authorities, interfaces and the division into elements are planned", "kind": "attestation"},
	"8.3.3": {"title": "Design and development inputs — functional, performance, statutory, regulatory and previous-design inputs are determined and conflicts resolved", "kind": "attestation"},
	"8.3.4": {"title": "Design and development controls — reviews, verification and validation are performed at the planned stages, problems are resolved and the results are retained", "kind": "attestation"},
	"8.3.4.1": {"title": "Design and development verification and validation testing — tests are planned and reviewed, run against defined criteria on the configuration under test, witnessed where required and recorded with their results (aerospace addition)", "kind": "attestation"},
	"8.3.5": {"title": "Design and development outputs — outputs meet inputs, define key characteristics and critical items and specify acceptance criteria and data for production", "kind": "attestation"},
	"8.3.6": {"title": "Design and development changes — changes are identified, reviewed, controlled, authorized and assessed for impact on delivered product", "kind": "attestation"},
	"8.4.1": {"title": "Control of external providers — an approved supplier list records each provider's approval status and scope, with controls set by the provider's effect on conformity", "kind": "fact", "evidence": "external_providers"},
	"8.4.2": {"title": "Type and extent of control — supplier performance is monitored and reviewed within the past year, verification activities are defined and risk is used to set controls", "kind": "fact", "evidence": "external_providers"},
	"8.4.3": {"title": "Information for external providers — requirements including flow-down of customer and QMS requirements are communicated and acknowledged by each provider", "kind": "fact", "evidence": "external_providers"},
	"8.5.1": {"title": "Control of production and service provision — provision runs under controlled conditions with documented information, monitoring, infrastructure, competence and release criteria", "kind": "attestation"},
	"8.5.1.1": {"title": "Control of equipment, tools and software programs — production equipment, tooling and software are identified, validated on a recorded date before use and maintained in a known state", "kind": "fact", "evidence": "production_equipment"},
	"8.5.1.2": {"title": "Validation and control of special processes — processes whose output cannot be verified afterwards are qualified, with criteria, approved equipment, personnel and records", "kind": "attestation"},
	"8.5.1.3": {"title": "Production process verification — first article inspection confirms the process delivers conforming product and is repeated after process or design changes", "kind": "attestation"},
	"8.5.2": {"title": "Identification and traceability — each unit or batch carries a unique identifier, its part number and its lot or serial record, so configuration and history can be reconstructed", "kind": "fact", "evidence": "traceability"},
	"8.5.3": {"title": "Property of customers and external providers — such property is identified, verified, protected and safeguarded, with loss or damage reported", "kind": "attestation"},
	"8.5.4": {"title": "Preservation — outputs are preserved during production and provision, including cleaning, FOD prevention, handling, shelf life and marking", "kind": "attestation"},
	"8.5.5": {"title": "Post-delivery activities — warranty, maintenance, recycling, disposal and the collection of in-service data and problems are controlled", "kind": "attestation"},
	"8.5.6": {"title": "Control of changes — every production or service change record is reviewed for impact, approved by an authorized person and retained", "kind": "fact", "evidence": "change_control"},
	"8.6": {"title": "Release of products and services — planned verification is completed, release is authorized and evidence of conformity with release authority is retained", "kind": "attestation"},
	"8.7.1": {"title": "Control of nonconforming outputs — each nonconformance record carries a disposition, and use-as-is or repair dispositions carry customer authorization", "kind": "fact", "evidence": "nonconformance"},
	"8.7.2": {"title": "Nonconformity records — each record carries a unique identifier and describes the nonconformity, the action taken and the authority that decided the disposition", "kind": "fact", "evidence": "nonconformance"},
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

# ── 8.1.2 Configuration management ───────────────────────────────────────────
# input.as9100d.configuration_management: {baselines: [{id, approved: bool, approved_by, approved_on: date}],
#   drift_records: [{baseline_id, detected_on: date, disposition}]}
# At least one baseline is required. Every baseline needs a unique non-blank id, approved: true, a non-blank
# approved_by and an approved_on that parses and is not in the future. drift_records must be a list (empty is
# fine: no drift was detected); each record names an existing baseline, a detection date that parses and a
# non-blank disposition.

_baselines := input.as9100d.configuration_management.baselines

_baseline_ids contains id if {
	some b in _baselines
	id := object.get(b, "id", null)
	is_string(id)
}

_present("8.1.2") if is_array(_baselines)

_gaps["8.1.2"] contains "no configuration baseline is recorded — at least one approved baseline is required" if {
	count(_baselines) == 0
}

_gaps["8.1.2"] contains r if {
	some b in _baselines
	not _text(b, "id")
	r := sprintf("baseline %v has no identifier (id must be a non-blank string)", [b])
}

_gaps["8.1.2"] contains r if {
	some id in _dup_ids(_baselines)
	r := sprintf("identifier %v is used by more than one baseline (ids must be unique)", [id])
}

_gaps["8.1.2"] contains r if {
	some b in _baselines
	not b.approved == true
	r := sprintf("baseline %v is not approved", [_label(b)])
}

_gaps["8.1.2"] contains r if {
	some b in _baselines
	b.approved == true
	not _text(b, "approved_by")
	r := sprintf("baseline %v records no approving authority (approved_by must be a non-blank string)", [_label(b)])
}

_gaps["8.1.2"] contains r if {
	some b in _baselines
	b.approved == true
	not _has_date(b, "approved_on")
	r := sprintf("baseline %v has no approval date that parses (approved_on: %v)", [_label(b), _shown(b, "approved_on")])
}

_gaps["8.1.2"] contains r if {
	some b in _baselines
	b.approved == true
	_has_date(b, "approved_on")
	not _not_future(b.approved_on)
	r := sprintf("baseline %v records an approval date in the future (approved_on: %v)", [_label(b), b.approved_on])
}

_gaps["8.1.2"] contains "no status-accounting (drift) records: configuration_management.drift_records must be a list" if {
	not is_array(object.get(input.as9100d.configuration_management, "drift_records", null))
}

_gaps["8.1.2"] contains r if {
	some d in input.as9100d.configuration_management.drift_records
	not _text(d, "baseline_id")
	r := sprintf("drift record %v names no baseline (baseline_id must be a non-blank string)", [d])
}

_gaps["8.1.2"] contains r if {
	some d in input.as9100d.configuration_management.drift_records
	_text(d, "baseline_id")
	not d.baseline_id in _baseline_ids
	r := sprintf("drift record references baseline %v, which is not in the baseline list", [d.baseline_id])
}

_gaps["8.1.2"] contains r if {
	some d in input.as9100d.configuration_management.drift_records
	not _has_date(d, "detected_on")
	r := sprintf("drift against baseline %v has no detection date that parses (detected_on: %v)", [_shown(d, "baseline_id"), _shown(d, "detected_on")])
}

_gaps["8.1.2"] contains r if {
	some d in input.as9100d.configuration_management.drift_records
	not _text(d, "disposition")
	r := sprintf("drift against baseline %v has no disposition", [_shown(d, "baseline_id")])
}

# ── 8.1.4 Prevention of counterfeit parts ────────────────────────────────────
# input.as9100d.counterfeit_prevention: {approved_sources: [string], components: [{id, source,
#   provenance_documented: bool}]}
# At least one component is required; each needs a unique non-blank id, provenance_documented: true and a
# source that appears in approved_sources.

_components := input.as9100d.counterfeit_prevention.components

_present("8.1.4") if is_array(_components)

_gaps["8.1.4"] contains "no components are recorded for provenance review — at least one is required" if {
	count(_components) == 0
}

_gaps["8.1.4"] contains "no approved-source list: counterfeit_prevention.approved_sources must be a list" if {
	not is_array(object.get(input.as9100d.counterfeit_prevention, "approved_sources", null))
}

_gaps["8.1.4"] contains r if {
	some c in _components
	not _text(c, "id")
	r := sprintf("component %v has no identifier (id must be a non-blank string)", [c])
}

_gaps["8.1.4"] contains r if {
	some id in _dup_ids(_components)
	r := sprintf("identifier %v is used by more than one component (ids must be unique)", [id])
}

_gaps["8.1.4"] contains r if {
	some c in _components
	not c.provenance_documented == true
	r := sprintf("component %v has no documented provenance (SBOM or certificate of conformity)", [_label(c)])
}

_gaps["8.1.4"] contains r if {
	is_array(input.as9100d.counterfeit_prevention.approved_sources)
	some c in _components
	not object.get(c, "source", null) in input.as9100d.counterfeit_prevention.approved_sources
	r := sprintf("component %v was obtained from %v, which is not an approved source", [_label(c), _shown(c, "source")])
}

# ── 8.4 Externally provided processes, products and services ─────────────────
# input.as9100d.external_providers: {suppliers: [{id, status: approved|conditional|..., scope,
#   performance_reviewed_on: date, flow_down_acknowledged: bool}]}
# At least one supplier is required for all three rows; there is no "none occurred" case because an aerospace
# organization with no external providers is not credible, so an empty list fails 8.4.1, 8.4.2 and 8.4.3.
# Every supplier needs a unique non-blank id, an approved or conditional status, a non-blank scope, a
# performance_reviewed_on that parses and lies within the rolling past year, and flow_down_acknowledged: true.

_approved_status := {"approved", "conditional"}

_suppliers := input.as9100d.external_providers.suppliers

_present("8.4.1") if is_array(_suppliers)

_gaps["8.4.1"] contains "the approved supplier list is empty — at least one supplier is required" if {
	count(_suppliers) == 0
}

_gaps["8.4.1"] contains r if {
	some s in _suppliers
	not _text(s, "id")
	r := sprintf("supplier %v has no identifier (id must be a non-blank string)", [s])
}

_gaps["8.4.1"] contains r if {
	some id in _dup_ids(_suppliers)
	r := sprintf("identifier %v is used by more than one supplier (ids must be unique)", [id])
}

_gaps["8.4.1"] contains r if {
	some s in _suppliers
	not object.get(s, "status", null) in _approved_status
	r := sprintf("supplier %v has status %v, not approved or conditional", [_label(s), _shown(s, "status")])
}

_gaps["8.4.1"] contains r if {
	some s in _suppliers
	not _text(s, "scope")
	r := sprintf("supplier %v has no approved scope recorded (scope must be a non-blank string)", [_label(s)])
}

_present("8.4.2") if is_array(_suppliers)

_gaps["8.4.2"] contains "the approved supplier list is empty — no supplier performance has been reviewed" if {
	count(_suppliers) == 0
}

_gaps["8.4.2"] contains r if {
	some s in _suppliers
	not _within_past_year(object.get(s, "performance_reviewed_on", null))
	r := sprintf("supplier %v has no performance review within the past year (performance_reviewed_on: %v)", [_label(s), _shown(s, "performance_reviewed_on")])
}

_present("8.4.3") if is_array(_suppliers)

_gaps["8.4.3"] contains "the approved supplier list is empty — no flow-down acknowledgement exists" if {
	count(_suppliers) == 0
}

_gaps["8.4.3"] contains r if {
	some s in _suppliers
	not s.flow_down_acknowledged == true
	r := sprintf("supplier %v has not acknowledged the flowed-down requirements (flow_down_acknowledged must be true)", [_label(s)])
}

# ── 8.5.1.1 Equipment, tools and software programs ───────────────────────────
# input.as9100d.production_equipment: [{id, type: equipment|tool|software, validated: bool, validated_on: date}]
# At least one entry is required; each needs a unique non-blank id, a recognized type, validated: true and a
# validated_on that parses and is not in the future.

_equipment_types := {"equipment", "tool", "software"}

_production := input.as9100d.production_equipment

_present("8.5.1.1") if is_array(_production)

_gaps["8.5.1.1"] contains "no production equipment, tooling or software is registered — at least one entry is required" if {
	count(_production) == 0
}

_gaps["8.5.1.1"] contains r if {
	some e in _production
	not _text(e, "id")
	r := sprintf("production equipment entry %v has no identifier (id must be a non-blank string)", [e])
}

_gaps["8.5.1.1"] contains r if {
	some id in _dup_ids(_production)
	r := sprintf("identifier %v is used by more than one production equipment entry (ids must be unique)", [id])
}

_gaps["8.5.1.1"] contains r if {
	some e in _production
	not object.get(e, "type", null) in _equipment_types
	r := sprintf("entry %v has type %v, not equipment, tool or software", [_label(e), _shown(e, "type")])
}

_gaps["8.5.1.1"] contains r if {
	some e in _production
	not e.validated == true
	r := sprintf("%v %v is not validated for use", [object.get(e, "type", "item"), _label(e)])
}

_gaps["8.5.1.1"] contains r if {
	some e in _production
	e.validated == true
	not _has_date(e, "validated_on")
	r := sprintf("%v %v is marked validated but has no validation date that parses (validated_on: %v)", [object.get(e, "type", "item"), _label(e), _shown(e, "validated_on")])
}

_gaps["8.5.1.1"] contains r if {
	some e in _production
	e.validated == true
	_has_date(e, "validated_on")
	not _not_future(e.validated_on)
	r := sprintf("%v %v records a validation date in the future (validated_on: %v)", [object.get(e, "type", "item"), _label(e), e.validated_on])
}

# ── 8.5.2 Identification and traceability ────────────────────────────────────
# input.as9100d.traceability: {items: [{id, part_number, serial | lot}]}
# At least one item is required; each needs a unique non-blank id, a non-blank part_number and a non-blank
# serial or lot.

_trace := input.as9100d.traceability.items

_present("8.5.2") if is_array(_trace)

_gaps["8.5.2"] contains "no traceability records are present — at least one is required" if {
	count(_trace) == 0
}

_gaps["8.5.2"] contains r if {
	some t in _trace
	not _text(t, "id")
	r := sprintf("traceability record %v has no unique identifier (id must be a non-blank string)", [t])
}

_gaps["8.5.2"] contains r if {
	some id in _dup_ids(_trace)
	r := sprintf("identifier %v is used by more than one traceability record (ids must be unique)", [id])
}

_gaps["8.5.2"] contains r if {
	some t in _trace
	not _text(t, "part_number")
	r := sprintf("item %v has no part number (part_number must be a non-blank string)", [_label(t)])
}

_gaps["8.5.2"] contains r if {
	some t in _trace
	not _text(t, "serial")
	not _text(t, "lot")
	r := sprintf("item %v carries neither a serial nor a lot number (serial or lot must be a non-blank string)", [_label(t)])
}

# ── 8.5.6 Control of changes ─────────────────────────────────────────────────
# input.as9100d.change_control: {records: [{id, approved: bool, approved_by, impact_reviewed: bool}]}
# At least one record is required; each needs a unique non-blank id, approved: true with a non-blank
# approved_by, and impact_reviewed: true.

_changes := input.as9100d.change_control.records

_present("8.5.6") if is_array(_changes)

_gaps["8.5.6"] contains "no change records are present — at least one is required" if {
	count(_changes) == 0
}

_gaps["8.5.6"] contains r if {
	some c in _changes
	not _text(c, "id")
	r := sprintf("change record %v has no identifier (id must be a non-blank string)", [c])
}

_gaps["8.5.6"] contains r if {
	some id in _dup_ids(_changes)
	r := sprintf("identifier %v is used by more than one change record (ids must be unique)", [id])
}

_gaps["8.5.6"] contains r if {
	some c in _changes
	not c.approved == true
	r := sprintf("change %v is not approved", [_label(c)])
}

_gaps["8.5.6"] contains r if {
	some c in _changes
	c.approved == true
	not _text(c, "approved_by")
	r := sprintf("change %v records no approving authority (approved_by must be a non-blank string)", [_label(c)])
}

_gaps["8.5.6"] contains r if {
	some c in _changes
	not c.impact_reviewed == true
	r := sprintf("change %v has no review of its consequences (impact_reviewed must be true)", [_label(c)])
}

# ── 8.7 Control of nonconforming outputs ─────────────────────────────────────
# input.as9100d.nonconformance: {records: [{id, description, disposition, disposition_authority,
#   customer_authorized: bool}], none_occurred: bool}
# At least one record is required. A period with no nonconformances is declared, never implied: records: []
# passes a row only with nonconformance.none_occurred: true AND that row attested (attestations["8.7.1"] /
# attestations["8.7.2"] == true). none_occurred alongside records is a contradiction and fails both rows.

_dispositions := {"rework", "repair", "use_as_is", "scrap", "return_to_supplier", "regrade", "correction"}

_customer_dispositions := {"use_as_is", "repair"}

_ncrs := input.as9100d.nonconformance.records

_ncr_none_declared if input.as9100d.nonconformance.none_occurred == true

# The gap an empty or contradicted list produces for row id, if any.
_ncr_list_gap(id) := r if {
	count(_ncrs) == 0
	not _ncr_none_declared
	r := sprintf("no nonconformance records are present — if none occurred in the period, set nonconformance.none_occurred: true and attest %s", [id])
}

_ncr_list_gap(id) := r if {
	count(_ncrs) == 0
	_ncr_none_declared
	not _attested(id)
	r := sprintf("nonconformance.none_occurred is true but the declaration is not attested (attestations[%q] must be true)", [id])
}

_ncr_list_gap(id) := r if {
	count(_ncrs) > 0
	_ncr_none_declared
	r := sprintf("nonconformance.none_occurred is true but %d records are present — the declaration contradicts the evidence (row %s)", [count(_ncrs), id])
}

_present("8.7.1") if is_array(_ncrs)

_gaps["8.7.1"] contains r if r := _ncr_list_gap("8.7.1")

_gaps["8.7.1"] contains r if {
	some n in _ncrs
	not object.get(n, "disposition", null) in _dispositions
	r := sprintf("nonconformance %v has no recognized disposition (%v)", [_label(n), _shown(n, "disposition")])
}

_gaps["8.7.1"] contains r if {
	some n in _ncrs
	n.disposition in _customer_dispositions
	not n.customer_authorized == true
	r := sprintf("nonconformance %v is dispositioned %v without customer authorization (customer_authorized must be true)", [_label(n), n.disposition])
}

_present("8.7.2") if is_array(_ncrs)

_gaps["8.7.2"] contains r if r := _ncr_list_gap("8.7.2")

_gaps["8.7.2"] contains r if {
	some n in _ncrs
	not _text(n, "id")
	r := sprintf("nonconformance record %v has no identifier (id must be a non-blank string)", [n])
}

_gaps["8.7.2"] contains r if {
	some id in _dup_ids(_ncrs)
	r := sprintf("identifier %v is used by more than one nonconformance record (ids must be unique)", [id])
}

_gaps["8.7.2"] contains r if {
	some n in _ncrs
	not _text(n, "description")
	r := sprintf("nonconformance %v has no description", [_label(n)])
}

_gaps["8.7.2"] contains r if {
	some n in _ncrs
	not _text(n, "disposition_authority")
	r := sprintf("nonconformance %v does not name the authority that decided the disposition (disposition_authority must be a non-blank string)", [_label(n)])
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
