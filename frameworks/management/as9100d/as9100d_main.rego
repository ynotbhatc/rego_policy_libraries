# METADATA
# title: "SAE AS9100D (9100:2016) — Aerospace quality management system, clauses 4–10"
# custom:
#   class: compliance
#   framework: as9100d
#   source: sae
#   domains: [aerospace, quality]
#   coverage:
#     checks: 5
#     cited: 1
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package as9100d.main

import rego.v1

# SAE AS9100D — Quality Management Systems: Requirements for Aviation, Space and Defense
# Organizations (SAE AS9100 Rev D, 2016; IAQG 9100:2016), built on ISO 9001:2015.
#
# Scope. 71 rows over the clause and sub-clause requirements of clauses 4–10 at clause granularity, including
# every aerospace addition to ISO 9001: 8.1.1 operational risk management, 8.1.2 configuration management, 8.1.3
# product safety, 8.1.4 prevention of counterfeit parts, 8.3.4.1 verification and validation testing, 8.4
# external providers with flow-down, 8.5.1.1 equipment/tools/software, 8.5.1.2 special processes, 8.5.1.3
# production process verification (first article inspection), 8.5.6 control of changes, 8.7 nonconforming
# outputs, 9.1 on-time delivery and conformity, 10.2 root cause and human factors. Every clause of the standard
# is a "shall"; the rows differ only in how they are decided (kind):
#   fact         18 rows decided from evidence AAC already produces elsewhere in this library (configuration
#                baselines and drift, change records, SBOM/provenance and approved sources, supplier registers,
#                asset/lot/serial identity, validated tooling, calibration registers, nonconformance and
#                corrective-action records, audit and review dates, KPIs)
#   attestation  53 rows attested by the organization: input.as9100d.attestations["<id>"] == true
#
# Grouped model. Rows follow the clause structure, but not every sub-clause is its own row: 7.5.3.1 and 7.5.3.2
# are decided under 7.5.3, and 8.2.3.1 and 8.2.3.2 under 8.2.3 (their titles say so). 8.3.4.1 is its own row.
# Clause 9.1.2 is one row decided two ways: on-time delivery and conformity KPIs are evidence (kpis) and
# customer feedback, complaints and corrective-action requests are attested under the same id
# (attestations["9.1.2"]), because no collector produces them. Every row id is a clause number of the standard.
#
# Not reproduced. AS9100D is sold by SAE International and IAQG; ISO 9001:2015 by ISO. This module carries
# clause numbers and short titles (public structure) and our own wording of the evidence that satisfies each
# clause. No requirement sentence of either standard appears here. Sources used for the clause structure:
#   - SwRI "PIMS & Progress" AS9100D / ISO 9001 compliance matrix (clause numbers and titles) —
#     pimsandprogress.space.swri.edu/compliance.html
#   - Smithers, "Smithers Summarizes: AS9100 Requirements" (Feb 2026) — smithers.com/resources
#   - IAQG 9100:2016 clarification notes (8.1.1–8.1.4 apply to every organization) — iaqg.org
#   - ISO 9001:2015 clause structure (Annex SL clauses 4–10) — iso.org/standard/62085.html
#   - Next revision: IAQG renamed the successor IA9100 (no "Rev E"); it follows ISO 9001:2026 (published
#     2026-09-16) and had no publication date on 2026-11-11 — iaqg.org, sae.org, sma.nasa.gov (2024-04-17),
#     lrqa.com. Tracked in STANDARDS_UPDATE_REGISTRY.md.
#
# Layout. One package per clause family, each self-contained so the product can upload it on its own:
#   as9100d.context (4, 5 rows)  as9100d.leadership (5, 5)  as9100d.planning (6, 5)  as9100d.support (7, 13)
#   as9100d.operation (8, 31)  as9100d.performance (9, 9)  as9100d.improvement (10, 4)
# This package rolls them up. Query: POST /v1/data/as9100d/main/compliance_report
#
# Exports. The OSCAL catalog and the other converter outputs list 88 controls for this framework: the 71 rows
# plus 17 template controls (the per-package "not attested", "FAIL-CLOSED" and gap message templates and this
# package's two contract rules), which the exporters count as controls of their own. 71 is the clause-row count.
#
# Fail-closed. Empty input: every row fails (attestation rows "not attested", fact rows "FAIL-CLOSED: no
# evidence at input.as9100d.<path>"), compliant is false, the report object is always defined. A clause
# module missing from the OPA store is itself a violation. An attestation for an unknown clause id is a
# violation (typo guard), as is an attestations container that is present but not an object (false, a string,
# a list). An as_of that does not parse is a violation and every date comparison fails until it is fixed.
# Nothing can be declared out of scope.
#
# Evidence validation. A required field that is absent, null, blank, of the wrong type or (for dates)
# unparseable is evidence missing: the row fails and the violation names the field. Ids must be non-blank and
# unique within their list. Dates are RFC 3339 or YYYY-MM-DD and are compared numerically after parsing.
# "Within the past year" is the twelve months ending on as_of: the same calendar date one year earlier counts
# (time.add_date, so a February 29 anchor falls back to March 1). Not a fiscal year, not a count of days.
#
# Empty lists. Rows that read a list require at least one record. Two evidence roots accept an explicit
# declaration that nothing occurred in the period, and only together with the row's attestation:
#   nonconformance.none_occurred: true      + attestations["8.7.1"] / attestations["8.7.2"]   (records: [])
#   corrective_actions.none_occurred: true  + attestations["10.2.1"] / attestations["10.2.2"] (records: [])
# A none_occurred declaration alongside records is a contradiction and fails both rows. measuring_equipment
# (7.1.5.1, 7.1.5.2) and external_providers.suppliers (8.4.1–8.4.3) have no such case: an aerospace QMS with
# no measuring equipment or no external providers is not credible, so an empty list fails every row that reads it.
#
# Evidence contract — input.as9100d.*
#   as_of                      date (RFC 3339 or YYYY-MM-DD) that pins "today" for the past-year windows;
#                              default: the evaluation clock
#   attestations               {"<row id>": true, ...} for the 53 attestation rows, the 9.1.2 feedback attestation and the none_occurred rows
#   measuring_equipment        [{id, description, in_service, calibration_due, calibrated_on, traceable}]  (7.1.5.1, 7.1.5.2)
#   configuration_management   {baselines: [{id, approved, approved_by, approved_on}],
#                               drift_records: [{baseline_id, detected_on, disposition}]}                (8.1.2)
#   counterfeit_prevention     {approved_sources: [string], components: [{id, source, provenance_documented}]}  (8.1.4)
#   external_providers         {suppliers: [{id, status, scope, performance_reviewed_on, flow_down_acknowledged}]}  (8.4.1–8.4.3)
#   production_equipment       [{id, type, validated, validated_on}]                                      (8.5.1.1)
#   traceability               {items: [{id, part_number, serial | lot}]}                                 (8.5.2)
#   change_control             {records: [{id, approved, approved_by, impact_reviewed}]}                   (8.5.6)
#   nonconformance             {records: [{id, description, disposition, disposition_authority, customer_authorized}],
#                               none_occurred}                                                            (8.7.1, 8.7.2)
#   kpis                       {on_time_delivery: {value, target, period_end}, conformity: {value, target, period_end}}  (9.1.2)
#   internal_audit             {programme: {planned: [{id, scope, scheduled_on}]}, audits: [{id, completed_on, report_issued}]}  (9.2.1, 9.2.2)
#   management_review          {reviews: [{held_on, outputs_recorded}]}                                   (9.3.1)
#   corrective_actions         {records: [{id, nonconformity_id, root_cause, human_factors_considered, status, due_on,
#                               closed_on, effectiveness_reviewed}], none_occurred}                        (10.2.1, 10.2.2)
# Shapes follow the records AAC's collectors already emit for configuration drift (cmmc.configuration_management),
# change control (csa_ccm.change_control), SBOM/provenance (cra supply-chain evidence) and supplier registers
# (dora / mas_trm third-party rows), renamed under one as9100d.* root so a single collector run feeds this module.

_families := ["context", "leadership", "planning", "support", "operation", "performance", "improvement"]

# Static references (a dynamic data.as9100d[f] would include this package and OPA rejects it as recursion).
# A clause module that is not in the store simply has no entry here and is reported below.
_reports["context"] := data.as9100d.context.compliance_report

_reports["leadership"] := data.as9100d.leadership.compliance_report

_reports["planning"] := data.as9100d.planning.compliance_report

_reports["support"] := data.as9100d.support.compliance_report

_reports["operation"] := data.as9100d.operation.compliance_report

_reports["performance"] := data.as9100d.performance.compliance_report

_reports["improvement"] := data.as9100d.improvement.compliance_report

_tables["context"] := data.as9100d.context.items

_tables["leadership"] := data.as9100d.leadership.items

_tables["planning"] := data.as9100d.planning.items

_tables["support"] := data.as9100d.support.items

_tables["operation"] := data.as9100d.operation.items

_tables["performance"] := data.as9100d.performance.items

_tables["improvement"] := data.as9100d.improvement.items

_loaded contains f if {
	some f, _ in _reports
}

# Every row of every clause module, keyed by row id.
items[id] := it if {
	some _, tbl in _tables
	some id, it in tbl
}

default compliant := false

compliant if {
	count(violations) == 0
	count(_loaded) == count(_families)
}

violations contains v if {
	some _, rep in _reports
	some v in rep.violations
}

violations contains msg if {
	some f in _families
	not f in _loaded
	msg := sprintf("AS9100D Input Contract: clause module as9100d.%s is not loaded — FAIL-CLOSED, its clauses cannot be evaluated", [f])
}

violations contains msg if {
	is_object(input.as9100d.attestations)
	some id, _ in input.as9100d.attestations
	not items[id]
	msg := sprintf("AS9100D Input Contract: attestation for unknown clause id %v — not a clause of AS9100D", [id])
}

# The container test goes through object.keys: `input.as9100d.attestations` as a bare expression is false for
# attestations: false, so the old guard never fired for that case and the report carried no contract violation.
violations contains msg if {
	is_object(input.as9100d)
	"attestations" in object.keys(input.as9100d)
	not is_object(input.as9100d.attestations)
	msg := sprintf("AS9100D Input Contract: input.as9100d.attestations must be an object of {\"<clause id>\": true}, got %v", [input.as9100d.attestations])
}

_as_of_parses if {
	d := input.as9100d.as_of
	is_string(d)
	count(d) == 10
	is_number(time.parse_rfc3339_ns(concat("", [d, "T00:00:00Z"])))
}

_as_of_parses if {
	d := input.as9100d.as_of
	is_string(d)
	count(d) != 10
	is_number(time.parse_rfc3339_ns(d))
}

violations contains msg if {
	is_object(input.as9100d)
	"as_of" in object.keys(input.as9100d)
	not _as_of_parses
	msg := sprintf("AS9100D Input Contract: input.as9100d.as_of must be an RFC 3339 or YYYY-MM-DD date, got %v — every date comparison in the clause modules fails until it is", [input.as9100d.as_of])
}

clauses[rep.clause] := r if {
	some f, rep in _reports
	r := {
		"name": rep.name,
		"package": concat(".", ["as9100d", f]),
		"total": rep.total,
		"passed": rep.passed,
		"failed": rep.failed,
		"attested": rep.attested,
		"fact_evaluated": rep.fact_evaluated,
		"fact_passed": rep.fact_passed,
		"gaps": rep.gaps,
		"compliant": rep.compliant,
	}
}

_sum(field) := sum([rep[field] | some _, rep in _reports])

default _as_of := "evaluation clock"

_as_of := input.as9100d.as_of

compliance_report := {
	"framework": "SAE AS9100D (9100:2016)",
	"standard": "SAE AS9100 Rev D — Quality Management Systems: Requirements for Aviation, Space and Defense Organizations (2016), built on ISO 9001:2015",
	"source": "sae.org / iaqg.org (clause structure only; standard text not reproduced)",
	"as_of": _as_of,
	"clause_modules_loaded": count(_loaded),
	"total": _sum("total"),
	"attestation_items": _sum("attestation_items"),
	"fact_items": _sum("fact_items"),
	"passed": _sum("passed"),
	"failed": _sum("failed"),
	"attested": _sum("attested"),
	"fact_evaluated": _sum("fact_evaluated"),
	"fact_passed": _sum("fact_passed"),
	"clauses": clauses,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"total_controls": max([_sum("total"), count(violations)]),
}
