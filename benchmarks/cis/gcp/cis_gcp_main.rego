# METADATA
# title: "CIS Google Cloud Platform Foundation Benchmark v5.0.0"
# custom:
#   class: security
#   framework: cis_cloud
#   source: cis
#   domains: [cloud, gcp]
#   coverage:
#     checks: 1
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_gcp.main

import rego.v1

import data.cis_gcp_foundations as bench

# CIS Google Cloud Platform Foundation Benchmark v5.0.0
#
# Entry point for the cis_gcp framework key. The 93 recommendations are evaluated in
# cis_gcp_foundations.rego (package cis_gcp_foundations, which also documents the input
# contract); this module republishes them in the cis_gcp compliance_report shape.
#
# Sections:
#   1. Identity and Access Management   5. Storage
#   2. Logging and Monitoring           6. Cloud SQL Database Services
#   3. Networking                       7. BigQuery
#   4. Virtual Machines                 8. Dataproc
#
# Violation messages read "CIS GCP <id>: ..." (downstream technical-debt scoring keys on the
# section number after "CIS GCP ").
#
# OPA endpoint: POST http://<host>:8181/v1/data/cis_gcp/main/compliance_report

default compliant := false

compliant if {
	count(violations) == 0
}

violations contains sprintf("CIS GCP %s", [v]) if some v in bench.violations

# ── Compliance Report ────────────────────────────────────────────────────────

# Optional identity fields are read through defaulted helpers. Referencing
# input.* directly inside the object literal made the entire report undefined
# whenever the caller omitted them (library rule #5) — the endpoint returned
# nothing at all rather than a report with blank metadata.

default _entity_name := ""

_entity_name := input.entity_name

default _project_id := ""

_project_id := input.gcp_project_id

default _assessed_at := ""

_assessed_at := input.assessment_date

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE
#
# With NO facts, nothing iterates and a benchmark can report near-total
# compliance for an assessment that evaluated nothing. A missing-facts
# assessment is reported as fully non-compliant with an explicit violation,
# never as a pass. (The engine also fails every recommendation whose evidence
# is missing, so a partial input cannot pass the controls it does not cover.)
# ---------------------------------------------------------------------------

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_gcp"],
)

# Counted from the recommendation table, never hard-coded.
default _total_controls := 93

_total_controls := bench.total_controls

# Sets are not arrays; the report contract publishes arrays so downstream
# JSON consumers get a stable type.
_bench_violations := sort([v | some v in violations])

_violations := array.concat(_bench_violations, [_no_facts_msg]) if not _facts_supplied

_violations := _bench_violations if _facts_supplied

# Failed = distinct failing recommendations (one control can fail on many resources),
# so passed + failed always equals total.
_failed := _total_controls if not _facts_supplied

_failed := count(bench.failing_controls) if _facts_supplied

# Clamp: a mis-declared total must never yield a negative passed count.
_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

_section(n) := [v | some v in _violations; startswith(v, sprintf("CIS GCP %d.", [n]))]

compliance_report := {
	"framework": "cis_gcp",
	"benchmark": "CIS Google Cloud Platform Foundation Benchmark",
	"version": "v5.0.0",
	"entity_name": _entity_name,
	"project_id": _project_id,
	"assessed_at": _assessed_at,
	"compliant": compliant,
	"total_controls": _total_controls,
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"violations": _violations,
	"violation_count": _failed,
	"section_results": {
		"iam": _section(1),
		"logging": _section(2),
		"networking": _section(3),
		"virtual_machines": _section(4),
		"storage": _section(5),
		"cloud_sql": _section(6),
		"bigquery": _section(7),
		# v5.0.0 has no GKE section (GKE is benchmarks/cis/gke); the key stays, always empty,
		# so existing consumers of this shape keep working.
		"gke": [],
		"dataproc": _section(8),
	},
}
