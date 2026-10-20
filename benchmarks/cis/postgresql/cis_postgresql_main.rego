# METADATA
# title: "CIS PostgreSQL - default compliance_report entrypoint (latest version: PostgreSQL 17 v1.1.0)"
# custom:
#   class: security
#   framework: cis_postgresql
#   source: cis
#   domains: [database, postgresql]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_postgresql.main

# OPA query path: /v1/data/cis_postgresql/main/compliance_report
#
# Standard: a version-agnostic key (cis_<product>) always resolves to the LATEST CIS
# benchmark version the library carries. Callers that must stay on an older release
# query that version's package directly (data.cis.postgresql_13 / _14 / _15).
# When a newer PostgreSQL benchmark lands, repoint the import below in the same PR.

import data.cis.postgresql_17 as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

# Bridge fields shared by every cis_*.main report (see _framework_key_tests).
_failed_ids := {id | some id, _ in bench.controls; not id in bench.passed}

_total := count(bench.controls)

default _pct := 0

_pct := round(((_total - count(_failed_ids)) * 100) / _total) if _total > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_postgresql"],
)

_report_violations := array.concat(bench.violations, [_no_facts_msg]) if not _facts_supplied

_report_violations := bench.violations if _facts_supplied

compliance_report := object.union(bench.compliance_report, {
	"facts_supplied": _facts_supplied,
	"framework": "cis_postgresql",
	"benchmark_package": "cis.postgresql_17",
	"passed_controls": _total - count(_failed_ids),
	"failed_controls": count(_failed_ids),
	"compliance_percentage": _pct,
	"violations": _report_violations,
})

compliant := bench.compliant

violations := bench.violations
