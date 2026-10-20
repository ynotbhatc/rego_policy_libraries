# METADATA
# title: "CIS Microsoft SQL Server 2025 Benchmark v1.0.0 - compliance_report entrypoint"
# custom:
#   class: security
#   framework: cis_sql_server_2025
#   source: cis
#   domains: [database, mssql]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: false
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis.sql_server_2025.main

# OPA query path: /v1/data/cis/sql_server_2025/main/compliance_report
# Thin alias of data.cis.sql_server_2025; that package already fails closed when input.sql is absent.

import data.cis.sql_server_2025 as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

# Bridge fields shared by every cis_*.main report (see _framework_key_tests): distinct failing
# in-scope controls, parsed from the "<id>: ..." message prefix; violations as a sorted array.
_failed_ids := {id |
	some v in bench.violations
	id := split(v, ":")[0]
	id in bench.in_scope
}

_total := count(bench.in_scope)

default _pct := 0

_pct := round(((_total - count(_failed_ids)) * 100) / _total) if _total > 0

compliance_report := object.union(bench.compliance_report, {
	"facts_supplied": _facts_supplied,
	"framework": "cis_sql_server_2025",
	"passed_controls": _total - count(_failed_ids),
	"failed_controls": count(_failed_ids),
	"compliance_percentage": _pct,
	"violations": _report_violations,
})

compliant := bench.compliant

violations := bench.violations

# FAIL-CLOSED gate (see benchmarks/cis/network_devices/pfsense/cis_pfsense_main.rego): with no facts at all the
# report says so explicitly, so an empty assessment can never read as a result.
_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_sql_server_2025"],
)

_report_violations := array.concat(sort([v | some v in bench.violations]), [_no_facts_msg]) if not _facts_supplied

_report_violations := sort([v | some v in bench.violations]) if _facts_supplied
