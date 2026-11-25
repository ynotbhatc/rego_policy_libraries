# METADATA
# title: "Bridge: expose cmmc under the /v1/data/<framework>/main/compliance_report entrypoint"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: false
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cmmc.main

# Framework-key entrypoint bridge. The product addresses every framework by key at
# /v1/data/<key>/main/compliance_report; this package maps the key cmmc onto
# cmmc. Fail-closed: with no facts the report is non-compliant with an
# explicit finding, and the report object is always defined (never {}).

import data.cmmc as _t
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"control": "FAIL-CLOSED",
	"title": "no facts supplied for cmmc — the assessment could not be evaluated; this is not a passing result",
	"severity": "high",
	"status": "open",
}

default _target_compliant := false

_target_compliant if _t.compliant == true

# Rows of the report: the input-contract findings, then one row per failed
# practice (data.cmmc.practice_rows). Every finding, one per user or system where
# a practice has several, is listed under "findings".
default _contract_rows := []

_contract_rows := sort(_t.input_contract_findings)

default _practice_rows := []

_practice_rows := _t.practice_rows

default _findings := []

_findings := _t.violations

_input_contract_violations := array.concat(_contract_rows, [_no_facts_finding]) if not _facts_supplied

_input_contract_violations := _contract_rows if _facts_supplied

_violations := array.concat(_input_contract_violations, _practice_rows)

default _compliant := false

_compliant if {
	_facts_supplied
	_target_compliant
	count(_violations) == 0
}

default _upstream := {}

_upstream := {"framework_key": "cmmc"}

# One source of truth: data.cmmc (cmmc_main.rego) decides the practices of the
# assessed level (15 at Level 1, 110 at Level 2 and at Level 3, where the 24
# Level 3 requirements are reported as not evaluated) and counts each failed
# practice once, so failed_controls <= total_controls by construction.
default total_controls := 110

total_controls := _t.practices_evaluated

default _failed := 110

_failed := _t.practices_failed

default _stated_level := null

_stated_level := input.cmmc_level

# violation_count == failed_controls + input_contract_violations on every input:
# one row per failed practice, plus the findings that name no practice (level not
# stated, Level 3 not evaluated, no facts supplied).
compliance_report := object.union(_upstream, {
	"framework_key": "cmmc",
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"failed_controls": _failed,
	"passed_controls": total_controls - _failed,
	"total_controls": total_controls,
	"input_contract_violations": count(_input_contract_violations),
	"findings": _findings,
	"finding_count": count(_findings),
	"assessed_level": _stated_level,
	"standard_sizes": _t.standard_sizes,
	"failed_practices": _failed_practices,
	"facts_supplied": _facts_supplied,
})

default _failed_practices := []

_failed_practices := sort(_t.failed_practices)

compliant := _compliant

violations := _violations
