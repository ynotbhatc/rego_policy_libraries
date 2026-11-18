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

default _target_violations := []

_target_violations := _t.violations

_violations := array.concat(_target_violations, [_no_facts_finding]) if not _facts_supplied

_violations := _target_violations if _facts_supplied

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

compliance_report := object.union(_upstream, {
	"framework_key": "cmmc",
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"failed_controls": _failed,
	"total_controls": total_controls,
	"assessed_level": object.get(input, "cmmc_level", null),
	"standard_sizes": _t.standard_sizes,
	"failed_practices": _failed_practices,
	"facts_supplied": _facts_supplied,
})

default _failed_practices := []

_failed_practices := sort(_t.failed_practices)

compliant := _compliant

violations := _violations
