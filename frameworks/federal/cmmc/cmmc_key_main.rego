# METADATA
# title: "Bridge: expose cmmc under the /v1/data/<framework>/main/compliance_report entrypoint"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
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

_target_violations := [v | some v in _t.all_violations]

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

compliance_report := object.union(_upstream, {
	"framework_key": "cmmc",
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"facts_supplied": _facts_supplied,
})

compliant := _compliant

violations := _violations
