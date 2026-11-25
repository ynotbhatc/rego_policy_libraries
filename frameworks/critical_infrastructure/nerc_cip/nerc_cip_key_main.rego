# METADATA
# title: "Bridge: expose nerc_cip under the /v1/data/<framework>/main/compliance_report entrypoint"
# custom:
#   class: ot
#   framework: nerc_cip
#   source: nerc
#   domains: [ot, energy, bulk-electric]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: false
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package nerc_cip.main

# Framework-key entrypoint bridge. The product addresses every framework by key at
# /v1/data/<key>/main/compliance_report; this package maps the key nerc_cip onto
# nerc_cip_main. Fail-closed: with no facts the report is non-compliant with an
# explicit finding, and the report object is always defined (never {}).

import data.nerc_cip_main as _t
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"control": "FAIL-CLOSED",
	"title": "no facts supplied for nerc_cip — the assessment could not be evaluated; this is not a passing result",
	"severity": "high",
	"status": "open",
}

default _target_compliant := false

_target_compliant if _t.report.overall_compliant == true

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

_upstream := _t.report

# Control universe for the product's passed = total - failed arithmetic (round 3): the 14 CIP standards
# CIP-002 to CIP-015 that nerc_cip_main evaluates (standards_total). A standard is one control and fails when it
# is not compliant; failed_controls counts standards. violation_count stays the finding count: a per-item rule
# yields one finding per person, system or link ("CIP-004: Person p1 has not completed CIP training"), so findings
# are not controls and are never used as the failed count. The "no facts supplied" finding is not a control; with
# no facts every standard fails on its own evidence-missing findings. (Until round 3 the total was 48, the number
# of rules, raised to the finding count, which is not a fixed property.)
total_controls := _t.report.standards_total

_failed_controls := _t.report.standards_total - _t.report.standards_passing

compliance_report := object.union(_upstream, {
	"framework_key": "nerc_cip",
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"failed_controls": _failed_controls,
	"passed_controls": total_controls - _failed_controls,
	"not_applicable_controls": 0,
	"total_controls": total_controls,
	"facts_supplied": _facts_supplied,
})

compliant := _compliant

violations := _violations
