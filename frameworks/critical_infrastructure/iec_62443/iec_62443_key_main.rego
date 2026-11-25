# METADATA
# title: "Bridge: expose iec_62443 under the /v1/data/<framework>/main/compliance_report entrypoint"
# custom:
#   class: ot
#   framework: iec_62443
#   source: iec
#   domains: [ot, industrial]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: false
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package iec_62443.main

# Framework-key entrypoint bridge. The product addresses every framework by key at
# /v1/data/<key>/main/compliance_report; this package maps the key iec_62443 onto
# iec_62443_main. Fail-closed: with no facts the report is non-compliant with an
# explicit finding, and the report object is always defined (never {}).

import data.iec_62443_main as _t
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"control": "FAIL-CLOSED",
	"title": "no facts supplied for iec_62443 — the assessment could not be evaluated; this is not a passing result",
	"severity": "high",
	"status": "open",
}

default _target_compliant := false

_target_compliant if _t.iec_62443_compliant == true

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

_upstream := _t.iec_62443_compliance_report

# Control universe for the product's passed = total - failed arithmetic (round 3): the 51 system security
# requirements of IEC 62443-3-3 (SR 1.1 to SR 7.8, counted by the orchestrator as total_srs / passing_srs) plus one
# control for each of the four process modules that carry no per-requirement count (Part 2-1, 2-3, 2-4 and 3-2),
# 55 in all. A control fails when it has a finding. violation_count stays the finding count: one requirement can
# carry several findings (per system, per zone, per security level), so findings are not controls and are never
# used as the failed count. The "no facts supplied" finding is not a control; with no facts every control fails
# on its own evidence-missing findings. (Until round 3 the total was 58, a figure from before findings per
# system existed, raised to the finding count, which was 108 on empty input.)
_part_flags := [_t.part2_1_compliant, _t.part2_3_compliant, _t.part2_4_compliant, _t.part3_2_compliant]

total_controls := _t.total_srs + count(_part_flags)

_failed_parts := count([f | some f in _part_flags; f != true])

# with no input document at all the per-FR reports are undefined, so no requirement is counted as passing
default _passing_srs := 0

_passing_srs := _t.passing_srs

_failed_srs := _t.total_srs - _passing_srs

_failed_controls := _failed_srs + _failed_parts

compliance_report := object.union(_upstream, {
	"framework_key": "iec_62443",
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
