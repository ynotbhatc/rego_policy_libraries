# METADATA
# title: "Bridge: expose ami_nist_ir7628 under the /v1/data/<framework>/main/compliance_report entrypoint"
# custom:
#   class: ot
#   framework: ami
#   source: nist
#   domains: [ot, energy, smart-grid]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package ami_nist_ir7628.main

# Framework-key entrypoint bridge. The product addresses every framework by key at
# /v1/data/<key>/main/compliance_report; this package maps the key ami_nist_ir7628 onto
# ami.nist_ir7628.complete. Fail-closed: with no facts the report is non-compliant with an
# explicit finding, and the report object is always defined (never {}).

import data.ami.nist_ir7628.complete as _t
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"control": "FAIL-CLOSED",
	"title": "no facts supplied for ami_nist_ir7628 — the assessment could not be evaluated; this is not a passing result",
	"severity": "high",
	"status": "open",
}

default _target_compliant := false

_target_compliant if count(_t.all_violations) == 0

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

_upstream := _t.compliance_assessment

# SG.AC (6), SG.AU (5), SG.IA (4), SG.SC (6), SG.CM (5), SG.IR (6) controls
# across the six family modules. Keep in step with the modules. Never fewer
# controls than findings: the store derives passed = total - failed.
_declared_controls := 32

total_controls := max([_declared_controls, count(_violations)])

compliance_report := object.union(_upstream, {
	"framework_key": "ami_nist_ir7628",
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"failed_controls": min([total_controls, count(_violations)]),
	"total_controls": total_controls,
	"facts_supplied": _facts_supplied,
})

compliant := _compliant

violations := _violations
