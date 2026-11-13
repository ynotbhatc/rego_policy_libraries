# METADATA
# title: "Bridge: expose cis_rhel10 under the /v1/data/<framework>/main/compliance_report entrypoint"
# custom:
#   class: security
#   framework: cis_rhel_10
#   source: cis
#   domains: [linux, rhel]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: false
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_rhel10.main

# Framework-key entrypoint bridge. The product addresses every framework by key at
# /v1/data/<key>/main/compliance_report; this package maps the key cis_rhel10 onto
# cis.rhel_10.main. Fail-closed: with no facts the report is non-compliant with an
# explicit finding, and the report object is always defined (never {}).

import data.cis.rhel_10.main as _t
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"control": "FAIL-CLOSED",
	"title": "no facts supplied for cis_rhel10 — the assessment could not be evaluated; this is not a passing result",
	"severity": "high",
	"status": "open",
}

default _target_compliant := false

_target_compliant if _t.compliance_report.compliant == true

default _target_violations := []

_target_violations := [v | some v in _t.compliance_report.violations]

_violations := array.concat(_target_violations, [_no_facts_finding]) if not _facts_supplied

_violations := _target_violations if _facts_supplied

default _compliant := false

_compliant if {
	_facts_supplied
	_target_compliant
	count(_violations) == 0
}

default _upstream := {}

_upstream := _t.compliance_report

compliance_report := object.union(_upstream, {
	"framework_key": "cis_rhel10",
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"facts_supplied": _facts_supplied,
})

compliant := _compliant

violations := _violations
