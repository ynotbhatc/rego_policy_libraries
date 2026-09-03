# Framework-key entrypoint alias with the fail-closed gate (pattern from
# stig_kubernetes_main.rego / rego PR #52 lineage): an empty input must
# report fully non-compliant with an explicit finding, never a pass.

package stig.amazon_linux_2023.main

import data.stig.amazon_linux_2023
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"rule_title": "FAIL-CLOSED: no facts supplied for stig.amazon_linux_2023 — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	"severity": "CAT I",
	"status": "Open",
}

_upstream := amazon_linux_2023.compliance_report

_total_controls := _upstream.total_controls

_upstream_open := [f | some f in _upstream.open_findings]

_open_findings := array.concat(_upstream_open, [_no_facts_finding]) if not _facts_supplied

_open_findings := _upstream_open if _facts_supplied

_failed := _total_controls if not _facts_supplied

_failed := count(_upstream_open) if _facts_supplied

_passed := 0 if not _facts_supplied

_passed := max([0, _total_controls - _failed]) if _facts_supplied

default _percentage := 0

_percentage := round((_passed * 100) / _total_controls) if _total_controls > 0

default _compliant := false

_compliant if {
	_facts_supplied
	count(_open_findings) == 0
}

compliance_report := object.union(_upstream, {
	"compliant": _compliant,
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"open_findings": _open_findings,
	"violations": _open_findings,
	"violation_count": count(_open_findings),
	"facts_supplied": _facts_supplied,
})

compliant := _compliant

violations := _open_findings
