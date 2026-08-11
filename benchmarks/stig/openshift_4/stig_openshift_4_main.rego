# Wrapper exposing the OpenShift 4 STIG compliance report at the package path
# expected by AAC's generic_framework_assessment.yml convention:
#
#   /v1/data/stig_openshift_4/main/compliance_report
#
# All policy logic lives in stig_openshift_4_complete.rego under
# `package stig.openshift_4`. This file is a thin alias so framework-key-based
# routing (`framework: stig_openshift_4` → URL `/v1/data/stig_openshift_4/main`)
# resolves cleanly without renaming the canonical package.

package stig_openshift_4.main

import data.stig.openshift_4
import rego.v1

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE
#
# The STIG rules are written as "finding is open if the fact says X". With NO
# facts, nothing iterates, no finding opens, and the benchmark reports a clean
# pass for an assessment that evaluated nothing. Measured on empty input before
# this gate: stig_openshift_4 reported compliant=true at 100% (24/24 passed),
# and stig_kubernetes 86% (25/29 passed).
#
# That is the same empty-input signature the CIS bridges were gated against in
# #52 — and unlike a report that collapses to {} (which the playbook now fails
# on), a bogus PASS is written to compliance_results as a green row. It is the
# more dangerous of the two failure modes, which is why it is fixed first.
#
# A missing-facts assessment is now reported as fully non-compliant with an
# explicit finding, never as a pass.
#
# LIMITATION: this gate detects a completely EMPTY input, not a partial one.
# An input carrying one irrelevant key still evaluates normally, so sparse or
# wrong-shaped facts can still under-report findings.
# ---------------------------------------------------------------------------

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {
	"rule_title": "FAIL-CLOSED: no facts supplied for stig_openshift_4 — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	"severity": "CAT I",
	"status": "open",
}

default _upstream := {}

_upstream := openshift_4.compliance_report

default _total_controls := 0

_total_controls := _upstream.total_controls

default _upstream_open := []

_upstream_open := [f | some f in _upstream.open_findings]

_open_findings := array.concat(_upstream_open, [_no_facts_finding]) if not _facts_supplied

_open_findings := _upstream_open if _facts_supplied

# No facts => every control is unverified, which counts as failed, not passed.
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

# Upstream report uses "open_findings"; the generic playbook contract expects
# "violations". Merge a violations alias into the report so callers can use
# either name. The gated values override the upstream ones.
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
