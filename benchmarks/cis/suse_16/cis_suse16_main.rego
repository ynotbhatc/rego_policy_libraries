# METADATA
# title: "Bridge: expose cis_suse16 under the /v1/data/<framework>/main/compliance_report"
# custom:
#   class: security
#   framework: cis_suse_16
#   source: cis
#   domains: [linux, suse]
#   coverage:
#     checks: 0
#     cited: 0
#     expected: 336
#     found: 340
#     scope: directory
#     density: over
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_suse16.main

# Bridge: expose cis_suse16 under the /v1/data/<framework>/main/compliance_report convention, with the
# same keys as cis_rhel9.main (plus profile and standard_total). Every field is sourced through a DEFAULTED
# helper: an undefined field inside an object literal would collapse the whole report to {}.
#
# total_controls is the number of recommendations applicable to the selected profile; standard_total is
# the benchmark's 336. A control passes only when real facts (or an attestation) satisfy it, so
# failed_controls counts distinct failing recommendation ids, including those whose evidence is missing.

import data.cis_suse16 as bench
import rego.v1

default _compliant := false

_compliant := bench.compliant

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_msg := "FAIL-CLOSED: no facts supplied for cis_suse16 — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input."

default _bench_violations := []

_bench_violations := bench.all_violations

default _not_assessed := []

_not_assessed := bench.not_assessed_sections

default _missing_inputs := {}

_missing_inputs := bench.missing_inputs

_not_assessed_msgs := [sprintf("NOT ASSESSED: %s — required input not collected: %s", [name, concat(", ", _missing_inputs[name])]) | some name in _not_assessed]

default _sections := {}

_sections := bench.section_compliance

default _section_percentage := 0

_section_percentage := bench.compliance_percentage

default _coverage := 0

_coverage := bench.assessment_coverage_percentage

default _profile := "unrecognised"

_profile := bench.profile

default _profile_msgs := []

_profile_msgs := bench.profile_violations

default _total_controls := 0

_total_controls := count(bench.applicable_ids)

default _failing := 0

_failing := count(bench.failing_ids)

_violations := array.concat(_bench_violations, array.concat([_no_facts_msg], _profile_msgs)) if not _facts_supplied

_violations := array.concat(_bench_violations, array.concat(_not_assessed_msgs, _profile_msgs)) if _facts_supplied

# No facts => every control is unverified, which counts as failed, not passed.
_failed := _total_controls if not _facts_supplied

_failed := min([_total_controls, _failing]) if _facts_supplied

_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := _capped_unless_compliant(round((_passed * 100000) / _total_controls) / 1000) if _total_controls > 0

# 100 means compliant: a report that is not compliant never reads 100
_capped_unless_compliant(p) := p if {
	_compliant
} else := min([p, 99.999])

compliance_report := {
	"framework": "cis_suse16",
	"benchmark": "CIS SUSE Linux Enterprise 16 Benchmark v1.0.0",
	"version": "v1.0.0",
	"profile": _profile,
	"total_controls": _total_controls,
	"standard_total": 336,
	"controls_basis": "CIS recommendations applicable to the selected profile (every one evaluated)",
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"section_compliance_percentage": _section_percentage,
	"compliant": _compliant,
	"violations": _violations,
	"section_results": _sections,
	"sections_not_assessed": _not_assessed,
	"missing_inputs": _missing_inputs,
	"assessment_coverage_percentage": _coverage,
}
