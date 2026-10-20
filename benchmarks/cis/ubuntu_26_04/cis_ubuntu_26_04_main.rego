# METADATA
# title: "Bridge: expose cis_ubuntu_26_04 under the /v1/data/<framework>/main/compliance_report"
# custom:
#   class: security
#   framework: cis_ubuntu_26_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 0
#     cited: 0
#     expected: 350
#     found: 355
#     scope: directory
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_26_04.main

# Bridge: expose cis_ubuntu_26_04 under the /v1/data/<framework>/main/compliance_report convention, with the
# same keys as cis_rhel9.main (plus profile and standard_total). Every field is sourced through a DEFAULTED
# helper: an undefined field inside an object literal would collapse the whole report to {}.
#
# total_controls is the number of recommendations applicable to the selected profile; standard_total is
# the benchmark's 350. A control passes only when real facts (or an attestation) satisfy it, so
# failed_controls counts distinct failing recommendation ids, including those whose evidence is missing.

import data.cis_ubuntu_26_04 as bench
import rego.v1

default _compliant := false

_compliant := bench.compliant

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_msg := "FAIL-CLOSED: no facts supplied for cis_ubuntu_26_04 — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input."

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

default _profile := "level1_server"

_profile := bench.profile

default _total_controls := 0

_total_controls := count(bench.applicable_ids)

default _failing := 0

_failing := count(bench.failing_ids)

_violations := array.concat(_bench_violations, [_no_facts_msg]) if not _facts_supplied

_violations := array.concat(_bench_violations, _not_assessed_msgs) if _facts_supplied

# No facts => every control is unverified, which counts as failed, not passed.
_failed := _total_controls if not _facts_supplied

_failed := min([_total_controls, _failing]) if _facts_supplied

_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

compliance_report := {
	"framework": "cis_ubuntu_26_04",
	"benchmark": "CIS Ubuntu Linux 26.04 LTS Benchmark v1.0.0",
	"version": "v1.0.0",
	"profile": _profile,
	"total_controls": _total_controls,
	"standard_total": 350,
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
