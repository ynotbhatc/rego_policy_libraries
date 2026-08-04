package cis_docker.main

# Bridge: expose cis_docker under the /v1/data/<framework>/main/compliance_report
# convention consumed by the Generic Framework Assessment playbook.
#
# Every field is sourced through a DEFAULTED local helper. An undefined field
# inside an object literal makes the whole object undefined, which OPA returns
# as {} — a silently empty compliance result rather than an error.
# See library rule #5 in CLAUDE.md.
#
# This benchmark previously shared a bare `package cis` namespace with 13
# unrelated benchmarks, where partial rules such as `violations` silently
# merged across all of them. It now owns `cis_docker`.

import rego.v1
import data.cis_docker as bench

default _compliant := false

_compliant := bench.compliant

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE
#
# Most of these benchmarks express controls as "violate if the fact says X".
# With NO facts, nothing iterates, no violation fires, and the benchmark
# reports near-total compliance for an assessment that evaluated nothing.
# Measured on empty input before this gate: cis_rhel10 99.0%, cis_azure 99.2%,
# cis_docker 99.1%, cis_kubernetes 99.2%, cis_aws 97.1%, cis_rhel9 71.9%.
#
# Two historical rows in compliance_results for cis_rhel10 carry exactly the
# empty-input signature (312/309/3 @ 99.04%) — this already reached the
# database.
#
# A missing-facts assessment is now reported as fully non-compliant with an
# explicit violation, never as a pass.
#
# LIMITATION: this gate detects a completely EMPTY input, not a partial one.
# An input carrying one irrelevant key still evaluates normally, so sparse or
# wrong-shaped facts can still under-report violations. Per-benchmark required-
# key assertions would be the stronger guarantee; that is a larger design change
# and is not attempted here.
# ---------------------------------------------------------------------------

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_docker"],
)

default _bench_violations := []

_bench_violations := [v | some v in bench.violations]

default _summary := {}

_summary := bench.compliance_summary

_total_controls := 108

_violations := array.concat(_bench_violations, [_no_facts_msg]) if not _facts_supplied

_violations := _bench_violations if _facts_supplied

# No facts => every control is unverified, which counts as failed, not passed.
_failed := _total_controls if not _facts_supplied

_failed := count(_bench_violations) if _facts_supplied

# Clamp: more violations than known controls must not yield a negative count.
_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

compliance_report := {
	"framework": "cis_docker",
	"benchmark": "CIS Docker Benchmark v1.8.0",
	"version": "v1.8.0",
	"total_controls": _total_controls,
	"controls_basis": "controls declared by this benchmark policy set",
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"compliant": _compliant,
	"violations": _violations,
	"section_results": _summary,
}
