package cis_debian_11.main

# Bridge: expose cis_debian_11 under the /v1/data/<framework>/main/compliance_report
# entrypoint convention, so a caller can evaluate this framework by key
# without knowing its internal package layout.
#
# Two deliberate choices here:
#
# 1. Every field is sourced through a DEFAULTED local helper. An undefined
#    field inside an object literal makes the whole object undefined, which
#    OPA returns as {} — a silently empty compliance result rather than an
#    error. See library rule #5 in CLAUDE.md.
#
# 2. total_controls is the number of DISTINCT CIS control IDs this policy set
#    actually evaluates (counted from the violation messages), NOT the size of
#    the published CIS benchmark. Reporting the benchmark's headline number
#    would overstate coverage. See "controls_basis" in the report.

# PROVENANCE: this policy set is DERIVED — its controls are a copy of
# CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0, relabelled for Debian 11. There is no
# Debian 11-specific CIS benchmark implemented here. The report therefore
# publishes the version of the benchmark it ACTUALLY implements, plus
# derived/derived_from/applied_to so consumers can detect this.
# See README.md in this directory.

import rego.v1
import data.cis_debian_11 as bench

default _compliant := false

_compliant := bench.compliant

default _section_percentage := 0

_section_percentage := bench.compliance_percentage

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE
#
# Most of these benchmarks express controls as "violate if the fact says X".
# With NO facts, nothing iterates, no violation fires, and the benchmark
# reports near-total compliance for an assessment that evaluated nothing.
# Measured on empty input before this gate: cis_rhel10 99.0%, cis_azure 99.2%,
# cis_docker 99.1%, cis_kubernetes 99.2%, cis_aws 97.1%, cis_rhel9 71.9%.
#
# Two historical rows in a downstream results store for cis_rhel10 carry exactly the
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
	["cis_debian_11"],
)

default _bench_violations := []

_bench_violations := [v | some v in bench.violations]

default _sections := {}

_sections := bench.module_status

_total_controls := 163

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
	"framework": "cis_debian_11",
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README)",
	"version": "v3.0.0",
	"derived": true,
	"derived_from": "CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0",
	"applied_to": "Debian 11",
	"total_controls": _total_controls,
	"controls_basis": "distinct CIS control IDs evaluated by this policy set",
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"section_compliance_percentage": _section_percentage,
	"compliant": _compliant,
	"violations": _violations,
	"section_results": _sections,
}
