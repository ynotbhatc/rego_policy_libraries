# CIS Microsoft 365 Foundations Benchmark v7.0.0 -- master orchestrator
#
# Aggregates the per-section reports and, just as importantly, states what
# is NOT evaluated. The benchmark defines 160 recommendations across nine
# sections. A caller that reads only `compliant` from a partial assessment
# would draw a false conclusion, so this report deliberately does not
# expose a bare tenant-wide `compliant` boolean. It exposes
# `assessed_controls_compliant` -- true only of the controls actually
# evaluated -- alongside the coverage that qualifies it.
#
# `coverage_accounting` proves the report describes the whole benchmark:
# every recommendation must land in exactly one of four buckets. Until
# 2026-08-25 six landed in none, so the buckets summed to 154 and the
# report silently described a benchmark that does not exist. A count that
# does not add up is the one kind of coverage error a reader can catch
# unaided, so it is published rather than merely asserted in a test.
#
# OPA query path: /v1/data/cis_m365_v7/main/compliance_report

package cis_m365_v7.main

import data.cis_m365_v7.admin_center
import data.cis_m365_v7.attestation
import data.cis_m365_v7.defender
import data.cis_m365_v7.entra
import data.cis_m365_v7.exchange
import data.cis_m365_v7.fabric
import data.cis_m365_v7.intune
import data.cis_m365_v7.purview
import data.cis_m365_v7.sharepoint
import data.cis_m365_v7.teams
import rego.v1

BENCHMARK_TOTAL_CONTROLS := 160

# Sections with no fact collector at all. Declared explicitly so that a
# reader (or an auditor) sees the gap rather than inferring coverage from
# the absence of violations.
not_evaluated := []

section_reports := [
	admin_center.compliance_report,
	defender.compliance_report,
	purview.compliance_report,
	intune.compliance_report,
	entra.compliance_report,
	exchange.compliance_report,
	sharepoint.compliance_report,
	teams.compliance_report,
	fabric.compliance_report,
]

# array.concat takes exactly two arrays -- fold rather than vararg.
all_violations := array.concat(
	[v | some r in section_reports; some v in r.violations],
	[v | some v in attestation.violation],
)

evaluated_controls := [c |
	some r in section_reports
	some c in r.controls
]

controls_evaluated := count(evaluated_controls)

controls_not_evaluated := BENCHMARK_TOTAL_CONTROLS - controls_evaluated

# The four buckets must partition the benchmark. Anything not evaluated
# has to be claimed by a named reason -- an unclaimed control is one the
# report does not mention at all, which reads exactly like a pass.
accounted_controls := (
	(controls_evaluated + count(attestation.REQUIRES_ATTESTATION)) +
	count(attestation.UNRESOLVED)
) + count(attestation.NOT_IMPLEMENTED)

default accounting_balanced := false

accounting_balanced if {
	accounted_controls == BENCHMARK_TOTAL_CONTROLS
}

coverage_accounting := {
	"benchmark_total": BENCHMARK_TOTAL_CONTROLS,
	"evaluated": controls_evaluated,
	"requires_attestation": count(attestation.REQUIRES_ATTESTATION),
	"unresolved": count(attestation.UNRESOLVED),
	"not_implemented": count(attestation.NOT_IMPLEMENTED),
	"accounted": accounted_controls,
	"unaccounted": BENCHMARK_TOTAL_CONTROLS - accounted_controls,
	"balanced": accounting_balanced,
}

default assessed_controls_compliant := false

assessed_controls_compliant if {
	count(all_violations) == 0
}

compliance_report := {
	"benchmark": "CIS Microsoft 365 Foundations Benchmark",
	"benchmark_version": "7.0.0",
	"benchmark_released": "2026-05-20",
	"benchmark_total_controls": BENCHMARK_TOTAL_CONTROLS,
	"controls_evaluated": controls_evaluated,
	"controls_not_evaluated": controls_not_evaluated,
	"coverage_percentage": round(controls_evaluated * 100 / BENCHMARK_TOTAL_CONTROLS),
	"evaluated_control_ids": evaluated_controls,
	"coverage_accounting": coverage_accounting,
	"sections_evaluated": section_reports,
	"sections_not_evaluated": not_evaluated,
	# Controls with no collector path are reported, never omitted -- an
	# omitted control is indistinguishable from a passing one.
	"no_collector_path": attestation.compliance_report,
	"violations": all_violations,
	"violation_count": count(all_violations),
	# Scoped deliberately: true means "no violation among the controls that
	# were evaluated", NOT "the tenant meets the benchmark".
	"assessed_controls_compliant": assessed_controls_compliant,
	"interpretation": "This is a partial assessment. assessed_controls_compliant covers only evaluated_control_ids and must not be read as benchmark compliance.",
}
