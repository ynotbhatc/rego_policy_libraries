# CIS Microsoft 365 Foundations Benchmark v7.0.0 -- master orchestrator
#
# Aggregates the per-section reports and, just as importantly, states what
# is NOT evaluated. The benchmark defines 160 recommendations across nine
# sections; this library evaluates 14 of them. A caller that reads only
# `compliant` from a partial assessment would draw a false conclusion, so
# this report deliberately does not expose a bare tenant-wide `compliant`
# boolean. It exposes `assessed_controls_compliant` -- true only of the
# controls actually evaluated -- alongside the coverage that qualifies it.
#
# OPA query path: /v1/data/cis_m365_v7/main/compliance_report

package cis_m365_v7.main

import data.cis_m365_v7.admin_center
import data.cis_m365_v7.attestation
import data.cis_m365_v7.defender
import data.cis_m365_v7.entra
import data.cis_m365_v7.exchange
import data.cis_m365_v7.intune
import data.cis_m365_v7.purview
import data.cis_m365_v7.sharepoint
import rego.v1

BENCHMARK_TOTAL_CONTROLS := 160

# Sections with no fact collector at all. Declared explicitly so that a
# reader (or an auditor) sees the gap rather than inferring coverage from
# the absence of violations.
not_evaluated := [
	{
		"section": "8",
		"name": "Microsoft Teams admin center",
		"section_total_controls": 17,
		"reason": "collector returns only a Teams app count and Microsoft Secure Score; neither establishes a CIS control",
	},
	{
		"section": "9",
		"name": "Microsoft Fabric",
		"section_total_controls": 12,
		"reason": "collector returns only Microsoft Secure Score; Fabric tenant settings require the Fabric Admin REST API, not Graph",
	},
]

section_reports := [
	admin_center.compliance_report,
	defender.compliance_report,
	purview.compliance_report,
	intune.compliance_report,
	entra.compliance_report,
	exchange.compliance_report,
	sharepoint.compliance_report,
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
