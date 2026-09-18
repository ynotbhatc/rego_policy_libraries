# CIS Controls v8.1 — master orchestrator
#
# Aggregates the 18 control modules (cis_controls_v8.c01 .. c18) into one
# framework report with cumulative Implementation Group (IG1 ⊆ IG2 ⊆ IG3)
# scoring. Fail-closed: a safeguard that is not attested `true` in
# `input.cis_controls.safeguards` counts as a gap.
#
# Entry point: data.cis_controls_v8.main.compliance_report

package cis_controls_v8.main

import rego.v1

import data.cis_controls_v8.c01
import data.cis_controls_v8.c02
import data.cis_controls_v8.c03
import data.cis_controls_v8.c04
import data.cis_controls_v8.c05
import data.cis_controls_v8.c06
import data.cis_controls_v8.c07
import data.cis_controls_v8.c08
import data.cis_controls_v8.c09
import data.cis_controls_v8.c10
import data.cis_controls_v8.c11
import data.cis_controls_v8.c12
import data.cis_controls_v8.c13
import data.cis_controls_v8.c14
import data.cis_controls_v8.c15
import data.cis_controls_v8.c16
import data.cis_controls_v8.c17
import data.cis_controls_v8.c18

# Per-control reports, in control order.
reports := [
	c01.compliance_report, c02.compliance_report, c03.compliance_report,
	c04.compliance_report, c05.compliance_report, c06.compliance_report,
	c07.compliance_report, c08.compliance_report, c09.compliance_report,
	c10.compliance_report, c11.compliance_report, c12.compliance_report,
	c13.compliance_report, c14.compliance_report, c15.compliance_report,
	c16.compliance_report, c17.compliance_report, c18.compliance_report,
]

# Every safeguard across all 18 controls: id -> {ig, title}.
all_safeguards := object.union_n([
	c01.safeguards, c02.safeguards, c03.safeguards,
	c04.safeguards, c05.safeguards, c06.safeguards,
	c07.safeguards, c08.safeguards, c09.safeguards,
	c10.safeguards, c11.safeguards, c12.safeguards,
	c13.safeguards, c14.safeguards, c15.safeguards,
	c16.safeguards, c17.safeguards, c18.safeguards,
])

# All violations, flattened from every control's report (no array.concat needed).
all_violations := [v | some r in reports; some v in r.violations]

attested(id) if input.cis_controls.safeguards[id] == true

# Cumulative IG sets — IG2 includes IG1, IG3 includes IG2.
ig_ids(max_ig) := {id | some id, m in all_safeguards; m.ig <= max_ig}

ig_gaps(max_ig) := {id | some id in ig_ids(max_ig); not attested(id)}

ig_summary(max_ig) := {
	"safeguards": count(ig_ids(max_ig)),
	"gaps": count(ig_gaps(max_ig)),
	"compliant": count(ig_gaps(max_ig)) == 0,
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "CIS Controls v8.1",
	"controls_evaluated": count(reports),
	"total_safeguards": count(all_safeguards),
	"violations": all_violations,
	"violation_count": count(all_violations),
	"implementation_groups": {
		"ig1": ig_summary(1),
		"ig2": ig_summary(2),
		"ig3": ig_summary(3),
	},
	"compliant": compliant,
}
