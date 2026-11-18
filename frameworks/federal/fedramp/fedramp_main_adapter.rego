# METADATA
# title: "FedRAMP main adapter — exposes the standard contract"
# custom:
#   class: compliance
#   framework: fedramp
#   source: fedramp
#   domains: [us-federal, cloud]
#   coverage:
#     checks: 10
#     cited: 10
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package fedramp.main

import data.fedramp as f
import rego.v1

# FedRAMP main adapter — exposes the standard contract
# (compliance_report, violations, compliant) at /v1/data/fedramp/main/...
# on top of the existing `package fedramp` policy module, which uses
# its own names (fedramp_compliant, all_violations, fedramp_compliance_report).
#
# Generic playbook contract:
#   /v1/data/fedramp/main/compliance_report
#
# The upstream module's fedramp_compliance_report references input fields
# (impact_level, etc.) directly.
# We compute the area summary here from the upstream violation_* sets so
# the adapter's compliance_report is always defined.

default compliant := false

default impact_level := "unknown"

default assessed_at := "unknown"

compliant := f.fedramp_compliant

impact_level := input.impact_level
assessed_at := input.assessment_date

violations := f.all_violations

# Per-area summaries — recomputed locally instead of pulling from the
# upstream report (which is input-dependent).
area_summary := {name: {"violations": count(area), "compliant": count(area) == 0} | some name, area in f.assessment_areas}

# total_controls is the number of checks this module evaluates at the declared impact level (10 at Low,
# 11 at Moderate, 12 at High or when the level is not declared, plus PS-3(3) when the agency sets a
# US-person criterion). It is NOT the FedRAMP baseline size: that is baseline_size, reported beside it
# (Rev 5: Low 156, Moderate 323, High 410, LI-SaaS 156), so the evaluated count is never read as coverage.
total_controls := count(f.applicable_checks)

default kev_note := "KEV due dates were not assessed: no continuous_monitoring.kev_findings supplied (not a pass, not a violation)"

kev_note := "KEV due dates assessed from continuous_monitoring.kev_findings" if f.kev_assessed

failed_controls := count(f.failed_checks)

compliance_report := {
	"framework": "FedRAMP",
	"regulation": "Federal Risk and Authorization Management Program",
	"baseline": "NIST SP 800-53 Rev 5 + FedRAMP Rev 5 baselines (selected checks only, not a full baseline assessment)",
	"impact_level": impact_level,
	"impact_level_normalized": f.impact_level_norm,
	"assessed_at": assessed_at,
	"compliant": compliant,
	"violations": violations,
	"violation_count": count(violations),
	"failed_controls": failed_controls,
	"failed_control_ids": sort(f.failed_checks),
	"total_controls": total_controls,
	"controls_evaluated": sort(f.applicable_checks),
	"baseline_size": f.baseline_size,
	"kev_assessed": f.kev_assessed,
	"kev_note": kev_note,
	"baseline_sizes": f.baseline_sizes,
	"coverage_note": "total_controls counts the checks this module evaluates; baseline_size is the number of controls the FedRAMP Rev 5 baseline selects at this impact level (null when the level is not declared). The module does not evaluate the baseline.",
	"area_summary": area_summary,
}
