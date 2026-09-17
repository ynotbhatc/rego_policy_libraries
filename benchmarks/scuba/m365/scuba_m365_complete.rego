# CISA SCuBA — Secure Configuration Baselines for Microsoft 365
# Master orchestrator over the seven product baselines:
#
#   MS.AAD           Microsoft Entra ID          34 policies
#   MS.DEFENDER      Defender for Office 365     19 policies
#   MS.EXO           Exchange Online             12 policies
#   MS.POWERBI       Power BI                     8 policies
#   MS.POWERPLATFORM Power Platform               9 policies
#   MS.SHAREPOINT    SharePoint & OneDrive        8 policies
#   MS.TEAMS         Microsoft Teams             14 policies
#                                       total   104 policies
#
# Source: cisagov/ScubaGear baseline documents (TLP:CLEAR). The SCuBA
# baselines carry no document-level version; each policy ID is versioned
# individually (the v-suffix) and this library pins the IDs it implements
# in the per-product modules. Assessment against these baselines is
# required for U.S. federal civilian agencies by CISA BOD 25-01; they
# apply equally to any M365 tenant.
#
# Criticality is part of the baseline: SHALL policies are mandatory,
# SHOULD policies are recommended (many carry mission-need qualifiers).
# `compliant` is strict — zero violations of any criticality. A caller
# that accepts SHOULD deviations through an exception process can read
# `shall_compliant`, which is true when no SHALL policy is violated;
# nothing is hidden either way, both counts are always reported.
#
# Fail-closed: absent facts fire every policy in every product module —
# an empty assessment reports 104 violations, never a pass.
#
# OPA query path: /v1/data/scuba_m365/main/compliance_report

package scuba_m365.main

import data.scuba_m365.aad
import data.scuba_m365.defender
import data.scuba_m365.exo
import data.scuba_m365.powerbi
import data.scuba_m365.powerplatform
import data.scuba_m365.sharepoint
import data.scuba_m365.teams
import rego.v1

BASELINE_TOTAL_POLICIES := 104

product_reports := [
	aad.compliance_report,
	defender.compliance_report,
	exo.compliance_report,
	powerbi.compliance_report,
	powerplatform.compliance_report,
	sharepoint.compliance_report,
	teams.compliance_report,
]

all_violations := [v |
	some r in product_reports
	some v in r.violations
]

policies_evaluated := sum([r.controls_evaluated | some r in product_reports])

shall_violation_count := sum([r.shall_violation_count | some r in product_reports])

should_violation_count := sum([r.should_violation_count | some r in product_reports])

default compliant := false

compliant if {
	count(all_violations) == 0
}

default shall_compliant := false

shall_compliant if {
	shall_violation_count == 0
}

# Every implemented policy must belong to exactly one product module; a
# count that does not add up is the one coverage error a reader can catch
# unaided, so it is published rather than asserted.
default accounting_balanced := false

accounting_balanced if {
	policies_evaluated == BASELINE_TOTAL_POLICIES
}

product_summary := {r.baseline: {
	"product": r.product,
	"compliant": r.compliant,
	"violation_count": r.violation_count,
	"shall_violation_count": r.shall_violation_count,
	"should_violation_count": r.should_violation_count,
} |
	some r in product_reports
}

# Defaults — an undefined input field would collapse the report object.
default assessment_date := "unknown"

assessment_date := input.assessment_date

default tenant_name := "unknown"

tenant_name := input.tenant_name

compliance_report := {
	"framework": "CISA SCuBA Secure Configuration Baselines for Microsoft 365",
	"version": "per-policy versioning (IDs pinned in modules); cisagov/ScubaGear baselines; CISA BOD 25-01",
	"tenant_name": tenant_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"shall_compliant": shall_compliant,
	"total_controls": BASELINE_TOTAL_POLICIES,
	"policies_evaluated": policies_evaluated,
	"accounting_balanced": accounting_balanced,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"shall_violation_count": shall_violation_count,
	"should_violation_count": should_violation_count,
	"product_summary": product_summary,
	"scope_note": "SHALL = mandatory, SHOULD = recommended per the baseline; shall_compliant reports the mandatory floor. SHOULD deviations for mission need belong in the caller's documented exception process — this report never suppresses them.",
}
