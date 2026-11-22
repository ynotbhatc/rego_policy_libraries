# CISA SCuBA — Secure Configuration Baselines for Microsoft 365
# Master orchestrator over the seven product baselines:
#
#   MS.AAD           Microsoft Entra ID          34 policies
#   MS.EXO           Exchange Online             12 policies
#   MS.POWERBI       Power BI                     8 policies
#   MS.POWERPLATFORM Power Platform               9 policies
#   MS.SECURITYSUITE Security Suite              24 policies
#   MS.SHAREPOINT    SharePoint & OneDrive        8 policies
#   MS.TEAMS         Microsoft Teams             14 policies
#                                       total   109 policies
#
# Source: cisagov/ScubaGear v2.0.0 baseline documents (TLP:CLEAR). Each
# policy ID is versioned individually (the v-suffix) and this library pins
# the IDs it implements in the per-product modules; the 109 IDs are every
# active policy in the v2.0.0 baselines. v2.0.0 removed the Defender
# baseline (MS.DEFENDER.*, 19 policies here before) in favour of the
# Security Suite baseline. Assessment against these baselines is
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
# Deprecated input path (one release): a collector that still sends only
# scuba.defender.* is evaluated against the Security Suite baseline through
# the scuba_m365.defender shim's one-to-one field projection; the Security
# Suite policies with no legacy fact fail closed. scuba.securitysuite.*,
# when present, always wins. The report names the path used
# (securitysuite_input_path). MS.DEFENDER ids are never counted here.
#
# Fail-closed: absent facts fire every policy in every product module —
# an empty assessment reports 109 violations, never a pass.
#
# OPA query path: /v1/data/scuba_m365/main/compliance_report

# METADATA
# title: "CISA SCuBA — Secure Configuration Baselines for Microsoft 365"
# custom:
#   class: security
#   framework: scuba_m365
#   source: cisa
#   domains: [saas, m365]
#   coverage:
#     checks: 0
#     cited: 0
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package scuba_m365.main

import data.scuba_m365.aad
import data.scuba_m365.defender
import data.scuba_m365.exo
import data.scuba_m365.powerbi
import data.scuba_m365.powerplatform
import data.scuba_m365.securitysuite
import data.scuba_m365.sharepoint
import data.scuba_m365.teams
import rego.v1

BASELINE_TOTAL_POLICIES := 109

_scuba := object.get(input, "scuba", {})

_has(key) if is_object(_scuba[key])

_LEGACY_PATH := "scuba.defender (deprecated; one-to-one fields only)"

# Which input the Security Suite baseline is evaluated from.
securitysuite_input_path := "scuba.securitysuite" if {
	_has("securitysuite")
} else := _LEGACY_PATH if {
	_has("defender")
} else := "none"

securitysuite_report := securitysuite.compliance_report if {
	securitysuite_input_path != _LEGACY_PATH
} else := r if {
	r := securitysuite.compliance_report with input.scuba.securitysuite as defender.as_securitysuite_input
}

input_note := "Security Suite evaluated from the deprecated scuba.defender.* input: only the one-to-one facts are translated, the Security Suite policies without a legacy fact fail closed. Move the collector to scuba.securitysuite.*; the scuba.defender path is removed in the next minor release." if {
	securitysuite_input_path == _LEGACY_PATH
} else := ""

product_reports := [
	aad.compliance_report,
	exo.compliance_report,
	powerbi.compliance_report,
	powerplatform.compliance_report,
	securitysuite_report,
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
	"version": "ScubaGear v2.0.0 baselines (per-policy IDs pinned in modules); CISA BOD 25-01",
	"tenant_name": tenant_name,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"shall_compliant": shall_compliant,
	"total_controls": BASELINE_TOTAL_POLICIES,
	"policies_evaluated": policies_evaluated,
	"accounting_balanced": accounting_balanced,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"failed_controls": min([BASELINE_TOTAL_POLICIES, count(all_violations)]),
	"shall_violation_count": shall_violation_count,
	"should_violation_count": should_violation_count,
	"product_summary": product_summary,
	"securitysuite_input_path": securitysuite_input_path,
	"input_note": input_note,
	"scope_note": "SHALL = mandatory, SHOULD = recommended per the baseline; shall_compliant reports the mandatory floor. SHOULD deviations for mission need belong in the caller's documented exception process — this report never suppresses them.",
}
