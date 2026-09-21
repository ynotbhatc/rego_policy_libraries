package zero_trust.governance

import rego.v1

# ZTMM v2.0 — Governance cross-cutting capability. AAC assessment mapping; each
# criterion tagged with its maturity stage.
#
# CISA Zero Trust Maturity Model v2.0 defines three cross-cutting capabilities
# that span all five pillars (Identity, Devices, Networks, Applications &
# Workloads, Data): Visibility & Analytics, Automation & Orchestration, and
# Governance. Each advances through four maturity stages: Traditional, Initial,
# Advanced, Optimal.
#
# ZTMM ships no numbered control list, so the criteria below are AAC's
# operationalization of the Governance capability: concrete, assessable
# statements each mapped to the maturity stage it represents. A caller attests
# to each criterion via input.zero_trust.governance.criteria[id] == true.
criteria := {
	"GOV-1": {
		"stage": "initial",
		"function": "Governance",
		"title": "A documented Zero Trust strategy exists and is approved by leadership",
	},
	"GOV-2": {
		"stage": "initial",
		"function": "Governance",
		"title": "Roles and responsibilities for Zero Trust are defined and assigned",
	},
	"GOV-3": {
		"stage": "initial",
		"function": "Governance",
		"title": "Security policies are documented and published to affected staff",
	},
	"GOV-4": {
		"stage": "advanced",
		"function": "Governance",
		"title": "Policies are reviewed and updated on a defined recurring cadence",
	},
	"GOV-5": {
		"stage": "advanced",
		"function": "Governance",
		"title": "Compliance with Zero Trust policy is measured and reported to leadership",
	},
	"GOV-6": {
		"stage": "advanced",
		"function": "Governance",
		"title": "Risk-based exceptions to policy are formally tracked, approved, and time-bound",
	},
	"GOV-7": {
		"stage": "optimal",
		"function": "Governance",
		"title": "Policy is enforced automatically and updated dynamically from risk signals",
	},
	"GOV-8": {
		"stage": "optimal",
		"function": "Governance",
		"title": "Governance is continuously improved through enterprise-wide feedback loops",
	},
}

attested(id) if input.zero_trust.governance.criteria[id] == true

violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Governance] %s (%s): %s — not met", [id, m.stage, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Governance",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
