package zero_trust.automation_orchestration

import rego.v1

# ZTMM v2.0 — Automation & Orchestration cross-cutting capability. AAC
# assessment mapping; each criterion tagged with its maturity stage.
#
# CISA Zero Trust Maturity Model v2.0 defines three cross-cutting capabilities
# that span all five pillars (Identity, Devices, Networks, Applications &
# Workloads, Data): Visibility & Analytics, Automation & Orchestration, and
# Governance. Each advances through four maturity stages: Traditional, Initial,
# Advanced, Optimal.
#
# ZTMM ships no numbered control list, so the criteria below are AAC's
# operationalization of the Automation & Orchestration capability: concrete,
# assessable statements each mapped to the maturity stage it represents. A
# caller attests to each criterion via
# input.zero_trust.automation_orchestration.criteria[id] == true.
criteria := {
	"AUT-1": {
		"stage": "initial",
		"function": "Automation & Orchestration",
		"title": "Repeatable operational tasks are automated rather than performed manually",
	},
	"AUT-2": {
		"stage": "initial",
		"function": "Automation & Orchestration",
		"title": "Security policy is deployed via infrastructure-as-code, not hand configuration",
	},
	"AUT-3": {
		"stage": "advanced",
		"function": "Automation & Orchestration",
		"title": "Policy violations trigger an automated response workflow",
	},
	"AUT-4": {
		"stage": "advanced",
		"function": "Automation & Orchestration",
		"title": "Provisioning and deprovisioning across pillars is orchestrated end to end",
	},
	"AUT-5": {
		"stage": "advanced",
		"function": "Automation & Orchestration",
		"title": "Incident response playbooks are codified and machine-executable",
	},
	"AUT-6": {
		"stage": "optimal",
		"function": "Automation & Orchestration",
		"title": "Response to threats is automated in near real time with minimal human intervention",
	},
	"AUT-7": {
		"stage": "optimal",
		"function": "Automation & Orchestration",
		"title": "Orchestration adapts dynamically to changing risk using analytics-driven signals",
	},
}

attested(id) if input.zero_trust.automation_orchestration.criteria[id] == true

violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Automation & Orchestration] %s (%s): %s — not met", [id, m.stage, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Automation & Orchestration",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
