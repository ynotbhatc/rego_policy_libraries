package zero_trust.visibility_analytics

import rego.v1

# ZTMM v2.0 — Visibility & Analytics cross-cutting capability. AAC assessment
# mapping; each criterion tagged with its maturity stage.
#
# CISA Zero Trust Maturity Model v2.0 defines three cross-cutting capabilities
# that span all five pillars (Identity, Devices, Networks, Applications &
# Workloads, Data): Visibility & Analytics, Automation & Orchestration, and
# Governance. Each advances through four maturity stages: Traditional, Initial,
# Advanced, Optimal.
#
# ZTMM ships no numbered control list, so the criteria below are AAC's
# operationalization of the Visibility & Analytics capability: concrete,
# assessable statements each mapped to the maturity stage it represents. A
# caller attests to each criterion via
# input.zero_trust.visibility_analytics.criteria[id] == true.
criteria := {
	"VIS-1": {
		"stage": "initial",
		"function": "Visibility & Analytics",
		"title": "Centralized logging captures security-relevant events across all five pillars",
	},
	"VIS-2": {
		"stage": "initial",
		"function": "Visibility & Analytics",
		"title": "Logs are retained for a defined period sufficient to support investigations",
	},
	"VIS-3": {
		"stage": "advanced",
		"function": "Visibility & Analytics",
		"title": "Analytics correlate signals across pillars to detect cross-domain threats",
	},
	"VIS-4": {
		"stage": "advanced",
		"function": "Visibility & Analytics",
		"title": "Telemetry coverage is measured and gaps are tracked to closure",
	},
	"VIS-5": {
		"stage": "advanced",
		"function": "Visibility & Analytics",
		"title": "Anomaly detection baselines normal behavior and alerts on deviation",
	},
	"VIS-6": {
		"stage": "optimal",
		"function": "Visibility & Analytics",
		"title": "Analytics feed automated, real-time access and policy decisions",
	},
	"VIS-7": {
		"stage": "optimal",
		"function": "Visibility & Analytics",
		"title": "Visibility is continuous and enterprise-wide with dynamic, situational dashboards",
	},
}

attested(id) if input.zero_trust.visibility_analytics.criteria[id] == true

violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Visibility & Analytics] %s (%s): %s — not met", [id, m.stage, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Visibility & Analytics",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
