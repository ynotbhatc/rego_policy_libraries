package zero_trust.devices

import rego.v1

# ZTMM v2.0 — Devices pillar. AAC assessment mapping; each criterion tagged with its maturity stage.
#
# CISA Zero Trust Maturity Model v2.0 defines the Devices pillar across four
# cross-cutting functions:
#   - Policy Enforcement & Compliance Monitoring
#   - Asset & Supply Chain Risk Management
#   - Resource Access
#   - Device Threat Protection
# and four maturity stages: Traditional, Initial, Advanced, Optimal.
#
# ZTMM ships no numbered control list, so the criteria below are AAC's
# operationalization of the pillar: concrete, assessable statements each mapped
# to the function it advances and the maturity stage it represents. A caller
# attests to each criterion via input.zero_trust.devices.criteria[id] == true.
criteria := {
	"DEV-1": {
		"stage": "initial",
		"function": "Asset & Supply Chain Risk Management",
		"title": "All devices are enrolled in a managed inventory",
	},
	"DEV-2": {
		"stage": "initial",
		"function": "Policy Enforcement & Compliance Monitoring",
		"title": "Every enrolled device has a documented compliance baseline",
	},
	"DEV-3": {
		"stage": "initial",
		"function": "Device Threat Protection",
		"title": "Anti-malware / EDR is deployed on all endpoints",
	},
	"DEV-4": {
		"stage": "advanced",
		"function": "Policy Enforcement & Compliance Monitoring",
		"title": "Device compliance state is evaluated automatically, not manually",
	},
	"DEV-5": {
		"stage": "advanced",
		"function": "Resource Access",
		"title": "Device compliance is a precondition for resource access",
	},
	"DEV-6": {
		"stage": "advanced",
		"function": "Asset & Supply Chain Risk Management",
		"title": "Supply-chain provenance is verified for procured hardware and firmware",
	},
	"DEV-7": {
		"stage": "advanced",
		"function": "Device Threat Protection",
		"title": "EDR telemetry is centrally collected and correlated for threat detection",
	},
	"DEV-8": {
		"stage": "optimal",
		"function": "Resource Access",
		"title": "Continuous device posture feeds real-time access decisions",
	},
	"DEV-9": {
		"stage": "optimal",
		"function": "Policy Enforcement & Compliance Monitoring",
		"title": "Non-compliant devices are automatically remediated or isolated",
	},
	"DEV-10": {
		"stage": "optimal",
		"function": "Asset & Supply Chain Risk Management",
		"title": "Asset inventory is reconciled in real time across the full device lifecycle",
	},
	"DEV-11": {
		"stage": "optimal",
		"function": "Device Threat Protection",
		"title": "Threat response on endpoints is automated and integrated with access policy",
	},
}

attested(id) if input.zero_trust.devices.criteria[id] == true

violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Devices] %s (%s / %s): %s — not met", [id, m.stage, m.function, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Devices",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
