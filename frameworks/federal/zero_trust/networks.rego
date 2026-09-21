package zero_trust.networks

import rego.v1

# CISA Zero Trust Maturity Model (ZTMM) v2.0 — Networks pillar.
#
# The Networks pillar functions are Network Segmentation, Network Traffic
# Management, Traffic Encryption, and Network Resilience, plus the pillar-level
# cross-cutting capabilities Visibility & Analytics, Automation &
# Orchestration, and Governance. Maturity advances through the stages
# Traditional -> Initial -> Advanced -> Optimal. NIST SP 800-207 tenets
# inform the criteria.
#
# ZTMM does not publish a numbered control list, so the criteria below are
# AAC's operationalization of the pillar's functions into discrete,
# assessable statements. Each criterion is tagged with the maturity stage
# it represents and the function it exercises. This is AAC's assessment
# mapping, not a verbatim reproduction of the model.
criteria := {
	"NET-1": {"stage": "initial", "function": "Network Segmentation", "title": "Macro-segmentation separates major network zones"},
	"NET-2": {"stage": "advanced", "function": "Network Segmentation", "title": "Micro-segmentation isolates individual workloads and applications"},
	"NET-3": {"stage": "optimal", "function": "Network Segmentation", "title": "Fully distributed ingress/egress micro-perimeters are dynamically defined per-workload"},
	"NET-4": {"stage": "initial", "function": "Network Traffic Management", "title": "Traffic is managed by static, manually maintained rules and policies"},
	"NET-5": {"stage": "advanced", "function": "Network Traffic Management", "title": "Application-aware traffic policies are dynamically enforced from risk signals"},
	"NET-6": {"stage": "optimal", "function": "Network Traffic Management", "title": "Traffic management is fully automated and adapts in real time to changing needs"},
	"NET-7": {"stage": "initial", "function": "Traffic Encryption", "title": "Encryption is applied to external and known-sensitive traffic"},
	"NET-8": {"stage": "advanced", "function": "Traffic Encryption", "title": "All internal and external traffic is encrypted wherever technically supported"},
	"NET-9": {"stage": "optimal", "function": "Traffic Encryption", "title": "Encryption keys are centrally managed and rotated with continuous enforcement"},
	"NET-10": {"stage": "advanced", "function": "Network Resilience", "title": "Network resilience and failover are tested against expected demand"},
	"NET-11": {"stage": "optimal", "function": "Network Resilience", "title": "Network resilience dynamically adjusts to demand and adverse conditions across the enterprise"},
	"NET-12": {"stage": "advanced", "function": "Visibility & Analytics", "title": "Network traffic and flow telemetry are centrally collected and analyzed"},
	"NET-13": {"stage": "advanced", "function": "Automation & Orchestration", "title": "Network and segmentation policy changes are automated through orchestration"},
	"NET-14": {"stage": "initial", "function": "Governance", "title": "Network security policies are documented and periodically reviewed"},
}

attested(id) if input.zero_trust.networks.criteria[id] == true

# Fail closed: an unattested criterion is a gap.
violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Networks] %s (%s / %s): %s — not met", [id, m.stage, m.function, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Networks",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
