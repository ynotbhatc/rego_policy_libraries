package zero_trust.identity

import rego.v1

# CISA Zero Trust Maturity Model (ZTMM) v2.0 — Identity pillar.
#
# The Identity pillar functions are Authentication, Identity Stores,
# Risk Assessments, and Access Management, plus the pillar-level
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
	"ID-1": {"stage": "initial", "function": "Authentication", "title": "MFA is enforced for all users"},
	"ID-2": {"stage": "advanced", "function": "Authentication", "title": "Phishing-resistant MFA (FIDO2/PIV) is required"},
	"ID-3": {"stage": "optimal", "function": "Authentication", "title": "Continuous / passwordless authentication is used across the enterprise"},
	"ID-4": {"stage": "initial", "function": "Identity Stores", "title": "Identity stores are consolidated and centrally managed"},
	"ID-5": {"stage": "advanced", "function": "Identity Stores", "title": "Self-hosted and cloud identity stores are integrated and federated"},
	"ID-6": {"stage": "initial", "function": "Risk Assessments", "title": "Identity risk is assessed using manual, point-in-time signals"},
	"ID-7": {"stage": "advanced", "function": "Risk Assessments", "title": "Continuous identity risk scoring feeds access decisions"},
	"ID-8": {"stage": "advanced", "function": "Access Management", "title": "Least-privilege access is enforced with just-in-time / just-enough privilege"},
	"ID-9": {"stage": "optimal", "function": "Access Management", "title": "Access is dynamically authorized per-session from real-time risk"},
	"ID-10": {"stage": "advanced", "function": "Visibility & Analytics", "title": "Authentication and access events are centrally logged and analyzed"},
	"ID-11": {"stage": "advanced", "function": "Automation & Orchestration", "title": "Identity lifecycle (provisioning/deprovisioning) is automated"},
	"ID-12": {"stage": "initial", "function": "Governance", "title": "Identity policies are documented and periodically reviewed"},
}

attested(id) if input.zero_trust.identity.criteria[id] == true

# Fail closed: an unattested criterion is a gap.
violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Identity] %s (%s / %s): %s — not met", [id, m.stage, m.function, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Identity",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
