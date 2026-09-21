package zero_trust.applications_workloads

import rego.v1

# CISA Zero Trust Maturity Model (ZTMM) v2.0 — Applications & Workloads pillar.
#
# The Applications & Workloads pillar functions are Application Access,
# Application Threat Protections, Accessible Applications, Secure Application
# Development & Deployment Workflow, and Application Security Testing, plus the
# pillar-level cross-cutting capabilities Visibility & Analytics, Automation &
# Orchestration, and Governance. Maturity advances through the stages
# Traditional -> Initial -> Advanced -> Optimal. NIST SP 800-207 tenets inform
# the criteria.
#
# ZTMM does not publish a numbered control list, so the criteria below are
# AAC's operationalization of the pillar's functions into discrete, assessable
# statements. Each criterion is tagged with the maturity stage it represents
# and the function it exercises. This is AAC's assessment mapping, not a
# verbatim reproduction of the model.
#
# Input contract: the caller attests to each criterion via
#   input.zero_trust.applications_workloads.criteria[<id>] == true
# An empty or absent map fails every criterion closed (all violations fire).
criteria := {
	"APP-1": {"stage": "initial", "function": "Application Access", "title": "Application access requires authenticated, authorized identity"},
	"APP-2": {"stage": "advanced", "function": "Application Access", "title": "Application access is authorized per-request from contextual/risk signals"},
	"APP-3": {"stage": "advanced", "function": "Accessible Applications", "title": "All applications are exposed behind an identity-aware proxy, not on the open network"},
	"APP-4": {"stage": "optimal", "function": "Accessible Applications", "title": "Applications are internet-accessible only through brokered zero-trust access with continuous authorization"},
	"APP-5": {"stage": "initial", "function": "Application Threat Protections", "title": "Applications sit behind WAF / runtime threat protection"},
	"APP-6": {"stage": "advanced", "function": "Application Threat Protections", "title": "Application threat protections are integrated with enterprise threat intelligence and telemetry"},
	"APP-7": {"stage": "initial", "function": "Application Security Testing", "title": "Static application security testing (SAST) runs in the CI pipeline"},
	"APP-8": {"stage": "advanced", "function": "Application Security Testing", "title": "Dynamic application security testing (DAST) runs against pre-production builds"},
	"APP-9": {"stage": "initial", "function": "Secure Application Development & Deployment Workflow", "title": "Application artifacts are built from version-controlled, immutable CI/CD pipelines"},
	"APP-10": {"stage": "advanced", "function": "Secure Application Development & Deployment Workflow", "title": "Deployment artifacts are cryptographically signed and provenance-verified before release"},
	"APP-11": {"stage": "advanced", "function": "Application Access", "title": "Workloads authenticate to each other with short-lived, cryptographic service identities"},
	"APP-12": {"stage": "optimal", "function": "Automation & Orchestration", "title": "Application authorization policy is centrally managed and continuously evaluated as code"},
}

attested(id) if input.zero_trust.applications_workloads.criteria[id] == true

# Fail closed: an unattested criterion is a gap.
violation contains msg if {
	some id, m in criteria
	not attested(id)
	msg := sprintf("Zero Trust [Applications & Workloads] %s (%s / %s): %s — not met", [id, m.stage, m.function, m.title])
}

default pillar_compliant := false

pillar_compliant if count(violation) == 0

compliance_report := {
	"pillar": "Applications & Workloads",
	"criteria_evaluated": count(criteria),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": pillar_compliant,
}
