package bsi_c5.security_policies

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain SP: Security Policies and Instructions.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"SP-1": {"domain": "SP", "title": "Security policies and instructions are documented, approved by management, and communicated to all personnel"},
	"SP-2": {"domain": "SP", "title": "Policies are reviewed at planned intervals and after significant changes to the service or threat landscape"},
	"SP-3": {"domain": "SP", "title": "Exceptions to policies are documented, risk-assessed, approved, and time-limited"},
}

attested(id) if input.bsi_c5.security_policies.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Security Policies and Instructions] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "SP",
	"area_name": "Security Policies and Instructions",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
