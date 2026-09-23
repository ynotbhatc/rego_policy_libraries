package bsi_c5.supplier_control

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain SSO: Control and Monitoring of Service Providers and Suppliers.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"SSO-1": {"domain": "SSO", "title": "Security requirements for suppliers and subprocessors are contractually enforced"},
	"SSO-2": {"domain": "SSO", "title": "Subprocessors involved in the service are identified, disclosed, and monitored for compliance"},
	"SSO-3": {"domain": "SSO", "title": "Supply-chain risks are assessed at regular intervals and on changes of supplier"},
}

attested(id) if input.bsi_c5.supplier_control.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Control and Monitoring of Service Providers and Suppliers] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "SSO",
	"area_name": "Control and Monitoring of Service Providers and Suppliers",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
