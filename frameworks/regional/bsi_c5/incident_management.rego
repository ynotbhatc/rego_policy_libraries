package bsi_c5.incident_management

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain SIM: Security Incident Management.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"SIM-1": {"domain": "SIM", "title": "A security incident management process defines roles, classification, and escalation"},
	"SIM-2": {"domain": "SIM", "title": "Customers are informed without undue delay of incidents affecting their data or service"},
	"SIM-3": {"domain": "SIM", "title": "Incident evidence is preserved and lessons learned feed back into safeguards"},
}

attested(id) if input.bsi_c5.incident_management.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Security Incident Management] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "SIM",
	"area_name": "Security Incident Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
