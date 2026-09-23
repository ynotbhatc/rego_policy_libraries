package bsi_c5.communication_security

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain COS: Communication Security.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"COS-1": {"domain": "COS", "title": "Networks are segmented to separate tenants from each other and management traffic from service traffic"},
	"COS-2": {"domain": "COS", "title": "Perimeter protections (firewalls, intrusion detection) defend the service's network boundaries"},
	"COS-3": {"domain": "COS", "title": "Network topology and data flows of the cloud service are documented and kept current"},
}

attested(id) if input.bsi_c5.communication_security.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Communication Security] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "COS",
	"area_name": "Communication Security",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
