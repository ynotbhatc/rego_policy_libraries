package bsi_c5.organisation_information_security

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain OIS: Organisation of Information Security.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"OIS-1": {"domain": "OIS", "title": "An ISMS with defined responsibilities for provision of the cloud service is established and maintained"},
	"OIS-2": {"domain": "OIS", "title": "Security roles and responsibilities are assigned, with segregation of conflicting duties enforced"},
	"OIS-3": {"domain": "OIS", "title": "A risk management process identifies, assesses, and treats cloud-specific risks on a defined cadence"},
	"OIS-4": {"domain": "OIS", "title": "Contact with relevant authorities and special-interest groups is maintained"},
}

attested(id) if input.bsi_c5.organisation_information_security.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Organisation of Information Security] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "OIS",
	"area_name": "Organisation of Information Security",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
