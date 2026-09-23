package bsi_c5.compliance_audit

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain COM: Compliance.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"COM-1": {"domain": "COM", "title": "Applicable legal, regulatory, and contractual requirements for the service are identified and kept current"},
	"COM-2": {"domain": "COM", "title": "Independent audits or attestations of the cloud service are performed at regular intervals"},
	"COM-3": {"domain": "COM", "title": "Internal audits verify the effectiveness of the ISMS for the cloud service"},
}

attested(id) if input.bsi_c5.compliance_audit.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Compliance] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "COM",
	"area_name": "Compliance",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
