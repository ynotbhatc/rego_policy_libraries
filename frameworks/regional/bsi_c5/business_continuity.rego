package bsi_c5.business_continuity

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain BCM: Business Continuity Management.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"BCM-1": {"domain": "BCM", "title": "Business continuity and disaster recovery plans for the cloud service are based on a business impact analysis"},
	"BCM-2": {"domain": "BCM", "title": "Continuity plans are exercised at regular intervals and updated from the results"},
}

attested(id) if input.bsi_c5.business_continuity.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Business Continuity Management] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "BCM",
	"area_name": "Business Continuity Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
