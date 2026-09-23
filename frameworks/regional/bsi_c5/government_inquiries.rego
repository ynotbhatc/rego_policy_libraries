package bsi_c5.government_inquiries

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain INQ: Dealing with Investigation Requests from Government Agencies.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"INQ-1": {"domain": "INQ", "title": "A defined process, including legal review, governs every government request for customer data"},
	"INQ-2": {"domain": "INQ", "title": "Affected customers are informed of investigation requests wherever legally permitted"},
	"INQ-3": {"domain": "INQ", "title": "Disclosure is limited to the legally required minimum, and applicable jurisdictions are transparent to customers"},
}

attested(id) if input.bsi_c5.government_inquiries.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Dealing with Investigation Requests from Government Agencies] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "INQ",
	"area_name": "Dealing with Investigation Requests from Government Agencies",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
