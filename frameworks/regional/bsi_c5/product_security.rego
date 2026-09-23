package bsi_c5.product_security

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain PSS: Product Safety and Security.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"PSS-1": {"domain": "PSS", "title": "Security features and configuration guidance for the service, including the shared-responsibility split, are documented for customers"},
	"PSS-2": {"domain": "PSS", "title": "Customer-facing interfaces and APIs are secured and tested against known attack classes"},
	"PSS-3": {"domain": "PSS", "title": "A vulnerability disclosure process covers the product, and errors are handled without exposing sensitive information"},
}

attested(id) if input.bsi_c5.product_security.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Product Safety and Security] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "PSS",
	"area_name": "Product Safety and Security",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
