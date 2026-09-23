package bsi_c5.portability_interoperability

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain PI: Portability and Interoperability.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"PI-1": {"domain": "PI", "title": "Documented interfaces and formats let customers export their data (portability)"},
	"PI-2": {"domain": "PI", "title": "Customer data is securely deleted at contract end, with the deletion confirmed to the customer"},
}

attested(id) if input.bsi_c5.portability_interoperability.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Portability and Interoperability] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "PI",
	"area_name": "Portability and Interoperability",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
