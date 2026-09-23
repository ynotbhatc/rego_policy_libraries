package bsi_c5.asset_management

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain AM: Asset Management.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"AM-1": {"domain": "AM", "title": "An inventory of all assets supporting the cloud service is maintained and kept current"},
	"AM-2": {"domain": "AM", "title": "Every asset has a designated owner and documented acceptable-use rules"},
	"AM-3": {"domain": "AM", "title": "Information is classified and labelled according to a defined scheme"},
	"AM-4": {"domain": "AM", "title": "Assets and media are securely wiped or destroyed on return, reuse, or disposal"},
}

attested(id) if input.bsi_c5.asset_management.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Asset Management] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "AM",
	"area_name": "Asset Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
