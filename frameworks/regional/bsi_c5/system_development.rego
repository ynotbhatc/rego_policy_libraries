package bsi_c5.system_development

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain DEV: Procurement, Development and Modification of Information Systems.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"DEV-1": {"domain": "DEV", "title": "A secure development policy embeds security requirements throughout the lifecycle of the cloud service"},
	"DEV-2": {"domain": "DEV", "title": "Development, test, and production environments are separated"},
	"DEV-3": {"domain": "DEV", "title": "Changes are tested and approved before deployment to production"},
	"DEV-4": {"domain": "DEV", "title": "The cloud service undergoes security testing (including code analysis and penetration testing) before and after major changes"},
}

attested(id) if input.bsi_c5.system_development.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Procurement, Development and Modification of Information Systems] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "DEV",
	"area_name": "Procurement, Development and Modification of Information Systems",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
