package bsi_c5.personnel

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain HR: Personnel.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"HR-1": {"domain": "HR", "title": "Background verification of employees is performed before access, proportional to the data classification handled"},
	"HR-2": {"domain": "HR", "title": "Employment terms include security and confidentiality obligations that survive termination"},
	"HR-3": {"domain": "HR", "title": "Security awareness training is completed at onboarding and refreshed regularly for all personnel"},
	"HR-4": {"domain": "HR", "title": "A disciplinary process addresses violations of security policies"},
	"HR-5": {"domain": "HR", "title": "Offboarding revokes all access and recovers assets in a defined, timely procedure"},
}

attested(id) if input.bsi_c5.personnel.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Personnel] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "HR",
	"area_name": "Personnel",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
