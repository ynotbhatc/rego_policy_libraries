package bsi_c5.physical_security

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain PS: Physical Security.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"PS-1": {"domain": "PS", "title": "Data centre perimeters and security zones restrict physical access to authorized persons, with entries logged"},
	"PS-2": {"domain": "PS", "title": "Protection against environmental threats — fire, water, temperature, power disruption — is implemented and tested"},
	"PS-3": {"domain": "PS", "title": "Redundant power and telecommunication supplies match the availability commitments of the service"},
	"PS-4": {"domain": "PS", "title": "Equipment is securely sited and maintained per manufacturer and security requirements"},
}

attested(id) if input.bsi_c5.physical_security.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Physical Security] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "PS",
	"area_name": "Physical Security",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
