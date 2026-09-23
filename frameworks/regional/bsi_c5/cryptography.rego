package bsi_c5.cryptography

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain CRY: Cryptography and Key Management.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"CRY-1": {"domain": "CRY", "title": "Cryptographic policies mandate state-of-the-art algorithms and protocols for the cloud service"},
	"CRY-2": {"domain": "CRY", "title": "Customer data is encrypted in transit over public networks"},
	"CRY-3": {"domain": "CRY", "title": "Customer data is encrypted at rest"},
	"CRY-4": {"domain": "CRY", "title": "Key management covers the full lifecycle and protects keys from unauthorized use, including by provider personnel"},
}

attested(id) if input.bsi_c5.cryptography.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Cryptography and Key Management] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "CRY",
	"area_name": "Cryptography and Key Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
